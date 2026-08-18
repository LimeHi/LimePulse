"""
Запускает одноразовый sing-box для одного outbound, проксирует
реальные HTTP запросы через него и возвращает результат проверки.

Два шага проверки, которые сложно подделать DPI/block-page:
  1. connectivity probe — несколько URL (CF + Google + Microsoft), достаточно одного.
  2. ipify JSON — должен вернуть реальный IP в поле "ip".
После этого — speed-тест (опционально, не влияет на ok/fail).

Все прокси-исключения (включая ProxyTimeoutError из aiohttp_socks)
перехватываются на всех уровнях — test_config никогда не кидает наружу.
"""
from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import json
import logging
import os
import time
import uuid as uuidlib
from typing import Optional, Tuple

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyError, ProxyTimeoutError, ProxyConnectionError

import config as cfg

log = logging.getLogger("singbox_runner")

_PROXY_ERRORS = (
    aiohttp.ClientError,
    asyncio.TimeoutError,
    OSError,
    ProxyError,
    ProxyTimeoutError,
    ProxyConnectionError,
)

# Несколько 204-эндпоинтов — пробуем по очереди, достаточно одного успеха.
_GENERATE_204_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
]

_port_lock = asyncio.Lock()
_next_port = cfg.PORT_RANGE_START


async def _claim_port() -> int:
    global _next_port
    async with _port_lock:
        port = _next_port
        _next_port += 1
        if _next_port > cfg.PORT_RANGE_END:
            _next_port = cfg.PORT_RANGE_START
        return port


@dataclasses.dataclass
class TestResult:
    ok: bool
    latency_ms: Optional[float] = None
    speed_mbps: Optional[float] = None


async def test_config(outbound: dict) -> TestResult:
    """Проверяет один outbound. Никогда не кидает исключений."""
    work_id = uuidlib.uuid4().hex[:12]
    job_dir = os.path.join(cfg.WORK_DIR, work_id)
    os.makedirs(job_dir, exist_ok=True)
    config_path = os.path.join(job_dir, "config.json")
    port = await _claim_port()

    singbox_config = {
        "log": {"level": "error", "disabled": True},
        "inbounds": [
            {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": port}
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }
    with open(config_path, "w") as f:
        json.dump(singbox_config, f)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            cfg.SINGBOX_BIN, "run", "-c", config_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        if not await _wait_port(port, proc, timeout=5.0):
            return TestResult(False)

        connector = ProxyConnector.from_url(
            f"socks5://127.0.0.1:{port}",
            rdns=True,
        )
        session_timeout = aiohttp.ClientTimeout(
            total=cfg.TEST_TIMEOUT,
            connect=cfg.TEST_CONNECT_TIMEOUT,
            sock_connect=cfg.TEST_CONNECT_TIMEOUT,
            sock_read=cfg.TEST_TIMEOUT,
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=session_timeout,
            ) as session:
                # Шаг 1: connectivity probe
                if not await _check_connectivity(session):
                    return TestResult(False)

                # Шаг 2: IP-эхо + латентность
                # ФИКС: start берём прямо перед запросом ipify,
                # а не до шага 1 — иначе в latency_ms включалось время
                # connectivity-пробы и быстрые серверы не получали ⚡️
                ok, latency_ms = await _check_ip_echo(session)
                if not ok:
                    return TestResult(False)

                # Шаг 3: замер скорости (не влияет на ok)
                speed_mbps = await _measure_speed(session)

                return TestResult(True, latency_ms, speed_mbps)

        except _PROXY_ERRORS as e:
            log.debug("test_config outer catch: %s", e)
            return TestResult(False)
        except Exception as e:
            log.debug("test_config unexpected: %s", e)
            return TestResult(False)

    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                pass
        try:
            for fname in os.listdir(job_dir):
                os.remove(os.path.join(job_dir, fname))
            os.rmdir(job_dir)
        except OSError:
            pass


async def _check_connectivity(session: aiohttp.ClientSession) -> bool:
    """
    Пробует несколько connectivity-URL по очереди, достаточно одного успеха.
    Спасает серверы у которых выходной IP забанен Cloudflare.
    """
    for url in _GENERATE_204_URLS:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                if url.endswith("connecttest.txt"):
                    if resp.status == 200:
                        body = await resp.read()
                        if b"Microsoft Connect Test" in body:
                            log.debug("connectivity OK via msft")
                            return True
                else:
                    if resp.status == 204:
                        body = await resp.read()
                        if len(body) == 0:
                            log.debug("connectivity OK via 204: %s", url)
                            return True
        except _PROXY_ERRORS as e:
            log.debug("connectivity probe failed (%s): %s", url, e)
        except Exception as e:
            log.debug("connectivity probe unexpected (%s): %s", url, e)
    return False


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _check_ip_echo(
    session: aiohttp.ClientSession,
) -> Tuple[bool, Optional[float]]:
    """
    ФИКС: start теперь берётся ЗДЕСЬ, а не снаружи.
    Раньше start ставился до вызова _check_connectivity, и latency_ms
    включала время connectivity-пробы (~1-3 сек) → быстрые серверы
    не проходили порог MAX_FAST_PING_MS и не получали ⚡️.
    """
    try:
        start = time.monotonic()
        async with session.get(cfg.TEST_URL_VERIFY, allow_redirects=True) as resp:
            if resp.status != 200:
                return False, None
            try:
                data = await resp.json(content_type=None)
            except (aiohttp.ContentTypeError, ValueError):
                return False, None
            ip = data.get("ip") if isinstance(data, dict) else None
            if not ip or not _looks_like_ip(ip):
                return False, None
            latency_ms = (time.monotonic() - start) * 1000
            if latency_ms < cfg.MIN_PLAUSIBLE_LATENCY_MS:
                return False, None
            return True, latency_ms
    except _PROXY_ERRORS:
        return False, None
    except Exception:
        return False, None


async def _measure_speed(session: aiohttp.ClientSession) -> Optional[float]:
    """Скачивает кусок данных через прокси, возвращает Мбит/с или None."""
    speed_timeout = aiohttp.ClientTimeout(
        total=cfg.SPEEDTEST_MAX_DURATION + 3,
        connect=cfg.TEST_CONNECT_TIMEOUT,
        sock_connect=cfg.TEST_CONNECT_TIMEOUT,
        sock_read=cfg.SPEEDTEST_MAX_DURATION + 3,
    )
    try:
        start = time.monotonic()
        downloaded = 0
        async with session.get(cfg.SPEEDTEST_URL, timeout=speed_timeout) as resp:
            if resp.status != 200:
                return None
            async for chunk in resp.content.iter_chunked(65536):
                downloaded += len(chunk)
                if time.monotonic() - start >= cfg.SPEEDTEST_MAX_DURATION:
                    break
        duration = time.monotonic() - start
        if duration <= 0 or downloaded == 0:
            return None
        return (downloaded * 8) / (duration * 1_000_000)
    except _PROXY_ERRORS:
        return None
    except Exception:
        return None


async def _wait_port(port: int, proc: asyncio.subprocess.Process, timeout: float) -> bool:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if proc.returncode is not None:
            return False
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except OSError:
            await asyncio.sleep(0.05)
    return False
