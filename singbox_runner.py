"""
Запускает одноразовый sing-box для одного outbound, проксирует
реальные HTTP запросы через него и возвращает результат проверки.

Проверка теперь намеренно ЖЁСТКАЯ и небыстрая — приоритет качеству, а не
скорости прохода по подписке:

1. Verify: конфиг должен получить валидный IP-эхо ответ (JSON с полем
   "ip") НЕЗАВИСИМО от cfg.REQUIRED_VERIFY_MATCHES (по умолчанию 2)
   РАЗНЫХ провайдеров, а не от одного первого ответившего. Один
   успешный ответ легко подделать локальным DPI/block-page для
   конкретного домена — два разных домена одновременно подделать
   на лету намного труднее.
2. Leak-check: IP, который вернул прокси, сверяется с реальным прямым
   IP этого сервера (см. _get_direct_ip). Совпадение значит, что
   запрос по факту ушёл в обход прокси (например, transparent proxy
   / DPI отвечает от своего имени) — такой конфиг бракуется, даже
   если формально "ответ пришёл".
3. Stability recheck: после успешной верификации ждём
   cfg.STABILITY_RECHECK_DELAY секунд и делаем ЕЩЁ один запрос через
   тот же самый прокси. Ноды, которые держат соединение долю секунды
   и потом рвут (перегруженные / забаненные по IP), отсеиваются на
   этом шаге.

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

# Провайдеры IP-эхо — пробуем по очереди, достаточно одного успеха.
# ФИКС: cfg.TEST_URL_PRIMARY раньше был объявлен в config.py, но нигде не
# использовался — переменная окружения TEST_URL_PRIMARY не давала эффекта.
_VERIFY_URLS = list(dict.fromkeys([
    cfg.TEST_URL_PRIMARY,
    cfg.TEST_URL_VERIFY,
    *cfg.TEST_URL_VERIFY_FALLBACKS,
]))

_port_lock = asyncio.Lock()
_next_port = cfg.PORT_RANGE_START

# Реальный прямой (без прокси) публичный IP этого сервера. Нужен, чтобы
# отличить "прокси реально отдал внешний IP" от "запрос почему-то ушёл
# напрямую/через transparent-proxy и отдал наш собственный IP". Кэшируется
# один раз при первом обращении и переиспользуется всеми проверками —
# он не меняется в рамках жизни процесса.
_direct_ip: Optional[str] = None
_direct_ip_lock = asyncio.Lock()


async def _get_direct_ip() -> Optional[str]:
    global _direct_ip
    if _direct_ip is not None:
        return _direct_ip
    async with _direct_ip_lock:
        if _direct_ip is not None:
            return _direct_ip
        for url in _VERIFY_URLS:
            try:
                timeout = aiohttp.ClientTimeout(total=8, connect=6)
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=timeout) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json(content_type=None)
                        ip = data.get("ip") if isinstance(data, dict) else None
                        if ip and _looks_like_ip(ip):
                            _direct_ip = ip
                            return _direct_ip
            except Exception as e:
                log.debug("direct ip probe failed via %s: %s", url, e)
                continue
        log.warning("could not determine direct (non-proxied) IP — leak-check disabled")
        return None


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
    reason: str = ""


async def test_config(outbound: dict) -> TestResult:
    """Проверяет один outbound. Никогда не кидает исключений."""
    work_id = uuidlib.uuid4().hex[:12]
    job_dir = os.path.join(cfg.WORK_DIR, work_id)
    os.makedirs(job_dir, exist_ok=True)
    config_path = os.path.join(job_dir, "config.json")
    port = await _claim_port()
    server_tag = f"{outbound.get('server')}:{outbound.get('server_port')}"

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
            reason = "sing-box exited early" if proc.returncode is not None else "local port never opened"
            log.info("FAIL %s: %s", server_tag, reason)
            return TestResult(False, reason=reason)

        connector = ProxyConnector.from_url(
            f"socks5://127.0.0.1:{port}",
            rdns=True,
        )
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                ok, latency_ms, reason = await _verify(session, required_matches=cfg.REQUIRED_VERIFY_MATCHES)
                if not ok:
                    log.info("FAIL %s: %s", server_tag, reason)
                    return TestResult(False, reason=reason)

                if cfg.STABILITY_RECHECK_DELAY > 0:
                    await asyncio.sleep(cfg.STABILITY_RECHECK_DELAY)
                    still_ok, _, stability_reason = await _verify(session, required_matches=1)
                    if not still_ok:
                        reason = f"failed stability recheck: {stability_reason}"
                        log.info("FAIL %s: %s", server_tag, reason)
                        return TestResult(False, reason=reason)

                speed_mbps = await _measure_speed(session)
                return TestResult(True, latency_ms, speed_mbps)

        except _PROXY_ERRORS as e:
            log.info("FAIL %s: proxy error: %s", server_tag, e)
            return TestResult(False, reason=str(e))
        except Exception as e:
            log.info("FAIL %s: unexpected error: %s", server_tag, e)
            return TestResult(False, reason=str(e))

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


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _verify(
    session: aiohttp.ClientSession, required_matches: int = 1
) -> Tuple[bool, Optional[float], str]:
    """
    Пробует IP-эхо провайдеров по очереди и требует, чтобы как минимум
    `required_matches` РАЗНЫХ провайдеров независимо подтвердили рабочий
    прокси, прежде чем вернуть успех. Каждый успешный ответ также
    сверяется с прямым (не через прокси) IP этого сервера — совпадение
    означает утечку/подмену, а не реальное проксирование, и не
    засчитывается.

    Первая попытка получает полный TEST_TIMEOUT, остальные — чуть
    укороченный, чтобы один тормозящий сервис не съедал весь бюджет.
    Идём по списку до конца (а не останавливаемся на первом success),
    пока не наберём нужное число подтверждений.
    """
    direct_ip = await _get_direct_ip()
    confirmations: list[Tuple[str, float]] = []
    last_reason = "no verify provider responded"

    for i, url in enumerate(_VERIFY_URLS):
        budget = cfg.TEST_TIMEOUT if i == 0 else min(cfg.TEST_TIMEOUT, 10.0)
        timeout = aiohttp.ClientTimeout(
            total=budget,
            connect=cfg.TEST_CONNECT_TIMEOUT,
            sock_connect=cfg.TEST_CONNECT_TIMEOUT,
            sock_read=budget,
        )
        try:
            start = time.monotonic()
            async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                if resp.status != 200:
                    last_reason = f"{url} -> HTTP {resp.status}"
                    continue
                try:
                    data = await resp.json(content_type=None)
                except (aiohttp.ContentTypeError, ValueError):
                    last_reason = f"{url} -> non-JSON response"
                    continue
                ip = data.get("ip") if isinstance(data, dict) else None
                if not ip or not _looks_like_ip(ip):
                    last_reason = f"{url} -> no valid ip in response"
                    continue
                latency_ms = (time.monotonic() - start) * 1000
                if latency_ms < cfg.MIN_PLAUSIBLE_LATENCY_MS:
                    last_reason = f"{url} -> suspiciously fast ({latency_ms:.1f}ms), likely faked"
                    continue
                if direct_ip and ip == direct_ip:
                    last_reason = f"{url} -> returned our own direct IP (not actually proxied)"
                    continue

                confirmations.append((url, latency_ms))
                if len(confirmations) >= required_matches:
                    # latency берём с первого подтверждения — оно наиболее
                    # репрезентативно, дальнейшие подтверждения только
                    # проверяют устойчивость, а не скорость
                    return True, confirmations[0][1], ""
        except _PROXY_ERRORS as e:
            last_reason = f"{url} -> {e}"
        except Exception as e:
            last_reason = f"{url} -> unexpected: {e}"

    if confirmations:
        last_reason = (
            f"only {len(confirmations)}/{required_matches} providers confirmed "
            f"real proxied connectivity"
        )
    return False, None, last_reason


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
