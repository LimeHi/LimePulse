"""
Spins up a disposable sing-box instance for a single outbound, proxies
real HTTP requests through it, and reports whether the config actually
works.

A single "does the socket open" or "did we get a 2xx" check is not enough:
a dead/blocked server can still produce a fast local response (through a
DPI block page, a captive portal, or a misrouted socket), which looks like
success from the outside. To avoid counting those as working, each config
has to pass two independent, content-verified checks against different
endpoints before it's accepted.
"""
from __future__ import annotations

import asyncio
import dataclasses
import ipaddress
import json
import os
import time
import uuid as uuidlib
from typing import Optional, Tuple

import aiohttp
from aiohttp_socks import ProxyConnector

import config as cfg

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
    """Runs connectivity + speed checks for a single outbound."""
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

        if not await _wait_port(port, proc, timeout=3.0):
            return TestResult(False)

        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(
            total=cfg.TEST_TIMEOUT,
            connect=cfg.TEST_CONNECT_TIMEOUT,
            sock_connect=cfg.TEST_CONNECT_TIMEOUT,
            sock_read=cfg.TEST_TIMEOUT,
        )
        try:
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                # Step 1: a plain, content-checked connectivity probe. A
                # real generate_204 endpoint always answers 204 with an
                # empty body - block pages and captive portals almost
                # never reproduce that exactly.
                if not await _check_generate_204(session):
                    return TestResult(False)

                # Step 2: an endpoint whose body can't be faked by a
                # generic block page - it has to actually reach the proxy
                # exit node and echo back a real IP as JSON. Doubles as
                # our ping/latency measurement.
                start = time.monotonic()
                ok, latency_ms = await _check_ip_echo(session, start)
                if not ok:
                    return TestResult(False)

                # Step 3: only for configs that already proved they work -
                # measure real throughput by downloading a chunk of data.
                speed_mbps = await _measure_speed(session)

                return TestResult(True, latency_ms, speed_mbps)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
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


async def _check_generate_204(session: aiohttp.ClientSession) -> bool:
    try:
        async with session.get(cfg.TEST_URL_PRIMARY, allow_redirects=True) as resp:
            if resp.status != 204:
                return False
            body = await resp.read()
            return len(body) == 0
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _check_ip_echo(session: aiohttp.ClientSession, start: float) -> Tuple[bool, Optional[float]]:
    try:
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
                # A real round trip to a remote exit node practically never
                # comes back this fast - this smells like a cached or
                # locally-terminated response, not an actual proxied one.
                return False, None
            return True, latency_ms
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return False, None


async def _measure_speed(session: aiohttp.ClientSession) -> Optional[float]:
    """Downloads a chunk of data through the proxy and returns Mbit/s, or
    None if the download failed. Capped at SPEEDTEST_MAX_DURATION so a
    very slow proxy doesn't hold up the whole test queue."""
    timeout = aiohttp.ClientTimeout(
        total=cfg.SPEEDTEST_MAX_DURATION + 3,
        sock_connect=cfg.TEST_CONNECT_TIMEOUT,
    )
    try:
        start = time.monotonic()
        downloaded = 0
        async with session.get(cfg.SPEEDTEST_URL, timeout=timeout) as resp:
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
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
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
