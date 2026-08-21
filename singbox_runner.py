"""
Запускает одноразовый sing-box для одного outbound, проксирует
реальные HTTP запросы через него и возвращает результат проверки.

Проверка намеренно ЖЁСТКАЯ и небыстрая — приоритет качеству, а не
скорости прохода по подписке:

1. Verify: конфиг должен получить валидный IP-эхо ответ (JSON с полем
   "ip") НЕЗАВИСИМО от cfg.REQUIRED_VERIFY_MATCHES (по умолчанию 2)
   РАЗНЫХ провайдеров, а не от одного первого ответившего. Один
   успешный ответ легко подделать локальным DPI/block-page для
   конкретного домена — два разных домена одновременно подделать
   на лету намного труднее.
2. DPI-диагностика (новое): если verify провалился и НИ ОДИН провайдер
   не прислал вообще никакого ответа (не пришло даже "неправильного"
   HTTP-статуса — чистые таймауты/обрывы), это ещё не значит, что сервер
   мёртв. Классический паттерн блокировки протокола по DPI в РФ выглядит
   так: TCP/пакетный уровень соединения поднимается нормально (хендшейк
   до сервера проходит), но полезная нагрузка приложения режется или
   душится сразу после того, как DPI опознаёт протокол по сигнатуре
   (например TLS ClientHello характерной формы, паттерн VMess/Shadowsocks
   и т.п.). Поэтому в этом случае отдельно поднимается "голый" SOCKS5
   TCP-туннель через тот же локальный инбаунд sing-box до одного из
   verify-хостов, БЕЗ HTTP поверх (см. _tcp_reachable_via_proxy). Если
   туннель поднимается, а прикладные данные так и не дошли — конфиг
   помечается как dpi_blocked=True, а не просто "мёртвый": соединение
   технически устанавливается, но протокол в текущих сетевых условиях
   недоступен.
3. Leak-check: IP, который вернул прокси, сверяется с реальным прямым
   IP этого сервера (см. _get_direct_ip). Совпадение значит, что
   запрос по факту ушёл в обход прокси (например, transparent proxy
   / DPI отвечает от своего имени) — такой конфиг бракуется, даже
   если формально "ответ пришёл".
4. Stability recheck: после успешной верификации ждём
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
from urllib.parse import urlsplit

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

# Голый SOCKS5 TCP-коннект (без HTTP поверх) для DPI-диагностики.
# aiohttp_socks сам построен поверх python_socks, так что пакет уже есть
# в зависимостях — но на всякий случай деградируем без него, а не падаем.
try:
    from python_socks.async_.asyncio import Proxy as _SocksProxy

    _SOCKS_PROBE_AVAILABLE = True
except ImportError:  # pragma: no cover - защитный фолбэк
    _SOCKS_PROBE_AVAILABLE = False
    log.warning(
        "python_socks недоступен напрямую — DPI-диагностика "
        "(различение 'нет соединения' и 'протокол задушен DPI') отключена, "
        "verify будет работать как раньше, без этого уточнения"
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
    # True, если verify провалился, но отдельная DPI-проба показала, что
    # голый TCP-туннель до сервера через этот же outbound поднимается —
    # т.е. соединение технически устанавливается, а протокол задушен уже
    # после хендшейка. Отличается от "сервер просто недоступен".
    dpi_blocked: bool = False


async def _tcp_reachable_via_proxy(
    local_port: int, dest_host: str, dest_port: int, timeout: float
) -> bool:
    """
    Поднимает СТРОГО TCP SOCKS5-туннель через локальный инбаунд sing-box
    до dest_host:dest_port и сразу его закрывает — никакого HTTP или
    другого прикладного трафика поверх не отправляется.

    Успех здесь означает, что настоящее сетевое соединение (полный
    SOCKS5 CONNECT: sing-box резолвит/коннектится к dest_host через
    выбранный outbound-протокол — vless/vmess/trojan/ss/hysteria2 — и
    только после этого отвечает клиенту "succeeded") реально
    поднимается. Используется исключительно для диагностики ПОСЛЕ того,
    как обычный verify по HTTP уже провалился без единого ответа —
    чтобы отличить "сервер недоступен" от "соединение есть, но DPI
    режет payload по сигнатуре протокола".
    """
    if not _SOCKS_PROBE_AVAILABLE:
        return False
    sock = None
    try:
        proxy = _SocksProxy.from_url(f"socks5://127.0.0.1:{local_port}")
        sock = await asyncio.wait_for(
            proxy.connect(dest_host=dest_host, dest_port=dest_port),
            timeout=timeout,
        )
        return True
    except Exception as e:
        log.debug("DPI-проба: TCP-туннель до %s:%s не поднялся: %s", dest_host, dest_port, e)
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


async def _classify_dpi_block(local_port: int) -> bool:
    """
    Пробует поднять голый TCP-туннель до нескольких verify-хостов (порт
    443) через тот же локальный SOCKS5 sing-box. True — хотя бы один
    поднялся, то есть соединение с внешним миром через этот outbound в
    принципе рабочее, и провал verify связан не с "сервер не отвечает",
    а с тем, что DPI успевает опознать и задушить протокол уже после
    хендшейка (актуально для обхода блокировок протоколов в РФ).
    """
    for url in _VERIFY_URLS[:3]:
        host = urlsplit(url).hostname
        if not host:
            continue
        if await _tcp_reachable_via_proxy(local_port, host, 443, timeout=cfg.DPI_PROBE_TIMEOUT):
            return True
    return False


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
                ok, latency_ms, reason, got_any_response = await _verify(
                    session, required_matches=cfg.REQUIRED_VERIFY_MATCHES
                )
                if not ok:
                    dpi_blocked = False
                    if not got_any_response:
                        # Ни один провайдер не ответил вообще ничем — прежде
                        # чем списывать конфиг в "мёртвые", проверяем, не
                        # это ли тот самый случай "соединение устанавливается,
                        # а трафик не идёт" (DPI режет протокол по сигнатуре
                        # уже после хендшейка).
                        dpi_blocked = await _classify_dpi_block(port)
                    if dpi_blocked:
                        reason = (
                            f"DPI: TCP-туннель до сервера поднимается, но "
                            f"прикладной трафик не идёт (похоже на блокировку "
                            f"протокола) — {reason}"
                        )
                    log.info("FAIL %s: %s", server_tag, reason)
                    return TestResult(False, reason=reason, dpi_blocked=dpi_blocked)

                if cfg.STABILITY_RECHECK_DELAY > 0:
                    await asyncio.sleep(cfg.STABILITY_RECHECK_DELAY)
                    still_ok, _, stability_reason, _ = await _verify(session, required_matches=1)
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
) -> Tuple[bool, Optional[float], str, bool]:
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

    Возвращает четвёртым элементом got_any_response: True, если хотя бы
    один провайдер вообще прислал HTTP-ответ (пусть даже "неправильный" —
    не тот статус, не JSON, чужой IP). Это отличает "сервер что-то
    отвечает, но неправильное" (blockpage / leak) от "не пришло вообще
    ничего, кроме таймаутов/обрывов" — второй случай является кандидатом
    на отдельную DPI-диагностику в test_config (см. _classify_dpi_block).
    """
    direct_ip = await _get_direct_ip()
    confirmations: list[Tuple[str, float]] = []
    last_reason = "no verify provider responded"
    got_any_response = False

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
                got_any_response = True
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
                    return True, confirmations[0][1], "", got_any_response
        except _PROXY_ERRORS as e:
            last_reason = f"{url} -> {e}"
        except Exception as e:
            last_reason = f"{url} -> unexpected: {e}"

    if confirmations:
        got_any_response = True
        last_reason = (
            f"only {len(confirmations)}/{required_matches} providers confirmed "
            f"real proxied connectivity"
        )
    return False, None, last_reason, got_any_response


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
