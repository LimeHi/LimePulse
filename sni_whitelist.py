"""
Загружает список SNI-вайтлиста, поставляемый вместе с ботом (sni_whitelist.txt),
и при старте пытается обновить его с GitHub.

Источник: https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/sni_whitelist.txt

Домены из этого списка маскируются под легитимный российский трафик
(mail.ru, vk.ru, yandex.ru, gosuslugi.ru и т.д.), поэтому конфиги с таким SNI
сложнее детектировать через DPI.

Плюс CIDR-вайтлист: диапазоны IP российских облачных/сетевых провайдеров
(в первую очередь Яндекс), которые массово раздают легитимным российским
сервисам и вряд ли блокируются целиком. Если у конфига нет SNI из
доменного вайтлиста, но IP сервера попадает в один из этих диапазонов —
это тоже сигнал "маскируется под обычный рунет-трафик", отдельный от SNI,
поэтому оба сигнала складываются в один is_white.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from typing import Optional

import aiohttp

log = logging.getLogger("sni_whitelist")

_WHITELIST_URL = (
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/sni_whitelist.txt"
)
_WHITELIST_PATH = os.path.join(os.path.dirname(__file__), "sni_whitelist.txt")

_whitelist: Optional[frozenset] = None

# Диапазоны IP, которые массово используются легитимным рунет-трафиком
# (в основном сети Яндекса) и которые РКН технически не может заблокировать
# целиком, не положив заодно кучу обычных российских сервисов. Конфиг с
# сервером в одном из этих диапазонов — такой же сигнал "маскировки под
# рунет", как и попадание в доменный SNI-вайтлист, просто на уровне сети,
# а не TLS-хендшейка.
_WHITELIST_CIDRS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "5.255.255.0/24", "77.88.0.0/18", "87.250.250.0/24",
        "95.108.0.0/16", "217.69.128.0/20", "109.120.128.0/17",
        "185.30.164.0/22", "91.200.120.0/24", "193.232.96.0/24",
        "92.223.80.0/22", "178.248.0.0/21",
    )
]


def _parse_lines(text: str) -> frozenset:
    return frozenset(
        line.strip().lower().rstrip(".")
        for line in text.splitlines()
        if line.strip()
    )


def _load_local() -> frozenset:
    try:
        with open(_WHITELIST_PATH, encoding="utf-8") as f:
            return _parse_lines(f.read())
    except OSError:
        return frozenset()


async def update_from_github() -> None:
    """Скачивает актуальный sni_whitelist.txt с GitHub и обновляет in-memory кэш.
    Вызывается один раз при старте бота. Не бросает исключений — в худшем
    случае остаётся локальная копия."""
    global _whitelist
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(_WHITELIST_URL) as resp:
                resp.raise_for_status()
                text = await resp.text(encoding="utf-8")
        parsed = _parse_lines(text)
        if len(parsed) > 10:          # считаем ответ валидным если домены есть
            _whitelist = parsed
            # сохраняем локально для следующего холодного старта
            try:
                with open(_WHITELIST_PATH, "w", encoding="utf-8") as f:
                    f.write(text)
            except OSError:
                pass
            log.info("SNI whitelist updated from GitHub: %d domains", len(parsed))
        else:
            log.warning("SNI whitelist from GitHub looks empty, keeping local copy")
    except Exception as e:
        log.warning("Could not update SNI whitelist from GitHub: %s — using local copy", e)
        if _whitelist is None:
            _whitelist = _load_local()


def is_whitelisted(sni: Optional[str]) -> bool:
    """SNI из доменного вайтлиста."""
    global _whitelist
    if _whitelist is None:
        _whitelist = _load_local()
    if not sni:
        return False
    return sni.strip().lower().rstrip(".") in _whitelist


def is_ip_whitelisted(host: Optional[str]) -> bool:
    """
    True, если host — это IP-адрес (не домен) и он попадает в один из
    _WHITELIST_CIDRS. Для доменов (в т.ч. когда host на самом деле SNI)
    всегда False — доменный кейс уже покрыт is_whitelisted().
    """
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host.strip())
    except ValueError:
        return False
    return any(ip in net for net in _WHITELIST_CIDRS)
