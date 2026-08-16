"""
Загружает список SNI-вайтлиста, поставляемый вместе с ботом (sni_whitelist.txt),
и при старте пытается обновить его с GitHub.

Источник: https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/sni_whitelist.txt

Домены из этого списка маскируются под легитимный российский трафик
(mail.ru, vk.ru, yandex.ru, gosuslugi.ru и т.д.), поэтому конфиги с таким SNI
сложнее детектировать через DPI.
"""
from __future__ import annotations

import asyncio
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
    global _whitelist
    if _whitelist is None:
        _whitelist = _load_local()
    if not sni:
        return False
    return sni.strip().lower().rstrip(".") in _whitelist
