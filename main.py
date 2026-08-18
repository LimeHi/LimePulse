"""
Telegram-бот: пользователь присылает подписку или список конфигов,
бот проверяет их через sing-box, сортирует по скорости/пингу,
добавляет ⚡️⚪️ префиксы и даёт выбрать, что прислать .txt файлом.

Структура кнопок после проверки:
  [📂 Категории]          ← открывает разбивку белые/чёрные
  [⚡️ Быстрые (N)]
  [Все рабочие (N)]

При нажатии «Категории» сообщение заменяется на два блока:
  ── ⚪️ Белые SNI ──
  [⚡️⚪️ Быстрые белые (N)]
  [⚪️ Все белые (N)]
  ── 🖤 Обычные серверы ──
  [⚡️ Быстрые чёрные (N)]
  [🖤 Все чёрные (N)]
  [← Назад]
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import os
import uuid

import aiohttp
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

import config as cfg
import sni_whitelist
from protocol_parser import ParseError, parse_config
from queue_manager import JobQueue, WorkingItem

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vpn_tester_bot")

router = Router()
job_queue = JobQueue()

# result_id -> список WorkingItem
_pending_results: dict[str, list[WorkingItem]] = {}

URI_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")

# ── Фильтры ────────────────────────────────────────────────────────────────
_DELIVERY_FILTERS = {
    "all":        lambda i: True,
    "fast":       lambda i: i.is_fast,
    "white":      lambda i: i.is_white,
    "fastwhite":  lambda i: i.is_fast and i.is_white,
    "black":      lambda i: not i.is_white,
    "fastblack":  lambda i: i.is_fast and not i.is_white,
}
_DELIVERY_LABELS = {
    "all":        "Все рабочие",
    "fast":       "⚡️ Быстрые",
    "white":      "⚪️ Все белые",
    "fastwhite":  "⚡️⚪️ Быстрые белые",
    "black":      "🖤 Все обычные",
    "fastblack":  "⚡️🖤 Быстрые обычные",
}
_SORT_KEYS = {
    "all":        "speed",
    "fast":       "speed",
    "white":      "latency",
    "fastwhite":  "speed",
    "black":      "speed",
    "fastblack":  "speed",
}


def _sorted_items(items: list[WorkingItem], kind: str) -> list[WorkingItem]:
    predicate = _DELIVERY_FILTERS.get(kind, _DELIVERY_FILTERS["all"])
    selected = [i for i in items if predicate(i)]
    if _SORT_KEYS.get(kind) == "speed":
        selected.sort(key=lambda i: -(i.speed_mbps or 0.0))
    else:
        selected.sort(key=lambda i: i.latency_ms if i.latency_ms is not None else float("inf"))
    return selected


def _avg_speed(lst: list[WorkingItem]) -> float | None:
    speeds = [i.speed_mbps for i in lst if i.speed_mbps is not None]
    return sum(speeds) / len(speeds) if speeds else None


def _avg_ping(lst: list[WorkingItem]) -> float | None:
    pings = [i.latency_ms for i in lst if i.latency_ms is not None]
    return sum(pings) / len(pings) if pings else None


def _btn(text: str, result_id: str, kind: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(text=text, callback_data=f"send:{result_id}:{kind}")


# ── Клавиатуры ─────────────────────────────────────────────────────────────

def _main_keyboard(result_id: str, items: list[WorkingItem]) -> InlineKeyboardMarkup:
    """Главное меню: Категории / Быстрые / Все."""
    fast = [i for i in items if i.is_fast]

    rows: list[list[InlineKeyboardButton]] = []

    # Кнопка «Категории» — всегда первая
    rows.append([InlineKeyboardButton(
        text="📂 Категории",
        callback_data=f"cat:{result_id}",
    )])

    # Быстрые (если есть)
    if fast:
        spd = _avg_speed(fast)
        label = f"⚡️ Быстрые ({len(fast)})"
        if spd:
            label += f" ~{spd:.0f} Мбит/с"
        rows.append([_btn(label, result_id, "fast")])

    # Все рабочие
    rows.append([_btn(f"Все рабочие ({len(items)})", result_id, "all")])

    return InlineKeyboardMarkup(inline_keyboard=rows)


def _category_keyboard(result_id: str, items: list[WorkingItem]) -> tuple[str, InlineKeyboardMarkup]:
    """Меню категорий: белые сверху, чёрные снизу."""
    white     = [i for i in items if i.is_white]
    fastwhite = [i for i in items if i.is_fast and i.is_white]
    black     = [i for i in items if not i.is_white]
    fastblack = [i for i in items if i.is_fast and not i.is_white]

    rows: list[list[InlineKeyboardButton]] = []

    # ── Белые SNI ──
    if white:
        if fastwhite:
            spd = _avg_speed(fastwhite)
            label = f"⚡️⚪️ Быстрые белые ({len(fastwhite)})"
            if spd:
                label += f" ~{spd:.0f} Мбит/с"
            rows.append([_btn(label, result_id, "fastwhite")])

        ping = _avg_ping(white)
        label = f"⚪️ Все белые ({len(white)})"
        if ping:
            label += f" ~{ping:.0f} мс"
        rows.append([_btn(label, result_id, "white")])

    # ── Обычные (чёрные) ──
    if black:
        if fastblack:
            spd = _avg_speed(fastblack)
            label = f"⚡️🖤 Быстрые обычные ({len(fastblack)})"
            if spd:
                label += f" ~{spd:.0f} Мбит/с"
            rows.append([_btn(label, result_id, "fastblack")])

        spd = _avg_speed(black)
        label = f"🖤 Все обычные ({len(black)})"
        if spd:
            label += f" ~{spd:.0f} Мбит/с"
        rows.append([_btn(label, result_id, "black")])

    # Назад
    rows.append([InlineKeyboardButton(
        text="← Назад",
        callback_data=f"back:{result_id}",
    )])

    # Текст-заголовок над клавиатурой
    parts = []
    if white:
        parts.append(f"⚪️ Белые SNI: {len(white)} конфигов")
    if black:
        parts.append(f"🖤 Обычные серверы: {len(black)} конфигов")
    header = "\n".join(parts) + "\n\nВыбери категорию для скачивания:"

    return header, InlineKeyboardMarkup(inline_keyboard=rows)


# ── FSM ────────────────────────────────────────────────────────────────────

class Flow(StatesGroup):
    waiting_signature = State()


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _looks_like_configs(text: str) -> bool:
    return any(line.strip().startswith(URI_SCHEMES) for line in text.splitlines())


async def _fetch_subscription_text(url: str) -> str:
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.text()


def _extract_lines(raw_text: str) -> list[str]:
    raw_text = raw_text.strip()
    if _looks_like_configs(raw_text):
        body = raw_text
    else:
        try:
            body = base64.b64decode(
                _pad(raw_text.replace("\n", "").replace("\r", ""))
            ).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            body = raw_text
    return [ln.strip() for ln in body.splitlines() if ln.strip().startswith(URI_SCHEMES)]


async def _get_input_text(message: Message) -> str | None:
    if message.document:
        file = await message.bot.get_file(message.document.file_id)
        buf = await message.bot.download_file(file.file_path)
        return buf.read().decode("utf-8", errors="ignore")
    if message.text:
        return message.text
    return None


# ── Команды ────────────────────────────────────────────────────────────────

@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Привет! Пришли ссылку на подписку (или .txt файл / список конфигов), "
        f"я вытащу конфиги (до {cfg.MAX_CONFIGS} шт.), проверю их через sing-box "
        "и дам выбрать, какие прислать файлом.\n\n"
        "Значки у рабочих конфигов:\n"
        "⚡️ — скорость ≥ 10 Мбит/с или пинг ≤ 80 мс\n"
        "⚪️ — SNI из российского белого списка (труднее для DPI)\n"
        "🖤 — обычный SNI (иностранный домен)\n\n"
        "Команды:\n"
        "/queue — параметры очереди\n"
        "/cancel — отменить текущий запрос"
    )


@router.message(Command("cancel"))
async def cmd_cancel(message: Message, state: FSMContext):
    await state.clear()
    await message.answer("Отменено. Пришли новую подписку, когда будешь готов.")


@router.message(Command("queue"))
async def cmd_queue(message: Message):
    await message.answer(
        f"Параллельно проверяется конфигов в одной подписке: {cfg.TEST_CONCURRENCY}\n"
        f"Одновременно обрабатывается подписок: {cfg.JOB_CONCURRENCY}\n"
        f"Лимит конфигов на подписку: {cfg.MAX_CONFIGS}\n\n"
        f"⚡️ ставится при скорости от {cfg.MIN_FAST_SPEED_MBPS:g} Мбит/с "
        f"или пинге до {cfg.MAX_FAST_PING_MS:g} мс"
    )


@router.message(Flow.waiting_signature, Command("skip"))
async def skip_signature(message: Message, state: FSMContext):
    await _enqueue(message, state, signature="")


@router.message(Flow.waiting_signature, F.text)
async def receive_signature(message: Message, state: FSMContext):
    await _enqueue(message, state, signature=message.text.strip())


@router.message(StateFilter(None), F.text | F.document)
async def receive_subscription(message: Message, state: FSMContext):
    raw_input = await _get_input_text(message)
    if not raw_input:
        await message.answer("Не понял. Пришли ссылку, .txt файл или список конфигов.")
        return

    raw_input = raw_input.strip()
    status = await message.answer("Загружаю и разбираю подписку…")

    try:
        if raw_input.startswith(("http://", "https://")) and "\n" not in raw_input:
            sub_text = await _fetch_subscription_text(raw_input)
        else:
            sub_text = raw_input
    except Exception as e:
        await status.edit_text(f"Не смог загрузить подписку: {e}")
        return

    lines = _extract_lines(sub_text)
    if not lines:
        await status.edit_text(
            "Не нашёл ни одного поддерживаемого конфига (vless/vmess/trojan/ss/hysteria2)."
        )
        return

    truncated = len(lines) > cfg.MAX_CONFIGS
    if truncated:
        lines = lines[: cfg.MAX_CONFIGS]

    parsed, failed = [], 0
    for line in lines:
        try:
            parsed.append(parse_config(line))
        except ParseError:
            failed += 1

    if not parsed:
        await status.edit_text("Ни один конфиг не удалось разобрать.")
        return

    await state.update_data(parsed=parsed)
    await state.set_state(Flow.waiting_signature)

    note = f"\n({failed} конфигов не распознано)" if failed else ""
    trunc_note = f"\nВзял первые {cfg.MAX_CONFIGS} из подписки (лимит)." if truncated else ""
    await status.edit_text(
        f"Нашёл {len(parsed)} конфигов.{note}{trunc_note}\n\n"
        "Хочешь добавить свою подпись к рабочим конфигам? Пришли текст подписи "
        "или отправь /skip, чтобы оставить только флаг (если есть)."
    )


async def _enqueue(message: Message, state: FSMContext, signature: str):
    data = await state.get_data()
    parsed = data.get("parsed")
    await state.clear()
    if not parsed:
        await message.answer("Сессия устарела, пришли подписку заново.")
        return

    status = await message.answer("Добавлено в очередь…")
    chat_id = status.chat.id

    async def progress_cb(text: str):
        try:
            await message.bot.edit_message_text(text, chat_id=chat_id, message_id=status.message_id)
        except Exception:
            pass

    async def done_cb(items: list[WorkingItem], working: int, total: int):
        if not items:
            await progress_cb(f"Готово. Рабочих конфигов: 0 из {total}.")
            return

        result_id = uuid.uuid4().hex[:10]
        _pending_results[result_id] = items

        white_count = sum(1 for i in items if i.is_white)
        black_count = working - white_count

        summary = (
            f"Готово: {working} рабочих из {total}.\n"
            f"⚪️ Белые SNI: {white_count}  🖤 Обычные: {black_count}\n\n"
            "Что прислать файлом?"
        )
        kb = _main_keyboard(result_id, items)
        try:
            await message.bot.edit_message_text(
                summary, chat_id=chat_id, message_id=status.message_id, reply_markup=kb,
            )
        except Exception:
            await message.bot.send_message(chat_id, summary, reply_markup=kb)

    job = await job_queue.submit(message.from_user.id, parsed, signature, progress_cb, done_cb)
    pos = job_queue.position_of(job.job_id)
    if pos > 0:
        await progress_cb(f"В очереди, позиция: {pos}. Ожидай…")
    else:
        await progress_cb(f"Начинаю проверку {len(parsed)} конфигов…")


# ── Callback: открыть меню категорий ───────────────────────────────────────

@router.callback_query(F.data.startswith("cat:"))
async def open_categories(callback: CallbackQuery):
    _, result_id = callback.data.split(":", 1)
    items = _pending_results.get(result_id)
    if items is None:
        await callback.answer("Результат устарел, пришли подписку заново.", show_alert=True)
        return

    header, kb = _category_keyboard(result_id, items)
    try:
        await callback.message.edit_text(header, reply_markup=kb)
    except Exception:
        pass
    await callback.answer()


# ── Callback: вернуться в главное меню ─────────────────────────────────────

@router.callback_query(F.data.startswith("back:"))
async def back_to_main(callback: CallbackQuery):
    _, result_id = callback.data.split(":", 1)
    items = _pending_results.get(result_id)
    if items is None:
        await callback.answer("Результат устарел, пришли подписку заново.", show_alert=True)
        return

    working = len(items)
    white_count = sum(1 for i in items if i.is_white)
    black_count = working - white_count

    summary = (
        f"Готово: {working} рабочих.\n"
        f"⚪️ Белые SNI: {white_count}  🖤 Обычные: {black_count}\n\n"
        "Что прислать файлом?"
    )
    kb = _main_keyboard(result_id, items)
    try:
        await callback.message.edit_text(summary, reply_markup=kb)
    except Exception:
        pass
    await callback.answer()


# ── Callback: скачать файл ─────────────────────────────────────────────────

@router.callback_query(F.data.startswith("send:"))
async def send_selected(callback: CallbackQuery):
    _, result_id, kind = callback.data.split(":", 2)
    items = _pending_results.get(result_id)
    if items is None:
        await callback.answer("Результат устарел, пришли подписку заново.", show_alert=True)
        return

    selected = _sorted_items(items, kind)
    if not selected:
        await callback.answer("Нет конфигов под этот фильтр.", show_alert=True)
        return

    sort_word = "скорости" if _SORT_KEYS.get(kind) == "speed" else "пингу"
    content = "\n".join(i.line for i in selected).encode("utf-8")
    doc = BufferedInputFile(content, filename="working_configs.txt")
    await callback.message.answer_document(
        doc,
        caption=(
            f"{_DELIVERY_LABELS.get(kind, 'Все')}: {len(selected)} конфигов.\n"
            f"Отсортировано по {sort_word}."
        ),
    )
    await callback.answer()


# ── Точка входа ────────────────────────────────────────────────────────────

def _build_bot() -> Bot:
    """Создаёт Bot; если задан TELEGRAM_PROXY_HOST — ходит через свой прокси
    вместо api.telegram.org (например, чтобы не палить прямой IP сервера)."""
    if cfg.TELEGRAM_PROXY_HOST:
        proxy_api = TelegramAPIServer.from_base(f"https://{cfg.TELEGRAM_PROXY_HOST}")
        session = AiohttpSession(api=proxy_api)
        session._connector_init["ssl"] = False
        log.info("Using Telegram API proxy: %s", cfg.TELEGRAM_PROXY_HOST)
        return Bot(token=cfg.BOT_TOKEN, session=session)
    return Bot(token=cfg.BOT_TOKEN)


async def main():
    os.makedirs(cfg.WORK_DIR, exist_ok=True)
    if not cfg.BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set")

    bot = _build_bot()
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    job_queue.start()

    await sni_whitelist.update_from_github()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
