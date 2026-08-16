"""
Telegram-бот: пользователь присылает подписку или список конфигов,
бот проверяет их через sing-box, сортирует по скорости/пингу,
добавляет ⚡️⚪️ префиксы и даёт выбрать, что прислать .txt файлом.
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

# result_id -> список WorkingItem, хранятся пока кнопки живые
_pending_results: dict[str, list[WorkingItem]] = {}

URI_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")

# ── Фильтры для кнопок доставки ────────────────────────────────────────────
_DELIVERY_FILTERS = {
    "all":       lambda i: True,
    "fast":      lambda i: i.is_fast,
    "white":     lambda i: i.is_white,
    "fastwhite": lambda i: i.is_fast and i.is_white,
}
_DELIVERY_LABELS = {
    "all":       "Все",
    "fast":      "⚡️ Быстрые",
    "white":     "⚪️ Белые SNI",
    "fastwhite": "⚡️⚪️ Быстрые и белые",
}

# Сортировка для каждого фильтра: "speed" — по убыванию скорости,
# "latency" — по возрастанию пинга
_SORT_KEYS = {
    "all":       "speed",
    "fast":      "speed",
    "white":     "latency",
    "fastwhite": "speed",
}


def _sorted_items(items: list[WorkingItem], kind: str) -> list[WorkingItem]:
    """Возвращает отфильтрованный и отсортированный список."""
    predicate = _DELIVERY_FILTERS.get(kind, _DELIVERY_FILTERS["all"])
    selected = [i for i in items if predicate(i)]
    sort_by = _SORT_KEYS.get(kind, "speed")
    if sort_by == "speed":
        selected.sort(
            key=lambda i: -(i.speed_mbps or 0.0)
        )
    else:
        selected.sort(
            key=lambda i: i.latency_ms if i.latency_ms is not None else float("inf")
        )
    return selected


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
        "⚪️ — SNI из российского белого списка (обход DPI)\n\n"
        "После проверки конфиги отсортированы по скорости/пингу.\n\n"
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

        # Подсчёт и подбор подписей к кнопкам
        fast_items   = [i for i in items if i.is_fast]
        white_items  = [i for i in items if i.is_white]
        fw_items     = [i for i in items if i.is_fast and i.is_white]

        def avg_speed(lst):
            speeds = [i.speed_mbps for i in lst if i.speed_mbps is not None]
            return sum(speeds) / len(speeds) if speeds else None

        def avg_ping(lst):
            pings = [i.latency_ms for i in lst if i.latency_ms is not None]
            return sum(pings) / len(pings) if pings else None

        def btn_label(key: str, lst: list[WorkingItem]) -> str:
            base = f"{_DELIVERY_LABELS[key]} ({len(lst)})"
            if key in ("fast", "fastwhite") and lst:
                spd = avg_speed(lst)
                if spd:
                    base += f" ~{spd:.0f} Мбит/с"
            elif key == "white" and lst:
                ping = avg_ping(lst)
                if ping:
                    base += f" ~{ping:.0f} мс"
            return base

        counts_map = {
            "all":       (working, items),
            "fast":      (len(fast_items), fast_items),
            "white":     (len(white_items), white_items),
            "fastwhite": (len(fw_items), fw_items),
        }

        buttons = [
            [InlineKeyboardButton(
                text=btn_label(key, lst),
                callback_data=f"send:{result_id}:{key}",
            )]
            for key, (count, lst) in counts_map.items()
            if count > 0
        ]
        kb = InlineKeyboardMarkup(inline_keyboard=buttons)
        try:
            await message.bot.edit_message_text(
                f"Готово: {working} рабочих из {total}. Что прислать файлом?\n"
                f"(отсортировано по скорости/пингу)",
                chat_id=chat_id, message_id=status.message_id, reply_markup=kb,
            )
        except Exception:
            await message.bot.send_message(
                chat_id,
                f"Готово: {working} рабочих из {total}. Что прислать файлом?",
                reply_markup=kb,
            )

    job = await job_queue.submit(message.from_user.id, parsed, signature, progress_cb, done_cb)
    pos = job_queue.position_of(job.job_id)
    if pos > 0:
        await progress_cb(f"В очереди, позиция: {pos}. Ожидай…")
    else:
        await progress_cb(f"Начинаю проверку {len(parsed)} конфигов…")


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

    content = "\n".join(i.line for i in selected).encode("utf-8")
    doc = BufferedInputFile(content, filename="working_configs.txt")
    await callback.message.answer_document(
        doc,
        caption=(
            f"{_DELIVERY_LABELS.get(kind, 'Все')}: {len(selected)} конфигов.\n"
            f"Отсортировано по {'скорости' if _SORT_KEYS.get(kind) == 'speed' else 'пингу'}."
        ),
    )
    await callback.answer()


async def main():
    os.makedirs(cfg.WORK_DIR, exist_ok=True)
    if not cfg.BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set")

    bot = Bot(token=cfg.BOT_TOKEN)
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    job_queue.start()

    # Обновляем SNI-вайтлист с GitHub перед стартом поллинга
    await sni_whitelist.update_from_github()

    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
