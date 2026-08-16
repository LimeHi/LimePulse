"""
Telegram bot: users submit a VPN subscription, configs are pulled out,
tested for real connectivity through sing-box, and the working ones are
sent back as a clean plain-text file - one link per line, flag emoji kept
and moved first, followed by the user's own signature.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import os

import aiohttp
from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BufferedInputFile, Message

import config as cfg
from protocol_parser import ParseError, parse_config
from queue_manager import JobQueue

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vpn_tester_bot")

router = Router()
job_queue = JobQueue()

URI_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")


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


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Привет! Пришли ссылку на подписку (или .txt файл / список конфигов), "
        f"я вытащу конфиги (до {cfg.MAX_CONFIGS} шт.), проверю их через sing-box "
        "и пришлю рабочие одним файлом.\n\n"
        "Команды:\n"
        "/queue — статус очереди\n"
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
        f"Лимит конфигов на подписку: {cfg.MAX_CONFIGS}"
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
        "или отправь /skip, чтобы оставить только флаг (если он есть у конфига)."
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

    async def done_cb(lines: list[str], working: int, total: int):
        if not lines:
            await progress_cb(f"Готово. Рабочих конфигов: 0 из {total}.")
            return
        content = "\n".join(lines).encode("utf-8")
        doc = BufferedInputFile(content, filename="working_configs.txt")
        await message.bot.send_document(
            chat_id, doc, caption=f"Готово: {working} рабочих из {total} проверенных."
        )
        try:
            await message.bot.delete_message(chat_id, status.message_id)
        except Exception:
            pass

    job = await job_queue.submit(message.from_user.id, parsed, signature, progress_cb, done_cb)
    pos = job_queue.position_of(job.job_id)
    if pos > 0:
        await progress_cb(f"В очереди, позиция: {pos}. Ожидай…")
    else:
        await progress_cb(f"Начинаю проверку {len(parsed)} конфигов…")


async def main():
    os.makedirs(cfg.WORK_DIR, exist_ok=True)
    if not cfg.BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set")
    bot = Bot(token=cfg.BOT_TOKEN)
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    job_queue.start()
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
