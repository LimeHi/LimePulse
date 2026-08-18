"""
FIFO-очередь для задач тестирования подписок.

Ключевые защиты от зависания:
- asyncio.gather(..., return_exceptions=True) — одна упавшая корутина
  не отменяет остальные
- progress_cb вызывается ВНЕ lock, и обёрнута в try/except — ошибка
  Telegram API не роняет воркер
- _worker перезапускается при любом исключении (бесконечный цикл
  обёрнут в try/except с логированием)
- test_config сам по себе не кидает исключений, но на случай багов
  worker() тоже обёрнут
"""
from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import Awaitable, Callable, List, Optional, Tuple

import config as cfg
import sni_whitelist
from protocol_parser import ParsedConfig, build_final_link, extract_flag_emoji
from singbox_runner import TestResult, test_config

log = logging.getLogger("queue_manager")

ProgressCb = Callable[[str], Awaitable[None]]


@dataclasses.dataclass
class WorkingItem:
    line: str
    is_fast: bool
    is_white: bool
    latency_ms: Optional[float] = None
    speed_mbps: Optional[float] = None


DoneCb = Callable[[List[WorkingItem], int, int], Awaitable[None]]


@dataclasses.dataclass
class Job:
    job_id: int
    user_id: int
    configs: List[ParsedConfig]
    signature: str
    progress_cb: ProgressCb
    done_cb: DoneCb
    cancelled: bool = False


def _extract_sni(outbound: dict) -> Optional[str]:
    """
    Достаёт SNI из outbound для любого протокола.

    Проблема была в том, что код делал только:
        outbound.get("tls", {}).get("server_name")
    — это работает для vless/vmess/trojan, но:
    - hysteria2 хранит tls как вложенный dict с ключом "server_name" (ок),
      однако sing-box иногда кладёт его под "tls" → "server_name" напрямую ✓
    - ss вообще не имеет tls → всегда None → никогда не белый

    Порядок проверки:
    1. outbound["tls"]["server_name"]  — vless/vmess/trojan/hysteria2
    2. outbound["server"]              — fallback: у ss это целевой хост;
       если SNI явно не задан, проверяем хотя бы хост (иногда совпадает
       с белым доменом, но чаще нет — это честный fallback, не магия)
    """
    # Путь 1: стандартный TLS-блок (vless, vmess, trojan, hysteria2)
    tls = outbound.get("tls")
    if isinstance(tls, dict):
        sni = tls.get("server_name")
        if sni:
            return sni

    # Путь 2: для ss и прочих без TLS — хост сервера
    # Белыми они не будут (у них нет SNI), но хотя бы не падаем
    return outbound.get("server")


class JobQueue:
    def __init__(self):
        self._queue: asyncio.Queue[Job] = asyncio.Queue()
        self._pending: List[Job] = []
        self._next_id = 1
        self._active_jobs: dict[int, Job] = {}
        self._workers_started = False

    def start(self):
        if self._workers_started:
            return
        self._workers_started = True
        for i in range(cfg.JOB_CONCURRENCY):
            asyncio.create_task(self._worker_loop(i))

    def position_of(self, job_id: int) -> int:
        for i, j in enumerate(self._pending):
            if j.job_id == job_id:
                return i
        return 0

    async def submit(
        self,
        user_id: int,
        configs: List[ParsedConfig],
        signature: str,
        progress_cb: ProgressCb,
        done_cb: DoneCb,
    ) -> Job:
        job = Job(self._next_id, user_id, configs, signature, progress_cb, done_cb)
        self._next_id += 1
        self._pending.append(job)
        await self._queue.put(job)
        return job

    def cancel(self, job_id: int) -> bool:
        job = self._active_jobs.get(job_id)
        if job:
            job.cancelled = True
            return True
        for j in self._pending:
            if j.job_id == job_id:
                j.cancelled = True
                return True
        return False

    async def _worker_loop(self, worker_id: int):
        """Бесконечный цикл воркера. Перезапускается при любом исключении."""
        log.info("Worker %d started", worker_id)
        while True:
            try:
                job = await self._queue.get()
                if job in self._pending:
                    self._pending.remove(job)
                self._active_jobs[job.job_id] = job
                try:
                    if not job.cancelled:
                        await self._run_job(job)
                except Exception as e:
                    log.exception("Worker %d: _run_job crashed (job %d): %s", worker_id, job.job_id, e)
                finally:
                    self._active_jobs.pop(job.job_id, None)
                    self._queue.task_done()
            except Exception as e:
                log.exception("Worker %d: outer loop crashed: %s — restarting", worker_id, e)
                await asyncio.sleep(1)

    async def _safe_progress(self, job: Job, text: str):
        """Отправляет прогресс, не роняя воркер при ошибке Telegram."""
        try:
            await job.progress_cb(text)
        except Exception as e:
            log.debug("progress_cb error (job %d): %s", job.job_id, e)

    async def _run_job(self, job: Job):
        total = len(job.configs)
        working: List[Tuple[ParsedConfig, TestResult]] = []
        checked = 0
        sem = asyncio.Semaphore(cfg.TEST_CONCURRENCY)
        lock = asyncio.Lock()

        async def one_config(pc: ParsedConfig):
            nonlocal checked
            if job.cancelled:
                return
            try:
                async with sem:
                    if job.cancelled:
                        return
                    result = await test_config(pc.outbound)
            except Exception as e:
                log.debug("test_config wrapper caught: %s", e)
                result = TestResult(False)

            async with lock:
                checked += 1
                if result.ok:
                    working.append((pc, result))
                send_progress = (checked % 10 == 0 or checked == total)

            if send_progress:
                await self._safe_progress(
                    job, f"Проверено {checked}/{total}, рабочих: {len(working)}"
                )

        results = await asyncio.gather(
            *(one_config(pc) for pc in job.configs),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                log.debug("gather caught stray exception: %s", r)

        if job.cancelled:
            return

        working.sort(key=lambda t: (-(t[1].speed_mbps or 0.0),
                                     t[1].latency_ms if t[1].latency_ms is not None else float("inf")))

        items: List[WorkingItem] = []
        for idx, (pc, result) in enumerate(working, start=1):
            is_fast = (
                (result.speed_mbps is not None and result.speed_mbps >= cfg.MIN_FAST_SPEED_MBPS)
                or (result.latency_ms is not None and result.latency_ms <= cfg.MAX_FAST_PING_MS)
            )

            # Фикс: используем _extract_sni вместо прямого .get("tls",{}).get("server_name")
            sni = _extract_sni(pc.outbound)
            is_white = sni_whitelist.is_whitelisted(sni)

            log.debug(
                "config #%d | speed=%.1f mbps | ping=%.0f ms | is_fast=%s | sni=%s | is_white=%s",
                idx,
                result.speed_mbps or 0.0,
                result.latency_ms or 0.0,
                is_fast,
                sni,
                is_white,
            )

            prefix = ("⚡️" if is_fast else "") + ("⚪️" if is_white else "")
            flag = extract_flag_emoji(pc.remark)
            sig = job.signature.strip() if job.signature else ""
            parts = [p for p in (prefix, flag, sig) if p]
            new_remark = " ".join(parts) if parts else f"config-{idx}"

            line = build_final_link(pc.raw, pc.protocol, new_remark)
            items.append(WorkingItem(
                line=line,
                is_fast=is_fast,
                is_white=is_white,
                latency_ms=result.latency_ms,
                speed_mbps=result.speed_mbps,
            ))

        try:
            await job.done_cb(items, len(items), total)
        except Exception as e:
            log.exception("done_cb error (job %d): %s", job.job_id, e)
