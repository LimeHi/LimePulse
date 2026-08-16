"""
FIFO-очередь для задач тестирования подписок. Фиксированное число воркеров
(JOB_CONCURRENCY) обрабатывают задачи последовательно, чтобы не плодить бесконечно
sing-box процессы. Внутри задачи конфиги тестируются конкурентно (TEST_CONCURRENCY).

WorkingItem хранит latency_ms и speed_mbps, чтобы main.py мог выводить
отсортированный по скорости/пингу список в кнопках выбора.
"""
from __future__ import annotations

import asyncio
import dataclasses
from typing import Awaitable, Callable, List, Optional, Tuple

import config as cfg
import sni_whitelist
from protocol_parser import ParsedConfig, build_final_link, extract_flag_emoji
from singbox_runner import TestResult, test_config

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


class JobQueue:
    def __init__(self):
        self._queue: "asyncio.Queue[Job]" = asyncio.Queue()
        self._pending: List[Job] = []
        self._next_id = 1
        self._active_jobs: dict[int, Job] = {}
        self._workers_started = False

    def start(self):
        if self._workers_started:
            return
        self._workers_started = True
        for _ in range(cfg.JOB_CONCURRENCY):
            asyncio.create_task(self._worker())

    def position_of(self, job_id: int) -> int:
        for i, j in enumerate(self._pending):
            if j.job_id == job_id:
                return i
        return 0

    async def submit(self, user_id: int, configs: List[ParsedConfig], signature: str,
                      progress_cb: ProgressCb, done_cb: DoneCb) -> Job:
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

    async def _worker(self):
        while True:
            job = await self._queue.get()
            if job in self._pending:
                self._pending.remove(job)
            self._active_jobs[job.job_id] = job
            try:
                if not job.cancelled:
                    await self._run_job(job)
            finally:
                self._active_jobs.pop(job.job_id, None)
                self._queue.task_done()

    async def _run_job(self, job: Job):
        total = len(job.configs)
        working: List[Tuple[ParsedConfig, TestResult]] = []
        checked = 0
        sem = asyncio.Semaphore(cfg.TEST_CONCURRENCY)
        lock = asyncio.Lock()

        async def worker(pc: ParsedConfig):
            nonlocal checked
            if job.cancelled:
                return
            async with sem:
                if job.cancelled:
                    return
                result = await test_config(pc.outbound)
            async with lock:
                checked += 1
                if result.ok:
                    working.append((pc, result))
                if checked % 10 == 0 or checked == total:
                    await job.progress_cb(
                        f"Проверено {checked}/{total}, рабочих: {len(working)}"
                    )

        await asyncio.gather(*(worker(pc) for pc in job.configs))

        if job.cancelled:
            return

        # Сортировка: сначала по скорости (убывает), при равенстве — по пингу (растёт)
        def sort_key(t: Tuple[ParsedConfig, TestResult]):
            _, r = t
            speed = -(r.speed_mbps or 0.0)          # больше — лучше → инвертируем
            latency = r.latency_ms if r.latency_ms is not None else float("inf")
            return (speed, latency)

        working.sort(key=sort_key)

        items: List[WorkingItem] = []
        for idx, (pc, result) in enumerate(working, start=1):
            is_fast = (
                (result.speed_mbps is not None and result.speed_mbps >= cfg.MIN_FAST_SPEED_MBPS)
                or (result.latency_ms is not None and result.latency_ms <= cfg.MAX_FAST_PING_MS)
            )
            sni = pc.outbound.get("tls", {}).get("server_name")
            is_white = sni_whitelist.is_whitelisted(sni)

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

        await job.done_cb(items, len(items), total)
