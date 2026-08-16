"""
FIFO job queue for subscription-testing requests. A small, fixed number of
workers (JOB_CONCURRENCY) process jobs sequentially so the host isn't asked
to run an unbounded number of sing-box processes at once. Inside a job,
individual configs are still tested concurrently, capped by
TEST_CONCURRENCY.
"""
from __future__ import annotations

import asyncio
import dataclasses
from typing import Awaitable, Callable, List, Tuple

import config as cfg
from protocol_parser import ParsedConfig, extract_flag_emoji, build_final_link
from singbox_runner import test_config

ProgressCb = Callable[[str], Awaitable[None]]
DoneCb = Callable[[List[str], int, int], Awaitable[None]]


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
        working: List[Tuple[ParsedConfig, float]] = []
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
                ok, latency = await test_config(pc.outbound)
            async with lock:
                checked += 1
                if ok:
                    working.append((pc, latency or 0.0))
                if checked % 10 == 0 or checked == total:
                    await job.progress_cb(f"Проверено {checked}/{total}, рабочих: {len(working)}")

        await asyncio.gather(*(worker(pc) for pc in job.configs))

        if job.cancelled:
            return

        working.sort(key=lambda t: t[1])
        lines = []
        for idx, (pc, _latency) in enumerate(working, start=1):
            flag = extract_flag_emoji(pc.remark)
            sig = job.signature.strip() if job.signature else ""
            parts = [p for p in (flag, sig) if p]
            new_remark = " ".join(parts) if parts else f"config-{idx}"
            lines.append(build_final_link(pc.raw, pc.protocol, new_remark))

        await job.done_cb(lines, len(working), total)
