"""
Async background task queue – no Redis required.

Uses asyncio primitives for a lightweight in-process queue suitable for
single-instance deployments. For horizontal scaling, swap this with
a Celery/Redis or ARQ backend.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from trustlens.core.logging import get_logger

logger = get_logger(__name__)

TaskFunc = Callable[..., Awaitable[Any]]


class AsyncTaskQueue:
    """In-process async task queue backed by asyncio.Queue."""

    def __init__(self, max_concurrent: int = 5) -> None:
        self._queue: asyncio.Queue[tuple[str, TaskFunc, tuple, dict]] = asyncio.Queue()
        self._max_concurrent = max_concurrent
        self._workers: list[asyncio.Task] = []  # type: ignore
        self._running = False
        self._stats: dict[str, int] = defaultdict(int)

    async def start(self) -> None:
        """Start worker tasks."""
        if self._running:
            return
        self._running = True
        for i in range(self._max_concurrent):
            task = asyncio.create_task(self._worker(f"worker-{i}"))
            self._workers.append(task)
        logger.info("task_queue.started", workers=self._max_concurrent)

    async def stop(self) -> None:
        """Gracefully stop all workers."""
        self._running = False
        # Send poison pills
        for _ in self._workers:
            await self._queue.put(("__stop__", lambda: None, (), {}))  # type: ignore
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info("task_queue.stopped")

    async def enqueue(self, task_id: str, func: TaskFunc, *args: Any, **kwargs: Any) -> None:
        """Add a task to the queue."""
        await self._queue.put((task_id, func, args, kwargs))
        self._stats["enqueued"] += 1
        logger.info("task_queue.enqueued", task_id=task_id, queue_size=self._queue.qsize())

    async def submit(self, coro) -> None:
        """Convenience: wrap an already-created coroutine as a task."""
        import uuid

        task_id = uuid.uuid4().hex[:8]

        async def _wrapper():
            await coro

        await self.enqueue(task_id, _wrapper)

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def _worker(self, name: str) -> None:
        """Process tasks from the queue."""
        while self._running:
            try:
                task_id, func, args, kwargs = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue

            if task_id == "__stop__":
                break

            try:
                logger.info("task_queue.processing", worker=name, task_id=task_id)
                await func(*args, **kwargs)
                self._stats["completed"] += 1
                logger.info("task_queue.completed", worker=name, task_id=task_id)
            except Exception as e:
                self._stats["failed"] += 1
                logger.error("task_queue.failed", worker=name, task_id=task_id, error=str(e))
            finally:
                self._queue.task_done()
