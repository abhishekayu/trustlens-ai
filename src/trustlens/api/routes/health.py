"""
Health / readiness endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from trustlens.core import get_settings
from trustlens.schemas import HealthResponse
from trustlens.api.deps import get_db, get_task_queue
from trustlens.db import Database
from trustlens.services.queue import AsyncTaskQueue

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse, summary="Service health check")
async def health(
    db: Database = Depends(get_db),
    queue: AsyncTaskQueue = Depends(get_task_queue),
):
    settings = get_settings()
    db_ok = db._connection is not None

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        version="0.1.0",
        ai_provider=settings.ai_provider,
        db_connected=db_ok,
        queue_stats={
            "pending": queue._queue.qsize() if hasattr(queue, "_queue") else 0,
            "active": queue._active if hasattr(queue, "_active") else 0,
            "max_concurrency": queue._max_concurrent if hasattr(queue, "_max_concurrent") else 0,
        },
    )
