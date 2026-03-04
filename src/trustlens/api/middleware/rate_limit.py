"""
In-memory sliding-window rate limiter middleware.

Limits requests per client IP within a configurable time window.
For production with multiple workers, swap to Redis-backed rate limiting.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from trustlens.core import get_settings


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP sliding-window rate limiter.

    Configurable via:
      - TRUSTLENS_RATE_LIMIT_REQUESTS (max requests per window)
      - TRUSTLENS_RATE_LIMIT_WINDOW_SECONDS (window duration)
    """

    def __init__(self, app, max_requests: int = 30, window_seconds: int = 60):
        super().__init__(app)
        self._max_requests = max_requests
        self._window = window_seconds
        self._clients: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for health checks
        if request.url.path in ("/health", "/docs", "/openapi.json", "/redoc"):
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        now = time.time()
        cutoff = now - self._window

        with self._lock:
            # Prune expired timestamps
            timestamps = self._clients[client_ip]
            self._clients[client_ip] = [t for t in timestamps if t > cutoff]

            if len(self._clients[client_ip]) >= self._max_requests:
                retry_after = int(self._clients[client_ip][0] + self._window - now) + 1
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded. Please retry later.",
                        "retry_after_seconds": max(retry_after, 1),
                    },
                    headers={"Retry-After": str(max(retry_after, 1))},
                )

            self._clients[client_ip].append(now)
            remaining = self._max_requests - len(self._clients[client_ip])

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self._max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(now + self._window))
        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract client IP, respecting X-Forwarded-For behind proxies."""
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
