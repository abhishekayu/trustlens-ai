"""
API Key Authentication Middleware – tiered access control.

Tiers:
    - free:       30 req/min, analyze + report scopes
    - pro:        200 req/min, all scopes + batch + priority
    - enterprise: 2000 req/min, all scopes + enterprise features

The middleware extracts the API key from the configured header (default:
X-API-Key), validates it against the database, and enforces per-key
rate limits that override the global rate limiter.

When `api_key_required=False` (default), unauthenticated requests proceed
with free-tier limits.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.models import APIKeyRecord, APITier

logger = get_logger(__name__)

# In-memory sliding-window rate limiter per API key
_key_windows: dict[str, list[float]] = defaultdict(list)


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Authenticate requests via API key and enforce tiered rate limits.

    Attaches `request.state.api_key` (APIKeyRecord | None) and
    `request.state.api_tier` (APITier) for downstream use.
    """

    # Paths that never require auth
    EXEMPT_PATHS = {"/health", "/docs", "/redoc", "/openapi.json"}

    def __init__(self, app, api_key_repo=None):
        super().__init__(app)
        self._repo = api_key_repo
        self._settings = get_settings()

    def set_repo(self, repo):
        """Set the API key repo after middleware creation (for lifespan init)."""
        self._repo = repo

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path.rstrip("/")

        # Exempt health / docs
        if path in self.EXEMPT_PATHS or path.startswith("/docs") or path.startswith("/redoc"):
            request.state.api_key = None
            request.state.api_tier = APITier.FREE
            return await call_next(request)

        # Extract API key from header
        raw_key = request.headers.get(self._settings.api_key_header, "")
        key_record: Optional[APIKeyRecord] = None

        if raw_key and self._repo:
            key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
            key_record = await self._repo.get_by_hash(key_hash)

            if key_record is None:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid API key"},
                )

            if not key_record.enabled:
                return JSONResponse(
                    status_code=403,
                    content={"error": "API key has been revoked"},
                )

            # Check expiration
            if key_record.expires_at:
                from datetime import datetime, timezone
                if datetime.now(timezone.utc) > key_record.expires_at:
                    return JSONResponse(
                        status_code=403,
                        content={"error": "API key has expired"},
                    )

            # Check scope
            scope_check = self._check_scope(request, key_record)
            if scope_check:
                return scope_check

            # Per-key rate limiting
            rate_check = self._check_key_rate_limit(key_record)
            if rate_check:
                return rate_check

        elif self._settings.api_key_required:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "API key required",
                    "header": self._settings.api_key_header,
                    "hint": "Request a free API key at /api/v1/keys/register",
                },
            )

        # Attach to request state
        request.state.api_key = key_record
        request.state.api_tier = key_record.tier if key_record else APITier.FREE

        return await call_next(request)

    def _check_scope(self, request: Request, key: APIKeyRecord) -> Optional[JSONResponse]:
        """Check if the API key has the required scope for this endpoint."""
        path = request.url.path.lower()

        required_scope = "analyze"
        if "/report" in path:
            required_scope = "report"
        elif "/batch" in path:
            required_scope = "batch"
        elif "/enterprise" in path or "/monitor" in path:
            required_scope = "enterprise"
        elif "/community" in path:
            required_scope = "community"
        elif "/threat" in path:
            required_scope = "threat_intel"

        if key.scopes and required_scope not in key.scopes:
            return JSONResponse(
                status_code=403,
                content={
                    "error": f"API key lacks required scope: '{required_scope}'",
                    "available_scopes": key.scopes,
                },
            )
        return None

    def _check_key_rate_limit(self, key: APIKeyRecord) -> Optional[JSONResponse]:
        """Sliding-window rate limit per API key."""
        now = time.time()
        window = _key_windows[key.key_hash]

        # Prune old entries
        cutoff = now - key.rate_window
        _key_windows[key.key_hash] = [t for t in window if t > cutoff]
        window = _key_windows[key.key_hash]

        if len(window) >= key.rate_limit:
            retry_after = int(key.rate_window - (now - window[0])) + 1
            logger.warning(
                "api_auth.rate_limited",
                key_hash=key.key_hash[:8],
                tier=key.tier.value,
                limit=key.rate_limit,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded for your API tier",
                    "tier": key.tier.value,
                    "limit": key.rate_limit,
                    "window_seconds": key.rate_window,
                    "retry_after": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        window.append(now)
        return None
