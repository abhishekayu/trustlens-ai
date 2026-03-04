"""
Domain allow/deny list middleware.

Enforces domain-level access control before analysis is queued.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from trustlens.core import get_settings


class DomainFilterMiddleware(BaseHTTPMiddleware):
    """
    Intercepts POST /api/v1/analyze requests and checks submitted URLs
    against configured allow/deny domain lists.

    If an allowlist is configured, only those domains are permitted.
    If a denylist is configured, those domains are blocked.
    """

    async def dispatch(self, request: Request, call_next):
        # Only filter analysis submission endpoints
        if request.method == "POST" and "/analyze" in request.url.path:
            try:
                body = await request.body()
                data = json.loads(body) if body else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return await call_next(request)

            urls_to_check = []
            if "url" in data:
                urls_to_check.append(data["url"])
            elif "urls" in data:
                urls_to_check.extend(data["urls"])

            for url_str in urls_to_check:
                rejection = self._check_domain(str(url_str))
                if rejection:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": rejection},
                    )

        return await call_next(request)

    @staticmethod
    def _check_domain(url: str) -> str | None:
        """Check URL domain against allow/deny lists.  Returns rejection reason or None."""
        settings = get_settings()
        allowlist = settings.allowed_domains
        denylist = settings.denied_domains

        if not allowlist and not denylist:
            return None

        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or "").lower()
        except Exception:
            return "Invalid URL"

        if not domain:
            return "Could not extract domain from URL"

        # Allowlist takes precedence: if set, domain must be in it
        if allowlist:
            if not any(domain == d or domain.endswith(f".{d}") for d in allowlist):
                return f"Domain '{domain}' is not in the configured allowlist"

        # Denylist: block if domain matches
        if denylist:
            if any(domain == d or domain.endswith(f".{d}") for d in denylist):
                return f"Domain '{domain}' is blocked by the configured denylist"

        return None
