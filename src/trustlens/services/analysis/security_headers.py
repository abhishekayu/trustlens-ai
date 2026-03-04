"""
Security Header Analyzer.

Evaluates HTTP response security headers. HTTPS enforcement, HSTS, CSP,
X-Frame-Options, etc. Produces a minor scoring influence signal.
"""

from __future__ import annotations

from trustlens.core.logging import get_logger
from trustlens.models import CrawlResult, SecurityHeaderResult

logger = get_logger(__name__)

# Headers to check with their relative importance (weight for internal scoring)
_SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", 20),
    "content-security-policy": ("CSP", 20),
    "x-frame-options": ("X-Frame-Options", 15),
    "x-content-type-options": ("X-Content-Type-Options", 10),
    "referrer-policy": ("Referrer-Policy", 10),
    "permissions-policy": ("Permissions-Policy", 10),
}

_HTTPS_WEIGHT = 15  # HTTPS enforcement weight in the 100-point scale


class SecurityHeaderAnalyzer:
    """Evaluate the security posture of HTTP response headers."""

    async def analyze(self, crawl: CrawlResult) -> SecurityHeaderResult:
        """Analyze headers and return a SecurityHeaderResult."""
        headers_lower = {k.lower(): v for k, v in crawl.headers.items()}
        ssl = crawl.ssl_info or {}

        result = SecurityHeaderResult()

        # ── HTTPS ────────────────────────────────────────────────
        result.is_https = ssl.get("is_https", False)
        score = 0.0

        if result.is_https:
            score += _HTTPS_WEIGHT
        else:
            result.missing_headers.append("HTTPS")
            result.signals.append("Site does not use HTTPS encryption")

        # ── Security headers ─────────────────────────────────────
        for header_key, (display_name, weight) in _SECURITY_HEADERS.items():
            present = header_key in headers_lower

            # Set the bool flags on the result model
            if header_key == "strict-transport-security":
                result.has_hsts = present
            elif header_key == "content-security-policy":
                result.has_csp = present
            elif header_key == "x-frame-options":
                result.has_x_frame_options = present
            elif header_key == "x-content-type-options":
                result.has_x_content_type_options = present
            elif header_key == "referrer-policy":
                result.has_referrer_policy = present
            elif header_key == "permissions-policy":
                result.has_permissions_policy = present

            if present:
                score += weight
            else:
                result.missing_headers.append(display_name)

        result.header_score = min(100.0, score)

        # Summary signal
        total = len(_SECURITY_HEADERS) + 1  # +1 for HTTPS
        present_count = total - len(result.missing_headers)
        if len(result.missing_headers) > 3:
            result.signals.append(
                f"Weak security posture: only {present_count}/{total} security headers present"
            )
        elif len(result.missing_headers) > 0:
            result.signals.append(
                f"Missing headers: {', '.join(result.missing_headers)}"
            )
        else:
            result.signals.append("All standard security headers present")

        logger.info(
            "security_headers.analyzed",
            score=result.header_score,
            missing=len(result.missing_headers),
        )
        return result
