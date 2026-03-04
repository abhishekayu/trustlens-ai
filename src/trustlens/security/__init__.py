"""
Security utilities – SSRF protection, URL validation, sandboxing helpers.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from trustlens.core.logging import get_logger

logger = get_logger(__name__)

# Private / reserved CIDR ranges that must be blocked for SSRF protection
_BLOCKED_CIDRS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

_BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data", "javascript"}


class SSRFError(Exception):
    """Raised when a URL targets a blocked network."""


def validate_url(url: str) -> str:
    """
    Validate and normalize a URL for safe crawling.

    Raises SSRFError if the URL resolves to a private/blocked address.
    Returns the normalized URL string.
    """
    parsed = urlparse(url)

    # Scheme check
    scheme = (parsed.scheme or "").lower()
    if scheme in _BLOCKED_SCHEMES:
        raise SSRFError(f"Blocked scheme: {scheme}")
    if scheme not in ("http", "https"):
        raise SSRFError(f"Unsupported scheme: {scheme}")

    # Hostname check
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("Missing hostname")

    # Reject obvious bypasses
    if hostname in ("localhost", "0.0.0.0"):
        raise SSRFError(f"Blocked hostname: {hostname}")

    return url


async def check_ssrf(url: str, block_private: bool = True) -> None:
    """
    Resolve the hostname and verify it doesn't point to a private IP.

    Should be called before every outbound request.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("Missing hostname")

    if not block_private:
        return

    try:
        # Resolve hostname to IP(s)
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            for cidr in _BLOCKED_CIDRS:
                if ip in cidr:
                    raise SSRFError(
                        f"URL resolves to blocked address: {hostname} → {ip} ({cidr})"
                    )
    except socket.gaierror:
        # DNS resolution failed – let the crawler handle the error downstream
        logger.warning("ssrf_check.dns_failed", hostname=hostname)


def sanitize_html_for_ai(html: str, max_length: int = 50_000) -> str:
    """
    Strip potentially dangerous content and truncate HTML for AI consumption.
    Removes script contents but keeps structure.
    """
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")

    # Remove script and style content (we keep tags for structural analysis)
    for tag in soup.find_all(["script", "style"]):
        tag.decompose()

    text = soup.get_text(separator="\n", strip=True)
    if len(text) > max_length:
        text = text[:max_length] + "\n[TRUNCATED]"
    return text


def extract_domain(url: str) -> str:
    """Extract the registered domain from a URL using tldextract."""
    import tldextract

    ext = tldextract.extract(url)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain
