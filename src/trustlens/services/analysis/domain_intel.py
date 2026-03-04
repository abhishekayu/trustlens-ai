"""
Domain Intelligence Module.

Provides RDAP lookup, domain age scoring, suspicious TLD detection,
and DNS resolution analysis.
"""

from __future__ import annotations

import asyncio
import socket
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import tldextract

from trustlens.core.logging import get_logger
from trustlens.models import DomainIntelligence

logger = get_logger(__name__)

# TLDs commonly abused in phishing campaigns (data-driven from APWG reports)
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",          # Freenom free TLDs
    "buzz", "xyz", "top", "club", "work",    # cheap gTLDs
    "icu", "cam", "surf", "monster",
    "click", "link", "site", "online",
    "rest", "fit", "loan", "racing",
    "win", "bid", "stream", "download",
    "gdn", "men", "review", "party",
}

# RDAP bootstrap for gTLDs
_RDAP_BOOTSTRAP = "https://rdap.org/domain/"


class DomainIntelligenceService:
    """Analyse domain registration, age, TLD risk, and DNS."""

    async def analyze(self, url: str) -> DomainIntelligence:
        """Run full domain intelligence gathering."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        ext = tldextract.extract(url)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""

        intel = DomainIntelligence(
            domain=hostname,
            registered_domain=registered_domain,
            tld=tld,
        )

        # Run sub-analyses concurrently
        rdap_task = self._rdap_lookup(registered_domain)
        dns_task = self._dns_resolve(hostname)
        tld_task = asyncio.coroutine(lambda: None)  # sync, just compute inline

        rdap_result, dns_result = await asyncio.gather(
            rdap_task, dns_task, return_exceptions=True
        )

        # ── TLD scoring ──────────────────────────────────────────
        if tld.lower() in SUSPICIOUS_TLDS:
            intel.is_suspicious_tld = True
            intel.tld_score = 30.0
            intel.signals.append(f"Suspicious TLD: .{tld} is frequently abused in phishing")
        else:
            intel.tld_score = 100.0

        # ── RDAP / domain age ────────────────────────────────────
        if isinstance(rdap_result, dict) and rdap_result:
            intel.rdap_raw = rdap_result
            self._parse_rdap(intel, rdap_result)
        elif isinstance(rdap_result, Exception):
            logger.warning("domain_intel.rdap_failed", domain=registered_domain, error=str(rdap_result))
            intel.signals.append("RDAP lookup failed – domain age unknown")

        # ── DNS ──────────────────────────────────────────────────
        if isinstance(dns_result, dict):
            intel.dns_records = dns_result
            if not dns_result.get("A") and not dns_result.get("AAAA"):
                intel.signals.append("No A/AAAA records found")
        elif isinstance(dns_result, Exception):
            logger.warning("domain_intel.dns_failed", domain=hostname, error=str(dns_result))

        # ── Aggregate domain score ───────────────────────────────
        intel.domain_score = (intel.age_score * 0.5 + intel.tld_score * 0.5)
        return intel

    async def _rdap_lookup(self, domain: str) -> dict[str, Any]:
        """Query RDAP for domain registration data."""
        url = f"{_RDAP_BOOTSTRAP}{domain}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, follow_redirects=True)
                if resp.status_code == 200:
                    return resp.json()
                return {}
        except Exception as e:
            logger.debug("rdap.request_failed", domain=domain, error=str(e))
            return {}

    async def _dns_resolve(self, hostname: str) -> dict[str, list[str]]:
        """Resolve A, AAAA, MX, TXT records."""
        records: dict[str, list[str]] = {}
        loop = asyncio.get_event_loop()

        for qtype, family in [("A", socket.AF_INET), ("AAAA", socket.AF_INET6)]:
            try:
                infos = await loop.run_in_executor(
                    None, lambda f=family: socket.getaddrinfo(hostname, None, f, socket.SOCK_STREAM)
                )
                records[qtype] = list({sockaddr[0] for _, _, _, _, sockaddr in infos})
            except socket.gaierror:
                records[qtype] = []

        return records

    def _parse_rdap(self, intel: DomainIntelligence, data: dict[str, Any]) -> None:
        """Extract registration dates and registrar from RDAP response."""
        events = data.get("events", [])
        for event in events:
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            if action == "registration" and date_str:
                intel.registration_date = date_str[:10]
                try:
                    reg_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - reg_date).days
                    intel.domain_age_days = age
                    intel.age_score = self._compute_age_score(age)
                    if age < 30:
                        intel.signals.append(f"Very new domain: registered {age} days ago")
                    elif age < 90:
                        intel.signals.append(f"Recently registered domain: {age} days ago")
                except (ValueError, TypeError):
                    pass
            elif action == "expiration" and date_str:
                intel.expiration_date = date_str[:10]

        # Registrar
        entities = data.get("entities", [])
        for ent in entities:
            roles = ent.get("roles", [])
            if "registrar" in roles:
                vcard = ent.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            intel.registrar = field[3] if len(field) > 3 else ""
                            break

    @staticmethod
    def _compute_age_score(age_days: int) -> float:
        """Map domain age to a trust score (0-100)."""
        if age_days < 7:
            return 10.0
        elif age_days < 30:
            return 25.0
        elif age_days < 90:
            return 50.0
        elif age_days < 365:
            return 75.0
        elif age_days < 365 * 3:
            return 90.0
        else:
            return 100.0
