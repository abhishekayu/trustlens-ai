"""
Threat Intelligence Feed System – aggregate external threat data.

Supports multiple feed sources:
    1. URLhaus (abuse.ch) – malware distribution URLs
    2. PhishTank – community-verified phishing URLs
    3. OpenPhish – machine-learning phishing feed
    4. Custom CSV/JSON feeds via configuration

The system caches feeds locally in the database and refreshes on a
configurable interval.  During analysis, the orchestrator queries the
local cache for O(1) lookups instead of hitting external APIs.

Architecture:
    FeedIngester → (parse) → ThreatFeedEntry → ThreatIntelRepository → (local cache)
    AnalysisOrchestrator → ThreatIntelService.lookup() → ThreatIntelResult
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.db import ThreatIntelRepository
from trustlens.models import ThreatFeedEntry, ThreatIntelResult

logger = get_logger(__name__)


# ── Feed Parsers ─────────────────────────────────────────────────────────────


class FeedParser:
    """Base class for threat feed parsers."""

    feed_name: str = "unknown"

    def parse(self, raw: str) -> list[ThreatFeedEntry]:
        raise NotImplementedError


class URLhausParser(FeedParser):
    """Parse abuse.ch URLhaus CSV feed."""

    feed_name = "urlhaus"

    def parse(self, raw: str) -> list[ThreatFeedEntry]:
        entries: list[ThreatFeedEntry] = []
        reader = csv.reader(io.StringIO(raw))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            try:
                # URLhaus CSV format: id, dateadded, url, url_status, threat, tags, ...
                if len(row) >= 6:
                    url = row[2].strip().strip('"')
                    threat_type = row[4].strip().strip('"') if len(row) > 4 else "malware"
                    tags_str = row[5].strip().strip('"') if len(row) > 5 else ""
                    tags = [t.strip() for t in tags_str.split(",") if t.strip()]

                    domain = urlparse(url).netloc.lower()
                    entries.append(ThreatFeedEntry(
                        indicator=domain or url,
                        indicator_type="domain" if domain else "url",
                        feed_name=self.feed_name,
                        threat_type=threat_type or "malware",
                        confidence=0.8,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        tags=tags,
                    ))
            except Exception:
                continue
        return entries


class PhishTankParser(FeedParser):
    """Parse PhishTank JSON feed."""

    feed_name = "phishtank"

    def parse(self, raw: str) -> list[ThreatFeedEntry]:
        entries: list[ThreatFeedEntry] = []
        try:
            data = json.loads(raw)
            if not isinstance(data, list):
                return entries
            for item in data[:10000]:  # Cap at 10k entries
                url = item.get("url", "")
                if not url:
                    continue
                domain = urlparse(url).netloc.lower()
                verified = item.get("verified", "no") == "yes"
                entries.append(ThreatFeedEntry(
                    indicator=domain or url,
                    indicator_type="domain" if domain else "url",
                    feed_name=self.feed_name,
                    threat_type="phishing",
                    confidence=0.9 if verified else 0.6,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    tags=["phishing", "verified" if verified else "unverified"],
                ))
        except (json.JSONDecodeError, KeyError):
            logger.warning("feed_parser.phishtank.parse_failed")
        return entries


class OpenPhishParser(FeedParser):
    """Parse OpenPhish text feed (one URL per line)."""

    feed_name = "openphish"

    def parse(self, raw: str) -> list[ThreatFeedEntry]:
        entries: list[ThreatFeedEntry] = []
        for line in raw.strip().splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            domain = urlparse(url).netloc.lower()
            entries.append(ThreatFeedEntry(
                indicator=domain or url,
                indicator_type="domain" if domain else "url",
                feed_name=self.feed_name,
                threat_type="phishing",
                confidence=0.75,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                tags=["phishing"],
            ))
        return entries


class GenericCSVParser(FeedParser):
    """Parse a generic CSV feed with at least a 'url' or 'domain' column."""

    feed_name = "custom"

    def __init__(self, feed_name: str = "custom") -> None:
        self.feed_name = feed_name

    def parse(self, raw: str) -> list[ThreatFeedEntry]:
        entries: list[ThreatFeedEntry] = []
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            indicator = row.get("url") or row.get("domain") or row.get("indicator", "")
            if not indicator:
                continue
            entries.append(ThreatFeedEntry(
                indicator=indicator.strip(),
                indicator_type=row.get("type", "domain"),
                feed_name=self.feed_name,
                threat_type=row.get("threat_type", "unknown"),
                confidence=float(row.get("confidence", 0.5)),
                tags=[t.strip() for t in row.get("tags", "").split(",") if t.strip()],
            ))
        return entries


# ── Parser registry ──────────────────────────────────────────────────────────

PARSER_REGISTRY: dict[str, type[FeedParser]] = {
    "urlhaus": URLhausParser,
    "phishtank": PhishTankParser,
    "openphish": OpenPhishParser,
    "csv": GenericCSVParser,
}


# ── Feed Ingester ────────────────────────────────────────────────────────────


class FeedIngester:
    """Download and parse threat feeds into the local database."""

    def __init__(self, repo: ThreatIntelRepository) -> None:
        self._repo = repo
        self._settings = get_settings()

    async def ingest_feed(self, feed_url: str, parser_name: str = "csv") -> int:
        """
        Download a feed URL and ingest entries into the database.

        Returns:
            Number of entries ingested.
        """
        parser_cls = PARSER_REGISTRY.get(parser_name, GenericCSVParser)
        parser = parser_cls() if parser_name != "csv" else GenericCSVParser(feed_url.split("/")[-1])

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.get(feed_url)
                resp.raise_for_status()
                raw = resp.text
        except Exception as e:
            logger.error("feed_ingester.download_failed", url=feed_url, error=str(e))
            return 0

        entries = parser.parse(raw)
        if not entries:
            logger.warning("feed_ingester.no_entries", url=feed_url)
            return 0

        count = await self._repo.bulk_upsert(entries)
        logger.info(
            "feed_ingester.ingested",
            feed_url=feed_url,
            parser=parser_name,
            entries=count,
        )
        return count

    async def ingest_all_configured(self) -> dict[str, int]:
        """Ingest all feeds configured in settings."""
        feed_urls = self._settings.threat_feed_urls
        if not feed_urls.strip():
            return {}

        results: dict[str, int] = {}
        for url in feed_urls.split(","):
            url = url.strip()
            if not url:
                continue
            # Auto-detect parser from URL
            parser_name = "csv"
            if "urlhaus" in url.lower():
                parser_name = "urlhaus"
            elif "phishtank" in url.lower():
                parser_name = "phishtank"
            elif "openphish" in url.lower():
                parser_name = "openphish"

            count = await self.ingest_feed(url, parser_name)
            results[url] = count

        return results


# ── Threat Intelligence Service ──────────────────────────────────────────────


class ThreatIntelService:
    """Query local threat intelligence cache during analysis."""

    def __init__(self, repo: ThreatIntelRepository) -> None:
        self._repo = repo

    async def lookup(self, url: str) -> ThreatIntelResult:
        """
        Look up a URL against the local threat intelligence cache.

        Checks both the full domain and any URL-level matches.
        """
        try:
            domain = urlparse(url).netloc.lower()
        except Exception:
            domain = ""

        if not domain:
            return ThreatIntelResult()

        entries = await self._repo.lookup_domain(domain)

        if not entries:
            return ThreatIntelResult(
                signals=["No matches in threat intelligence feeds"]
            )

        # Aggregate results
        threat_types = list(set(e.threat_type for e in entries if e.threat_type))
        feed_names = list(set(e.feed_name for e in entries))
        highest_conf = max(e.confidence for e in entries) if entries else 0.0

        signals: list[str] = []
        for entry in entries[:5]:
            signals.append(
                f"[{entry.feed_name}] {entry.indicator} — {entry.threat_type} "
                f"(confidence: {entry.confidence:.2f})"
            )

        result = ThreatIntelResult(
            matches=entries,
            is_known_threat=highest_conf >= 0.5,
            highest_confidence=highest_conf,
            feed_count=len(feed_names),
            threat_types=threat_types,
            signals=signals,
        )

        logger.info(
            "threat_intel.lookup",
            domain=domain,
            matches=len(entries),
            is_known=result.is_known_threat,
            feeds=feed_names,
        )

        return result

    async def get_stats(self) -> dict[str, int]:
        """Get feed statistics."""
        return await self._repo.get_feed_stats()
