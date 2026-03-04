"""
Database layer – async SQLite via aiosqlite, abstracted for future PostgreSQL swap.

Uses a thin repository pattern so the rest of the app never touches raw SQL.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from trustlens.core.logging import get_logger
from trustlens.models import (
    AnalysisStatus,
    APIKeyRecord,
    APITier,
    AuditEvent,
    BrandAlert,
    BrandMonitor,
    CommunityConsensus,
    CommunityReport,
    ThreatFeedEntry,
    URLAnalysis,
)

logger = get_logger(__name__)

_DB_PATH: str = "trustlens.db"


# ── Schema ───────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id            TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    submitted_at  TEXT NOT NULL,
    completed_at  TEXT,
    result_json   TEXT,
    error         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_analyses_status ON analyses(status);
CREATE INDEX IF NOT EXISTS idx_analyses_url ON analyses(url);
CREATE INDEX IF NOT EXISTS idx_analyses_submitted ON analyses(submitted_at);

CREATE TABLE IF NOT EXISTS brand_registry (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    brand_name    TEXT NOT NULL UNIQUE,
    domains       TEXT NOT NULL,           -- JSON array of official domains
    keywords      TEXT NOT NULL DEFAULT '[]',
    logo_hash     TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Community Reports ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS community_reports (
    id            TEXT PRIMARY KEY,
    url           TEXT NOT NULL,
    domain        TEXT NOT NULL DEFAULT '',
    reporter_id   TEXT NOT NULL DEFAULT '',
    report_type   TEXT NOT NULL DEFAULT 'phishing',
    description   TEXT NOT NULL DEFAULT '',
    evidence_urls TEXT NOT NULL DEFAULT '[]',
    submitted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    verified      INTEGER NOT NULL DEFAULT 0,
    trust_weight  REAL NOT NULL DEFAULT 1.0
);

CREATE INDEX IF NOT EXISTS idx_community_reports_url ON community_reports(url);
CREATE INDEX IF NOT EXISTS idx_community_reports_domain ON community_reports(domain);
CREATE INDEX IF NOT EXISTS idx_community_reports_submitted ON community_reports(submitted_at);

-- ── API Keys ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash      TEXT PRIMARY KEY,
    owner         TEXT NOT NULL DEFAULT '',
    tier          TEXT NOT NULL DEFAULT 'free',
    rate_limit    INTEGER NOT NULL DEFAULT 30,
    rate_window   INTEGER NOT NULL DEFAULT 60,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT,
    scopes        TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner);

-- ── Threat Intelligence ────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS threat_entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator     TEXT NOT NULL,
    indicator_type TEXT NOT NULL DEFAULT 'domain',
    feed_name     TEXT NOT NULL DEFAULT '',
    threat_type   TEXT NOT NULL DEFAULT '',
    confidence    REAL NOT NULL DEFAULT 0.0,
    first_seen    TEXT,
    last_seen     TEXT,
    tags          TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_threat_entries_indicator ON threat_entries(indicator);
CREATE INDEX IF NOT EXISTS idx_threat_entries_feed ON threat_entries(feed_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_entries_unique
    ON threat_entries(indicator, feed_name);

-- ── Screenshot Hashes ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS screenshot_hashes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    brand_name    TEXT NOT NULL DEFAULT '',
    phash         TEXT NOT NULL DEFAULT '',
    dhash         TEXT NOT NULL DEFAULT '',
    source_url    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_screenshot_hashes_brand ON screenshot_hashes(brand_name);

-- ── Audit Log ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS audit_log (
    id            TEXT PRIMARY KEY,
    timestamp     TEXT NOT NULL DEFAULT (datetime('now')),
    event_type    TEXT NOT NULL,
    actor         TEXT NOT NULL DEFAULT '',
    resource      TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL DEFAULT '',
    outcome       TEXT NOT NULL DEFAULT 'success',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    ip_address    TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);

-- ── Enterprise Brand Monitors ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS brand_monitors (
    id                  TEXT PRIMARY KEY,
    brand_name          TEXT NOT NULL,
    official_domains    TEXT NOT NULL DEFAULT '[]',
    keywords            TEXT NOT NULL DEFAULT '[]',
    logo_hashes         TEXT NOT NULL DEFAULT '[]',
    monitoring_enabled  INTEGER NOT NULL DEFAULT 1,
    scan_interval_hours INTEGER NOT NULL DEFAULT 24,
    alert_threshold     REAL NOT NULL DEFAULT 0.7,
    alert_webhook       TEXT NOT NULL DEFAULT '',
    last_scan_at        TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS brand_alerts (
    id              TEXT PRIMARY KEY,
    monitor_id      TEXT NOT NULL,
    brand_name      TEXT NOT NULL,
    suspicious_url  TEXT NOT NULL,
    similarity_score REAL NOT NULL DEFAULT 0.0,
    detection_type  TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    acknowledged    INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (monitor_id) REFERENCES brand_monitors(id)
);

CREATE INDEX IF NOT EXISTS idx_brand_alerts_monitor ON brand_alerts(monitor_id);
CREATE INDEX IF NOT EXISTS idx_brand_alerts_created ON brand_alerts(created_at);
"""


# ── Connection management ────────────────────────────────────────────────────


class Database:
    """Async database wrapper with connection pooling placeholder."""

    def __init__(self, db_url: str = "") -> None:
        # Parse sqlite path from URL like "sqlite+aiosqlite:///./trustlens.db"
        if ":///" in db_url:
            path = db_url.split(":///", 1)[1]
            self._db_path = path if path else _DB_PATH
        else:
            self._db_path = db_url or _DB_PATH
        self._connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        logger.info("database.connecting", path=self._db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = await aiosqlite.connect(self._db_path)
        self._connection.row_factory = aiosqlite.Row
        await self._connection.executescript(_SCHEMA)
        await self._connection.commit()
        logger.info("database.connected")

    async def disconnect(self) -> None:
        if self._connection:
            await self._connection.close()
            logger.info("database.disconnected")

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise RuntimeError("Database not connected – call await db.connect() first")
        return self._connection


# ── Repository ───────────────────────────────────────────────────────────────


class AnalysisRepository:
    """Data-access object for URL analyses."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create(self, analysis: URLAnalysis) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO analyses (id, url, status, submitted_at, result_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                analysis.id,
                analysis.url,
                analysis.status.value,
                analysis.submitted_at.isoformat(),
                None,
            ),
        )
        await self._db.conn.commit()

    async def update_status(
        self, analysis_id: str, status: AnalysisStatus, error: Optional[str] = None
    ) -> None:
        await self._db.conn.execute(
            """
            UPDATE analyses SET status = ?, error = ?, updated_at = datetime('now')
            WHERE id = ?
            """,
            (status.value, error, analysis_id),
        )
        await self._db.conn.commit()

    async def save_result(self, analysis: URLAnalysis) -> None:
        result_json = analysis.model_dump_json(exclude={"id", "url", "submitted_at"})
        completed = analysis.completed_at.isoformat() if analysis.completed_at else None
        await self._db.conn.execute(
            """
            UPDATE analyses
            SET status = ?, completed_at = ?, result_json = ?, error = ?,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (
                analysis.status.value,
                completed,
                result_json,
                analysis.error,
                analysis.id,
            ),
        )
        await self._db.conn.commit()

    async def get_by_id(self, analysis_id: str) -> Optional[URLAnalysis]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_analysis(row)

    async def list_recent(self, limit: int = 20, offset: int = 0) -> list[URLAnalysis]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM analyses ORDER BY submitted_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        rows = await cursor.fetchall()
        return [self._row_to_analysis(r) for r in rows]

    @staticmethod
    def _row_to_analysis(row: aiosqlite.Row) -> URLAnalysis:
        data: dict = dict(row)  # type: ignore[arg-type]
        if data.get("result_json"):
            result = json.loads(data["result_json"])
            result["id"] = data["id"]
            result["url"] = data["url"]
            result["submitted_at"] = data["submitted_at"]
            return URLAnalysis.model_validate(result)
        return URLAnalysis(
            id=data["id"],
            url=data["url"],
            status=AnalysisStatus(data["status"]),
            submitted_at=datetime.fromisoformat(data["submitted_at"]),
            error=data.get("error"),
        )


# ── Brand Registry ──────────────────────────────────────────────────────────


class BrandRepository:
    """Data-access for the known-brand registry."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def get_all(self) -> list[dict]:
        cursor = await self._db.conn.execute("SELECT * FROM brand_registry")
        rows = await cursor.fetchall()
        results = []
        for row in rows:
            d = dict(row)  # type: ignore[arg-type]
            d["domains"] = json.loads(d["domains"])
            d["keywords"] = json.loads(d["keywords"])
            results.append(d)
        return results

    async def upsert(self, brand_name: str, domains: list[str], keywords: list[str] = []) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO brand_registry (brand_name, domains, keywords)
            VALUES (?, ?, ?)
            ON CONFLICT(brand_name) DO UPDATE SET
                domains = excluded.domains,
                keywords = excluded.keywords
            """,
            (brand_name, json.dumps(domains), json.dumps(keywords)),
        )
        await self._db.conn.commit()

    async def seed_defaults(self) -> None:
        """Seed the registry with well-known brands for demo/testing."""
        defaults = [
            ("Google", ["google.com", "googleapis.com", "gstatic.com"], ["google", "gmail"]),
            ("Microsoft", ["microsoft.com", "live.com", "outlook.com", "office.com"], ["microsoft", "outlook", "onedrive"]),
            ("Apple", ["apple.com", "icloud.com"], ["apple", "icloud"]),
            ("Amazon", ["amazon.com", "aws.amazon.com"], ["amazon", "aws"]),
            ("PayPal", ["paypal.com"], ["paypal"]),
            ("Facebook", ["facebook.com", "fb.com", "meta.com"], ["facebook", "meta"]),
            ("Netflix", ["netflix.com"], ["netflix"]),
            ("Bank of America", ["bankofamerica.com"], ["bankofamerica", "bofa"]),
            ("Chase", ["chase.com", "jpmorganchase.com"], ["chase", "jpmorgan"]),
            ("Wells Fargo", ["wellsfargo.com"], ["wellsfargo"]),
            ("DHL", ["dhl.com"], ["dhl"]),
            ("LinkedIn", ["linkedin.com"], ["linkedin"]),
            ("Dropbox", ["dropbox.com"], ["dropbox"]),
        ]
        for name, domains, keywords in defaults:
            await self.upsert(name, domains, keywords)
        logger.info("brand_registry.seeded", count=len(defaults))


# ── Community Reporting ──────────────────────────────────────────────────────


class CommunityReportRepository:
    """Data-access for community-submitted scam/phishing reports."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def submit(self, report: CommunityReport) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO community_reports
                (id, url, domain, reporter_id, report_type, description,
                 evidence_urls, submitted_at, verified, trust_weight)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.id,
                report.url,
                self._extract_domain(report.url),
                report.reporter_id,
                report.report_type,
                report.description,
                json.dumps(report.evidence_urls),
                report.submitted_at.isoformat(),
                int(report.verified),
                report.trust_weight,
            ),
        )
        await self._db.conn.commit()

    async def get_by_url(self, url: str, limit: int = 50) -> list[CommunityReport]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM community_reports WHERE url = ? ORDER BY submitted_at DESC LIMIT ?",
            (url, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_report(r) for r in rows]

    async def get_by_domain(self, domain: str, limit: int = 100) -> list[CommunityReport]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM community_reports WHERE domain = ? ORDER BY submitted_at DESC LIMIT ?",
            (domain, limit),
        )
        rows = await cursor.fetchall()
        return [self._row_to_report(r) for r in rows]

    async def get_consensus(self, url: str, domain: str) -> CommunityConsensus:
        """Aggregate community reports into a consensus score."""
        # Get reports for this URL or domain
        url_reports = await self.get_by_url(url)
        domain_reports = await self.get_by_domain(domain)

        # Deduplicate by report id
        seen_ids: set[str] = set()
        all_reports: list[CommunityReport] = []
        for r in url_reports + domain_reports:
            if r.id not in seen_ids:
                seen_ids.add(r.id)
                all_reports.append(r)

        if not all_reports:
            return CommunityConsensus(url_or_domain=domain)

        phishing = sum(1 for r in all_reports if r.report_type == "phishing")
        safe = sum(1 for r in all_reports if r.report_type == "safe")
        scam = sum(1 for r in all_reports if r.report_type == "scam")
        total = len(all_reports)

        # Weighted risk score: more phishing/scam reports → lower score
        danger_weight = sum(
            r.trust_weight for r in all_reports if r.report_type in ("phishing", "scam", "malware")
        )
        safe_weight = sum(r.trust_weight for r in all_reports if r.report_type == "safe")
        total_weight = danger_weight + safe_weight

        if total_weight > 0:
            crowd_risk = max(0.0, min(100.0, 50.0 - (danger_weight - safe_weight) / total_weight * 50.0))
        else:
            crowd_risk = 50.0

        # Confidence increases with report count and diversity
        import math
        confidence = min(0.95, 1.0 - 1.0 / (1.0 + math.log1p(total)))

        last_report = max(all_reports, key=lambda r: r.submitted_at)

        return CommunityConsensus(
            url_or_domain=domain,
            total_reports=total,
            phishing_reports=phishing,
            safe_reports=safe,
            scam_reports=scam,
            crowd_risk_score=round(crowd_risk, 1),
            consensus_confidence=round(confidence, 3),
            last_report_at=last_report.submitted_at,
        )

    @staticmethod
    def _extract_domain(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url).netloc.lower()
        except Exception:
            return ""

    @staticmethod
    def _row_to_report(row: aiosqlite.Row) -> CommunityReport:
        d = dict(row)  # type: ignore[arg-type]
        return CommunityReport(
            id=d["id"],
            url=d["url"],
            reporter_id=d.get("reporter_id", ""),
            report_type=d.get("report_type", "phishing"),
            description=d.get("description", ""),
            evidence_urls=json.loads(d.get("evidence_urls", "[]")),
            submitted_at=datetime.fromisoformat(d["submitted_at"]),
            verified=bool(d.get("verified", 0)),
            trust_weight=float(d.get("trust_weight", 1.0)),
        )


# ── API Key Repository ──────────────────────────────────────────────────────


class APIKeyRepository:
    """Data-access for API key management."""

    def __init__(self, db: Database) -> None:
        self._db = db

    @staticmethod
    def generate_key() -> tuple[str, str]:
        """Generate a new API key and return (raw_key, key_hash)."""
        raw = f"tl_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        return raw, key_hash

    async def create(self, key_hash: str, owner: str = "", tier: APITier = APITier.FREE,
                     scopes: list[str] | None = None) -> APIKeyRecord:
        tier_limits = {APITier.FREE: (30, 60), APITier.PRO: (200, 60), APITier.ENTERPRISE: (2000, 60)}
        rate_limit, rate_window = tier_limits.get(tier, (30, 60))
        record = APIKeyRecord(
            key_hash=key_hash, owner=owner, tier=tier,
            rate_limit=rate_limit, rate_window=rate_window,
            scopes=scopes or ["analyze", "report"],
        )
        await self._db.conn.execute(
            """
            INSERT INTO api_keys (key_hash, owner, tier, rate_limit, rate_window, enabled, scopes)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            """,
            (key_hash, owner, tier.value, rate_limit, rate_window, json.dumps(record.scopes)),
        )
        await self._db.conn.commit()
        return record

    async def get_by_hash(self, key_hash: str) -> Optional[APIKeyRecord]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        d = dict(row)  # type: ignore[arg-type]
        return APIKeyRecord(
            key_hash=d["key_hash"],
            owner=d.get("owner", ""),
            tier=APITier(d.get("tier", "free")),
            rate_limit=d.get("rate_limit", 30),
            rate_window=d.get("rate_window", 60),
            enabled=bool(d.get("enabled", 1)),
            scopes=json.loads(d.get("scopes", "[]")),
        )

    async def revoke(self, key_hash: str) -> None:
        await self._db.conn.execute(
            "UPDATE api_keys SET enabled = 0 WHERE key_hash = ?", (key_hash,)
        )
        await self._db.conn.commit()


# ── Threat Intelligence Repository ──────────────────────────────────────────


class ThreatIntelRepository:
    """Data-access for threat intelligence feed entries."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def upsert_entry(self, entry: ThreatFeedEntry) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO threat_entries
                (indicator, indicator_type, feed_name, threat_type, confidence,
                 first_seen, last_seen, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator, feed_name) DO UPDATE SET
                threat_type = excluded.threat_type,
                confidence = excluded.confidence,
                last_seen = excluded.last_seen,
                tags = excluded.tags
            """,
            (
                entry.indicator,
                entry.indicator_type,
                entry.feed_name,
                entry.threat_type,
                entry.confidence,
                entry.first_seen.isoformat() if entry.first_seen else None,
                entry.last_seen.isoformat() if entry.last_seen else None,
                json.dumps(entry.tags),
            ),
        )
        await self._db.conn.commit()

    async def bulk_upsert(self, entries: list[ThreatFeedEntry]) -> int:
        """Bulk insert/update threat entries. Returns count of processed entries."""
        count = 0
        for entry in entries:
            await self.upsert_entry(entry)
            count += 1
        return count

    async def lookup(self, indicator: str) -> list[ThreatFeedEntry]:
        """Look up an indicator across all feeds."""
        cursor = await self._db.conn.execute(
            "SELECT * FROM threat_entries WHERE indicator = ?", (indicator,)
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(r) for r in rows]

    async def lookup_domain(self, domain: str) -> list[ThreatFeedEntry]:
        """Look up a domain and all URL-type entries containing it."""
        cursor = await self._db.conn.execute(
            """
            SELECT * FROM threat_entries
            WHERE indicator = ? OR (indicator_type = 'url' AND indicator LIKE ?)
            """,
            (domain, f"%{domain}%"),
        )
        rows = await cursor.fetchall()
        return [self._row_to_entry(r) for r in rows]

    async def get_feed_stats(self) -> dict[str, int]:
        cursor = await self._db.conn.execute(
            "SELECT feed_name, COUNT(*) as cnt FROM threat_entries GROUP BY feed_name"
        )
        rows = await cursor.fetchall()
        return {dict(r)["feed_name"]: dict(r)["cnt"] for r in rows}  # type: ignore[arg-type]

    @staticmethod
    def _row_to_entry(row: aiosqlite.Row) -> ThreatFeedEntry:
        d = dict(row)  # type: ignore[arg-type]
        return ThreatFeedEntry(
            indicator=d["indicator"],
            indicator_type=d.get("indicator_type", "domain"),
            feed_name=d.get("feed_name", ""),
            threat_type=d.get("threat_type", ""),
            confidence=float(d.get("confidence", 0.0)),
            first_seen=datetime.fromisoformat(d["first_seen"]) if d.get("first_seen") else None,
            last_seen=datetime.fromisoformat(d["last_seen"]) if d.get("last_seen") else None,
            tags=json.loads(d.get("tags", "[]")),
        )


# ── Screenshot Hash Repository ──────────────────────────────────────────────


class ScreenshotHashRepository:
    """Data-access for perceptual hash storage (brand screenshot baselines)."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def add_hash(self, brand_name: str, phash: str, dhash: str, source_url: str = "") -> None:
        await self._db.conn.execute(
            """
            INSERT INTO screenshot_hashes (brand_name, phash, dhash, source_url)
            VALUES (?, ?, ?, ?)
            """,
            (brand_name, phash, dhash, source_url),
        )
        await self._db.conn.commit()

    async def get_all_hashes(self) -> list[dict]:
        cursor = await self._db.conn.execute("SELECT * FROM screenshot_hashes")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]  # type: ignore[arg-type]

    async def get_by_brand(self, brand_name: str) -> list[dict]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM screenshot_hashes WHERE brand_name = ?", (brand_name,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]  # type: ignore[arg-type]


# ── Audit Log Repository ────────────────────────────────────────────────────


class AuditLogRepository:
    """Data-access for security audit events."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def log(self, event: AuditEvent) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO audit_log
                (id, timestamp, event_type, actor, resource, action,
                 outcome, metadata_json, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.timestamp.isoformat(),
                event.event_type,
                event.actor,
                event.resource,
                event.action,
                event.outcome,
                json.dumps(event.metadata),
                event.ip_address,
                event.user_agent,
            ),
        )
        await self._db.conn.commit()

    async def query(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        conditions = []
        params: list = []
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if actor:
            conditions.append("actor = ?")
            params.append(actor)

        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        cursor = await self._db.conn.execute(
            f"SELECT * FROM audit_log WHERE {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        rows = await cursor.fetchall()
        return [self._row_to_event(r) for r in rows]

    async def count_recent(self, event_type: str, actor: str, window_seconds: int = 3600) -> int:
        """Count events of a given type by actor in a time window. Useful for abuse detection."""
        cutoff = datetime.now(timezone.utc).isoformat()
        cursor = await self._db.conn.execute(
            """
            SELECT COUNT(*) as cnt FROM audit_log
            WHERE event_type = ? AND actor = ?
              AND timestamp >= datetime(?, '-' || ? || ' seconds')
            """,
            (event_type, actor, cutoff, window_seconds),
        )
        row = await cursor.fetchone()
        return dict(row)["cnt"] if row else 0  # type: ignore[arg-type]

    @staticmethod
    def _row_to_event(row: aiosqlite.Row) -> AuditEvent:
        d = dict(row)  # type: ignore[arg-type]
        return AuditEvent(
            id=d["id"],
            timestamp=datetime.fromisoformat(d["timestamp"]),
            event_type=d["event_type"],
            actor=d.get("actor", ""),
            resource=d.get("resource", ""),
            action=d.get("action", ""),
            outcome=d.get("outcome", "success"),
            metadata=json.loads(d.get("metadata_json", "{}")),
            ip_address=d.get("ip_address", ""),
            user_agent=d.get("user_agent", ""),
        )


# ── Enterprise Brand Monitor Repository ─────────────────────────────────────


class BrandMonitorRepository:
    """Data-access for enterprise brand monitoring configs and alerts."""

    def __init__(self, db: Database) -> None:
        self._db = db

    async def create_monitor(self, monitor: BrandMonitor) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO brand_monitors
                (id, brand_name, official_domains, keywords, logo_hashes,
                 monitoring_enabled, scan_interval_hours, alert_threshold,
                 alert_webhook, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                monitor.id,
                monitor.brand_name,
                json.dumps(monitor.official_domains),
                json.dumps(monitor.keywords),
                json.dumps(monitor.logo_hashes),
                int(monitor.monitoring_enabled),
                monitor.scan_interval_hours,
                monitor.alert_threshold,
                monitor.alert_webhook,
                monitor.created_at.isoformat(),
            ),
        )
        await self._db.conn.commit()

    async def get_active_monitors(self) -> list[BrandMonitor]:
        cursor = await self._db.conn.execute(
            "SELECT * FROM brand_monitors WHERE monitoring_enabled = 1"
        )
        rows = await cursor.fetchall()
        return [self._row_to_monitor(r) for r in rows]

    async def create_alert(self, alert: BrandAlert) -> None:
        await self._db.conn.execute(
            """
            INSERT INTO brand_alerts
                (id, monitor_id, brand_name, suspicious_url, similarity_score,
                 detection_type, screenshot_path, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert.id,
                alert.monitor_id,
                alert.brand_name,
                alert.suspicious_url,
                alert.similarity_score,
                alert.detection_type,
                alert.screenshot_path,
                alert.created_at.isoformat(),
            ),
        )
        await self._db.conn.commit()

    async def get_alerts(self, monitor_id: Optional[str] = None, limit: int = 50) -> list[BrandAlert]:
        if monitor_id:
            cursor = await self._db.conn.execute(
                "SELECT * FROM brand_alerts WHERE monitor_id = ? ORDER BY created_at DESC LIMIT ?",
                (monitor_id, limit),
            )
        else:
            cursor = await self._db.conn.execute(
                "SELECT * FROM brand_alerts ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        rows = await cursor.fetchall()
        return [self._row_to_alert(r) for r in rows]

    @staticmethod
    def _row_to_monitor(row: aiosqlite.Row) -> BrandMonitor:
        d = dict(row)  # type: ignore[arg-type]
        return BrandMonitor(
            id=d["id"],
            brand_name=d["brand_name"],
            official_domains=json.loads(d.get("official_domains", "[]")),
            keywords=json.loads(d.get("keywords", "[]")),
            logo_hashes=json.loads(d.get("logo_hashes", "[]")),
            monitoring_enabled=bool(d.get("monitoring_enabled", 1)),
            scan_interval_hours=d.get("scan_interval_hours", 24),
            alert_threshold=float(d.get("alert_threshold", 0.7)),
            alert_webhook=d.get("alert_webhook", ""),
            last_scan_at=(
                datetime.fromisoformat(d["last_scan_at"]) if d.get("last_scan_at") else None
            ),
            created_at=datetime.fromisoformat(d["created_at"]),
        )

    @staticmethod
    def _row_to_alert(row: aiosqlite.Row) -> BrandAlert:
        d = dict(row)  # type: ignore[arg-type]
        return BrandAlert(
            id=d["id"],
            monitor_id=d["monitor_id"],
            brand_name=d["brand_name"],
            suspicious_url=d["suspicious_url"],
            similarity_score=float(d.get("similarity_score", 0.0)),
            detection_type=d.get("detection_type", ""),
            screenshot_path=d.get("screenshot_path"),
            created_at=datetime.fromisoformat(d["created_at"]),
            acknowledged=bool(d.get("acknowledged", 0)),
        )