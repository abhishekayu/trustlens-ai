"""
Observability Module – structured audit logging, security event tracking,
and suspicious activity detection.

Components:
    1. AuditLogger       – persistent security audit trail
    2. ActivityMonitor    – real-time suspicious activity detection
    3. MetricsCollector   – in-memory counters for health/status endpoints

Design:
    All events flow through AuditLogger.emit() which:
    - Writes to the audit_log DB table
    - Forwards to structlog for JSON output
    - Feeds the ActivityMonitor for anomaly detection
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Optional

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.db import AuditLogRepository
from trustlens.models import AuditEvent

logger = get_logger(__name__)


# ── Event Types (constants for consistency) ──────────────────────────────────

class EventTypes:
    """Standardized audit event type constants."""

    # Analysis lifecycle
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_FAILED = "analysis.failed"

    # API access
    API_REQUEST = "api.request"
    API_RATE_LIMITED = "api.rate_limited"
    API_UNAUTHORIZED = "api.unauthorized"

    # API key management
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"

    # Community reports
    COMMUNITY_REPORT = "community.report_submitted"

    # Threat intelligence
    THREAT_FEED_INGESTED = "threat_intel.feed_ingested"
    THREAT_MATCH_FOUND = "threat_intel.match_found"

    # Security events
    SSRF_BLOCKED = "security.ssrf_blocked"
    INJECTION_DETECTED = "security.injection_detected"
    DOMAIN_DENIED = "security.domain_denied"

    # Enterprise
    BRAND_ALERT = "enterprise.brand_alert"
    BRAND_MONITOR_CREATED = "enterprise.monitor_created"

    # System
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    DB_ERROR = "system.db_error"


# ── Audit Logger ─────────────────────────────────────────────────────────────


class AuditLogger:
    """
    Persistent security audit trail.

    All security-relevant events should flow through this logger.
    Events are stored in the database AND forwarded to structured logging.
    """

    def __init__(self, repo: Optional[AuditLogRepository] = None) -> None:
        self._repo = repo
        self._monitor = ActivityMonitor()
        self._metrics = MetricsCollector()
        self._settings = get_settings()

    def set_repo(self, repo: AuditLogRepository) -> None:
        """Set the repo after construction (for deferred init)."""
        self._repo = repo

    async def emit(
        self,
        event_type: str,
        actor: str = "",
        resource: str = "",
        action: str = "",
        outcome: str = "success",
        metadata: dict[str, Any] | None = None,
        ip_address: str = "",
        user_agent: str = "",
    ) -> AuditEvent:
        """
        Record an audit event.

        This is the single entry point for all audit events.
        """
        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            resource=resource,
            action=action,
            outcome=outcome,
            metadata=metadata or {},
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Always log to structlog
        logger.info(
            "audit",
            event_type=event_type,
            actor=actor,
            resource=resource,
            action=action,
            outcome=outcome,
            ip=ip_address,
        )

        # Persist to database (if available and enabled)
        if self._repo and self._settings.audit_log_enabled:
            try:
                await self._repo.log(event)
            except Exception as e:
                logger.error("audit.persist_failed", error=str(e))

        # Feed activity monitor
        self._monitor.record(event_type, actor, ip_address)

        # Update metrics
        self._metrics.increment(event_type)

        return event

    async def query(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query historical audit events."""
        if not self._repo:
            return []
        return await self._repo.query(event_type=event_type, actor=actor, limit=limit)

    @property
    def monitor(self) -> ActivityMonitor:
        return self._monitor

    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics


# ── Activity Monitor ─────────────────────────────────────────────────────────


class ActivityMonitor:
    """
    Real-time suspicious activity detection via sliding-window analysis.

    Detects:
    - High-frequency requests from a single IP (DDoS / abuse)
    - Burst of failed auth attempts (credential stuffing)
    - Spike in SSRF/injection events (active attack)
    - Unusual analysis patterns (scanning)
    """

    def __init__(self, window_seconds: int = 3600) -> None:
        self._window = window_seconds
        # Per-IP event deques: ip -> deque of (timestamp, event_type)
        self._ip_events: dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        # Per-type counters: event_type -> deque of timestamps
        self._type_events: dict[str, deque] = defaultdict(lambda: deque(maxlen=50000))
        self._settings = get_settings()

    def record(self, event_type: str, actor: str, ip_address: str) -> None:
        """Record an event for monitoring."""
        now = time.time()
        if ip_address:
            self._ip_events[ip_address].append((now, event_type))
        if actor:
            self._ip_events[actor].append((now, event_type))
        self._type_events[event_type].append(now)

    def check_suspicious(self, ip_address: str = "", actor: str = "") -> list[dict[str, Any]]:
        """
        Check for suspicious activity patterns.

        Returns:
            List of suspicious activity alerts.
        """
        alerts: list[dict[str, Any]] = []
        now = time.time()
        cutoff = now - self._window
        threshold = self._settings.suspicious_activity_threshold

        # Check per-IP/actor
        for identifier in [ip_address, actor]:
            if not identifier:
                continue
            events = self._ip_events.get(identifier)
            if not events:
                continue

            recent = [(ts, evt) for ts, evt in events if ts > cutoff]
            if len(recent) >= threshold:
                alerts.append({
                    "type": "high_frequency",
                    "identifier": identifier,
                    "count": len(recent),
                    "threshold": threshold,
                    "window_seconds": self._window,
                    "message": f"High-frequency activity: {len(recent)} events in {self._window}s",
                })

            # Check for auth failures
            auth_failures = [e for ts, e in recent if e in (
                EventTypes.API_UNAUTHORIZED, EventTypes.API_RATE_LIMITED
            )]
            if len(auth_failures) >= 10:
                alerts.append({
                    "type": "auth_brute_force",
                    "identifier": identifier,
                    "count": len(auth_failures),
                    "message": f"Possible brute-force: {len(auth_failures)} auth failures",
                })

            # Check for security events
            security_events = [e for ts, e in recent if e in (
                EventTypes.SSRF_BLOCKED, EventTypes.INJECTION_DETECTED
            )]
            if len(security_events) >= 5:
                alerts.append({
                    "type": "active_attack",
                    "identifier": identifier,
                    "count": len(security_events),
                    "message": f"Possible active attack: {len(security_events)} security events",
                })

        return alerts

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of monitored activity."""
        now = time.time()
        cutoff = now - self._window
        summary: dict[str, Any] = {
            "window_seconds": self._window,
            "active_ips": 0,
            "events_per_type": {},
        }

        active_ips = set()
        for ip, events in self._ip_events.items():
            if any(ts > cutoff for ts, _ in events):
                active_ips.add(ip)
        summary["active_ips"] = len(active_ips)

        for evt_type, timestamps in self._type_events.items():
            recent = sum(1 for ts in timestamps if ts > cutoff)
            if recent > 0:
                summary["events_per_type"][evt_type] = recent

        return summary


# ── Metrics Collector ────────────────────────────────────────────────────────


class MetricsCollector:
    """
    In-memory metrics for health/status endpoints.

    Lightweight alternative to Prometheus for self-hosted deployments.
    """

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._start_time = time.time()

    def increment(self, metric: str, value: int = 1) -> None:
        self._counters[metric] += value

    def get(self, metric: str) -> int:
        return self._counters.get(metric, 0)

    def get_all(self) -> dict[str, int]:
        return dict(self._counters)

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._start_time

    def get_health_metrics(self) -> dict[str, Any]:
        """Metrics suitable for health/status endpoint."""
        return {
            "uptime_seconds": round(self.uptime_seconds, 1),
            "total_analyses": self._counters.get(EventTypes.ANALYSIS_COMPLETED, 0),
            "failed_analyses": self._counters.get(EventTypes.ANALYSIS_FAILED, 0),
            "api_requests": self._counters.get(EventTypes.API_REQUEST, 0),
            "rate_limited": self._counters.get(EventTypes.API_RATE_LIMITED, 0),
            "security_events": (
                self._counters.get(EventTypes.SSRF_BLOCKED, 0)
                + self._counters.get(EventTypes.INJECTION_DETECTED, 0)
                + self._counters.get(EventTypes.DOMAIN_DENIED, 0)
            ),
            "threat_matches": self._counters.get(EventTypes.THREAT_MATCH_FOUND, 0),
            "community_reports": self._counters.get(EventTypes.COMMUNITY_REPORT, 0),
        }


# ── Module-level singleton ──────────────────────────────────────────────────

_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger singleton."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def set_audit_logger(audit: AuditLogger) -> None:
    """Set the global audit logger (for dependency injection)."""
    global _audit_logger
    _audit_logger = audit
