"""
Enterprise Mode – brand monitoring and continuous domain similarity scanning.

Enterprise features (requires enterprise_mode=True in settings):

1. Brand Monitor Setup
   - Register your brand with official domains, keywords, logo hashes
   - Configure alert thresholds and webhook notifications

2. Continuous Scanning
   - Periodically scan certificate transparency logs / new domain registrations
   - Check for domains similar to monitored brands
   - Run TrustLens analysis on suspicious discoveries

3. Alert Management
   - Generate alerts when impersonation is detected
   - Webhook notifications for real-time response
   - Alert dashboard with acknowledge/resolve workflow

Architecture:
    BrandMonitorService → (scan) → candidate URLs
    → AnalysisOrchestrator.analyze() → BrandMatch check
    → BrandAlert (if similarity > threshold) → Webhook notification
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Optional

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.db import BrandMonitorRepository
from trustlens.models import BrandAlert, BrandMonitor

logger = get_logger(__name__)


class BrandMonitorService:
    """
    Enterprise brand protection service.

    Manages brand monitors and generates alerts when impersonation is detected.
    The continuous scanning loop is designed to be run as a background task.
    """

    def __init__(self, repo: BrandMonitorRepository) -> None:
        self._repo = repo
        self._settings = get_settings()
        self._running = False

    async def create_monitor(
        self,
        brand_name: str,
        official_domains: list[str],
        keywords: list[str] | None = None,
        logo_hashes: list[str] | None = None,
        alert_threshold: float = 0.7,
        alert_webhook: str = "",
        scan_interval_hours: int = 24,
    ) -> BrandMonitor:
        """
        Register a brand for continuous monitoring.

        Args:
            brand_name: Name of the brand to protect.
            official_domains: List of known official domains.
            keywords: Brand-related keywords to watch for.
            logo_hashes: Perceptual hashes of official brand logos.
            alert_threshold: Similarity score above which to generate alerts.
            alert_webhook: URL to POST alert notifications.
            scan_interval_hours: How often to run scans.

        Returns:
            The created BrandMonitor.
        """
        if not self._settings.enterprise_mode:
            raise RuntimeError(
                "Enterprise mode is not enabled. "
                "Set TRUSTLENS_ENTERPRISE_MODE=true to enable."
            )

        monitor = BrandMonitor(
            brand_name=brand_name,
            official_domains=official_domains,
            keywords=keywords or [],
            logo_hashes=logo_hashes or [],
            alert_threshold=alert_threshold,
            alert_webhook=alert_webhook,
            scan_interval_hours=scan_interval_hours,
        )

        await self._repo.create_monitor(monitor)

        logger.info(
            "enterprise.monitor_created",
            monitor_id=monitor.id,
            brand=brand_name,
            domains=official_domains,
        )

        return monitor

    async def get_active_monitors(self) -> list[BrandMonitor]:
        """Get all active brand monitors."""
        return await self._repo.get_active_monitors()

    async def generate_alert(
        self,
        monitor: BrandMonitor,
        suspicious_url: str,
        similarity_score: float,
        detection_type: str = "domain",
        screenshot_path: Optional[str] = None,
    ) -> BrandAlert:
        """
        Generate a brand impersonation alert.

        Args:
            monitor: The brand monitor that triggered the alert.
            suspicious_url: The URL suspected of impersonation.
            similarity_score: How similar the URL is to the brand.
            detection_type: "domain", "visual", "content", or "logo".
            screenshot_path: Path to screenshot evidence.

        Returns:
            The created BrandAlert.
        """
        alert = BrandAlert(
            monitor_id=monitor.id,
            brand_name=monitor.brand_name,
            suspicious_url=suspicious_url,
            similarity_score=similarity_score,
            detection_type=detection_type,
            screenshot_path=screenshot_path,
        )

        await self._repo.create_alert(alert)

        logger.warning(
            "enterprise.brand_alert",
            alert_id=alert.id,
            brand=monitor.brand_name,
            url=suspicious_url,
            similarity=similarity_score,
            detection=detection_type,
        )

        # Fire webhook notification (async, non-blocking)
        if monitor.alert_webhook:
            asyncio.create_task(self._send_webhook(monitor.alert_webhook, alert))

        return alert

    async def get_alerts(
        self,
        monitor_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[BrandAlert]:
        """Get alerts, optionally filtered by monitor."""
        return await self._repo.get_alerts(monitor_id=monitor_id, limit=limit)

    async def check_analysis_for_alerts(
        self,
        url: str,
        brand_matches: list[Any],
        screenshot_path: Optional[str] = None,
    ) -> list[BrandAlert]:
        """
        Check if an analysis result should trigger enterprise brand alerts.

        Called by the orchestrator after analysis completes.  Compares
        brand_matches against all active monitors.

        Returns:
            List of generated alerts.
        """
        if not self._settings.enterprise_mode:
            return []

        monitors = await self.get_active_monitors()
        if not monitors:
            return []

        alerts: list[BrandAlert] = []

        for monitor in monitors:
            for match in brand_matches:
                # Check if this brand match corresponds to a monitored brand
                if not self._brand_names_match(monitor.brand_name, match.brand_name):
                    continue

                # Check if similarity exceeds alert threshold
                if match.similarity_score >= monitor.alert_threshold and not match.is_official:
                    alert = await self.generate_alert(
                        monitor=monitor,
                        suspicious_url=url,
                        similarity_score=match.similarity_score,
                        detection_type="domain" if match.domain_similarity > 0.5 else "content",
                        screenshot_path=screenshot_path,
                    )
                    alerts.append(alert)

        return alerts

    @staticmethod
    def _brand_names_match(monitor_brand: str, match_brand: str) -> bool:
        """Fuzzy brand name comparison."""
        return monitor_brand.lower().strip() == match_brand.lower().strip()

    async def _send_webhook(self, webhook_url: str, alert: BrandAlert) -> None:
        """Send alert notification to webhook (fire-and-forget)."""
        try:
            import httpx
            payload = {
                "event": "brand_impersonation_alert",
                "alert_id": alert.id,
                "brand": alert.brand_name,
                "suspicious_url": alert.suspicious_url,
                "similarity_score": alert.similarity_score,
                "detection_type": alert.detection_type,
                "timestamp": alert.created_at.isoformat(),
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(webhook_url, json=payload)
            logger.info("enterprise.webhook_sent", url=webhook_url, alert_id=alert.id)
        except Exception as e:
            logger.error("enterprise.webhook_failed", url=webhook_url, error=str(e))

    async def start_scanning_loop(self, orchestrator: Any = None) -> None:
        """
        Start the continuous brand monitoring scan loop.

        This is a long-running background task that periodically:
        1. Queries certificate transparency / new domain feeds
        2. Checks for domains similar to monitored brands
        3. Runs analysis on suspicious candidates

        NOTE: This is a stub — the actual CT log integration and domain
        feed polling require additional infrastructure (certstream, DNS
        zone file access, etc.).
        """
        if not self._settings.enterprise_mode:
            logger.info("enterprise.scanning_disabled")
            return

        self._running = True
        interval = self._settings.enterprise_brand_scan_interval * 3600  # hours → seconds

        logger.info(
            "enterprise.scanning_started",
            interval_hours=self._settings.enterprise_brand_scan_interval,
        )

        while self._running:
            try:
                monitors = await self.get_active_monitors()
                for monitor in monitors:
                    await self._scan_for_brand(monitor, orchestrator)
                    monitor.last_scan_at = datetime.now(timezone.utc)
            except Exception as e:
                logger.error("enterprise.scan_failed", error=str(e))

            await asyncio.sleep(interval)

    async def _scan_for_brand(self, monitor: BrandMonitor, orchestrator: Any) -> None:
        """
        Scan for potential impersonations of a monitored brand.

        Stub implementation — in production:
        1. Query certstream for new certificates mentioning brand keywords
        2. Check newly registered domains via WHOIS zone files
        3. Run TrustLens analysis on candidates
        """
        logger.debug(
            "enterprise.scanning_brand",
            brand=monitor.brand_name,
            keywords=monitor.keywords,
        )
        # TODO: Implement CT log streaming and domain feed integration
        # candidates = await self._get_candidates(monitor)
        # for url in candidates:
        #     analysis = await orchestrator.analyze(URLAnalysis(url=url))
        #     await self.check_analysis_for_alerts(url, analysis.brand_matches)

    def stop(self) -> None:
        """Stop the scanning loop."""
        self._running = False
        logger.info("enterprise.scanning_stopped")
