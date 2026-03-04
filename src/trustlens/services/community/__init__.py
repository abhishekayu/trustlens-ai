"""
Community Reporting Service – crowd-sourced URL trust signals.

Allows users to submit phishing/scam/safe reports for URLs.  Reports are
aggregated into a consensus score weighted by reporter reputation.

Features:
    - Submit reports with evidence
    - Aggregate crowd consensus per URL/domain
    - Reporter reputation weighting (prevent spam/manipulation)
    - Rate limiting per reporter (via audit log integration)
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.db import CommunityReportRepository
from trustlens.models import CommunityConsensus, CommunityReport

logger = get_logger(__name__)

VALID_REPORT_TYPES = {"phishing", "scam", "malware", "safe", "spam", "other"}


class CommunityReportingService:
    """Manage community-submitted URL reports and consensus scoring."""

    def __init__(self, report_repo: CommunityReportRepository) -> None:
        self._repo = report_repo
        self._settings = get_settings()

    async def submit_report(
        self,
        url: str,
        report_type: str,
        reporter_ip: str = "",
        description: str = "",
        evidence_urls: list[str] | None = None,
    ) -> CommunityReport:
        """
        Submit a new community report.

        Args:
            url: The URL being reported.
            report_type: One of VALID_REPORT_TYPES.
            reporter_ip: IP of the reporter (hashed for privacy).
            description: Free-text description.
            evidence_urls: Supporting evidence URLs.

        Returns:
            The created CommunityReport.

        Raises:
            ValueError: If report_type is invalid.
        """
        if report_type not in VALID_REPORT_TYPES:
            raise ValueError(
                f"Invalid report type '{report_type}'. "
                f"Must be one of: {', '.join(sorted(VALID_REPORT_TYPES))}"
            )

        # Hash reporter IP for privacy
        reporter_id = hashlib.sha256(reporter_ip.encode()).hexdigest()[:16] if reporter_ip else ""

        # Calculate trust weight based on reporter history
        trust_weight = await self._compute_reporter_trust(reporter_id)

        if trust_weight < self._settings.community_report_min_trust:
            logger.warning(
                "community.low_trust_reporter",
                reporter_id=reporter_id,
                trust_weight=trust_weight,
            )
            # Still accept but with reduced weight
            trust_weight = max(0.1, trust_weight)

        report = CommunityReport(
            url=url,
            reporter_id=reporter_id,
            report_type=report_type,
            description=description[:2000],  # Cap length
            evidence_urls=(evidence_urls or [])[:10],  # Cap count
            trust_weight=trust_weight,
        )

        await self._repo.submit(report)

        logger.info(
            "community.report_submitted",
            report_id=report.id,
            url=url,
            report_type=report_type,
            trust_weight=trust_weight,
        )

        return report

    async def get_consensus(self, url: str) -> CommunityConsensus:
        """
        Get aggregated community consensus for a URL.

        Checks both exact URL and domain-level reports.
        """
        try:
            domain = urlparse(url).netloc.lower()
        except Exception:
            domain = ""

        consensus = await self._repo.get_consensus(url, domain)

        logger.debug(
            "community.consensus_fetched",
            url=url,
            total_reports=consensus.total_reports,
            crowd_risk=consensus.crowd_risk_score,
        )

        return consensus

    async def get_reports_for_url(self, url: str, limit: int = 50) -> list[CommunityReport]:
        """Get individual reports for a specific URL."""
        return await self._repo.get_by_url(url, limit)

    async def get_reports_for_domain(self, domain: str, limit: int = 100) -> list[CommunityReport]:
        """Get all reports for a domain."""
        return await self._repo.get_by_domain(domain, limit)

    async def _compute_reporter_trust(self, reporter_id: str) -> float:
        """
        Compute a trust weight for a reporter based on their history.

        Factors:
        - New reporters start at 1.0
        - Reporters with many reports that align with consensus get higher trust
        - Reporters who consistently contradict consensus get lower trust

        This is a simplified version — a production system would use
        a more sophisticated reputation model.
        """
        if not reporter_id:
            return 0.5  # Anonymous = lower trust

        # For now, all registered reporters get default trust
        # Future: query report history and compute alignment with consensus
        return 1.0
