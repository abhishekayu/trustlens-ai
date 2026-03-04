"""
Analysis orchestrator – coordinates the full analysis pipeline.

Sequences: Crawl → [Rules, AI, Brand, Behavioral, Domain, Headers,
                     Screenshot, Logo, ThreatIntel, Community] (parallel)
         → ZeroDay → Score → Explain → Enterprise Alerts → Store
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.db import (
    AnalysisRepository,
    BrandRepository,
    CommunityReportRepository,
    Database,
    ScreenshotHashRepository,
    ThreatIntelRepository,
)
from trustlens.models import AnalysisStatus, CrawlResult, URLAnalysis
from trustlens.services.ai import (
    SYSTEM_PROMPT,
    BaseAIProvider,
    build_analysis_prompt,
    get_ai_provider,
)
from trustlens.services.analysis.behavioral import BehavioralAnalyzer
from trustlens.services.analysis.brand_similarity import BrandSimilarityEngine
from trustlens.services.analysis.content_extractor import ContentExtractor
from trustlens.services.analysis.domain_intel import DomainIntelligenceService
from trustlens.services.analysis.logo_detection import LogoDetectionEngine
from trustlens.services.analysis.rules import RuleEngine
from trustlens.services.analysis.screenshot_similarity import ScreenshotSimilarityEngine
from trustlens.services.analysis.security_headers import SecurityHeaderAnalyzer
from trustlens.services.analysis.zeroday import ZeroDaySuspicionScorer
from trustlens.services.community import CommunityReportingService
from trustlens.services.crawler import CrawlerService
from trustlens.services.scoring import ScoringEngine
from trustlens.services.threat_intel import ThreatIntelService

logger = get_logger(__name__)


class AnalysisOrchestrator:
    """End-to-end URL analysis pipeline."""

    def __init__(
        self,
        db: Database,
        analysis_repo: AnalysisRepository,
        brand_repo: BrandRepository,
    ) -> None:
        self._db = db
        self._repo = analysis_repo
        self._brand_repo = brand_repo
        self._crawler = CrawlerService()
        self._rule_engine = RuleEngine()
        self._behavioral = BehavioralAnalyzer()
        self._domain_intel = DomainIntelligenceService()
        self._header_analyzer = SecurityHeaderAnalyzer()
        self._content_extractor = ContentExtractor()
        self._scoring = ScoringEngine()
        self._zeroday = ZeroDaySuspicionScorer()
        self._logo_detector = LogoDetectionEngine()

        # Phase 5 services (set externally via setters for DI)
        self._screenshot_engine: Optional[ScreenshotSimilarityEngine] = None
        self._threat_intel: Optional[ThreatIntelService] = None
        self._community: Optional[CommunityReportingService] = None
        self._enterprise = None  # BrandMonitorService

    def set_screenshot_engine(self, engine: ScreenshotSimilarityEngine) -> None:
        self._screenshot_engine = engine

    def set_threat_intel(self, service: ThreatIntelService) -> None:
        self._threat_intel = service

    def set_community(self, service: CommunityReportingService) -> None:
        self._community = service

    def set_enterprise(self, service) -> None:
        self._enterprise = service

    async def analyze(
        self,
        analysis: URLAnalysis,
        enable_ai: bool = True,
        enable_domain_intel: bool = True,
        enable_threat_intel: bool = True,
        enable_community: bool = True,
        enable_zeroday: bool = True,
    ) -> URLAnalysis:
        """
        Run the complete analysis pipeline for a URL.

        Pipeline:
        1. Crawl the URL in a sandbox browser
        2. Run analysis components in parallel:
           a. Rule-based heuristics
           b. AI deception classifier (if enabled)
           c. Brand impersonation check
           d. Behavioral redirect analysis
           e. Domain intelligence (RDAP, age, TLD)
           f. Security header analysis
           g. Screenshot similarity (visual clone detection)
           h. Logo detection (placeholder)
           i. Threat intelligence feed lookup
           j. Community consensus
        3. Run zero-day suspicion scoring (needs results from phase 2)
        4. Score all signals with the 70/30 hybrid engine
        5. Generate AI explanation
        6. Enterprise alerts (if enabled)
        7. Persist results
        """
        url = analysis.url

        try:
            # ── Phase 1: Crawl ───────────────────────────────────
            await self._repo.update_status(analysis.id, AnalysisStatus.CRAWLING)
            analysis.status = AnalysisStatus.CRAWLING
            logger.info("orchestrator.crawling", analysis_id=analysis.id, url=url)

            crawl_result = await self._crawler.crawl(url)
            analysis.crawl_result = crawl_result

            if crawl_result.errors and crawl_result.status_code == 0:
                analysis.status = AnalysisStatus.FAILED
                analysis.error = f"Crawl failed: {'; '.join(crawl_result.errors)}"
                await self._repo.save_result(analysis)
                return analysis

            # ── Phase 2: Parallel analysis ───────────────────────
            await self._repo.update_status(analysis.id, AnalysisStatus.ANALYZING)
            analysis.status = AnalysisStatus.ANALYZING
            logger.info("orchestrator.analyzing", analysis_id=analysis.id)

            # Load brand registry
            brands = await self._brand_repo.get_all()
            brand_engine = BrandSimilarityEngine(brands if brands else None)

            # Build concurrent tasks
            tasks: dict[str, Any] = {
                "rules": self._rule_engine.analyze(crawl_result, url),
                "brand": brand_engine.analyze(crawl_result, url),
                "behavioral": self._behavioral.analyze(crawl_result, url),
                "headers": self._header_analyzer.analyze(crawl_result),
            }

            if enable_domain_intel:
                tasks["domain_intel"] = self._domain_intel.analyze(url)

            if enable_ai:
                tasks["ai"] = self._run_ai_analysis(crawl_result, url)

            # Screenshot similarity
            if self._screenshot_engine and crawl_result.screenshot_path:
                tasks["screenshot"] = self._screenshot_engine.analyze(
                    crawl_result.screenshot_path
                )

            # Logo detection
            if crawl_result.screenshot_path:
                tasks["logo"] = self._logo_detector.analyze(crawl_result.screenshot_path)

            # Threat intelligence
            if enable_threat_intel and self._threat_intel:
                tasks["threat_intel"] = self._threat_intel.lookup(url)

            # Community consensus
            if enable_community and self._community:
                tasks["community"] = self._community.get_consensus(url)

            # Run all components concurrently
            results = {}
            task_list = list(tasks.items())
            coros = [t[1] for t in task_list]
            completed = await asyncio.gather(*coros, return_exceptions=True)

            for (name, _), result in zip(task_list, completed):
                if isinstance(result, Exception):
                    logger.error("orchestrator.component_failed", component=name, error=str(result))
                    results[name] = None
                else:
                    results[name] = result

            analysis.rule_signals = results.get("rules") or []
            analysis.ai_result = results.get("ai")
            analysis.brand_matches = results.get("brand") or []
            analysis.behavioral_signals = results.get("behavioral") or []
            analysis.domain_intel = results.get("domain_intel")
            analysis.security_headers = results.get("headers")
            analysis.screenshot_similarity = results.get("screenshot")
            analysis.logo_detection = results.get("logo")
            analysis.threat_intel = results.get("threat_intel")
            analysis.community_consensus = results.get("community")

            # ── Phase 2.5: Zero-Day Suspicion ────────────────────
            if enable_zeroday:
                try:
                    analysis.zeroday_suspicion = self._zeroday.analyze(
                        crawl=crawl_result,
                        url=url,
                        rule_signals=analysis.rule_signals,
                        brand_matches=analysis.brand_matches,
                        behavioral_signals=analysis.behavioral_signals,
                        domain_intel=analysis.domain_intel,
                        security_headers=analysis.security_headers,
                    )
                except Exception as e:
                    logger.error("orchestrator.zeroday_failed", error=str(e))

            # ── Phase 3: Scoring ─────────────────────────────────
            await self._repo.update_status(analysis.id, AnalysisStatus.SCORING)
            analysis.status = AnalysisStatus.SCORING
            logger.info("orchestrator.scoring", analysis_id=analysis.id)

            analysis.trust_score = self._scoring.score(
                rule_signals=analysis.rule_signals,
                ai_result=analysis.ai_result,
                brand_matches=analysis.brand_matches,
                behavioral_signals=analysis.behavioral_signals,
                domain_intel=analysis.domain_intel,
                security_headers=analysis.security_headers,
                screenshot_similarity=analysis.screenshot_similarity,
                zeroday_suspicion=analysis.zeroday_suspicion,
                threat_intel=analysis.threat_intel,
                community_consensus=analysis.community_consensus,
            )

            # ── Phase 4: AI Explanation ──────────────────────────
            if enable_ai and analysis.trust_score:
                try:
                    provider = get_ai_provider()
                    signals_summary = self._build_signals_summary(analysis)
                    ai_explanation = await provider.generate_explanation(signals_summary)
                    if ai_explanation:
                        analysis.trust_score.ai_explanation = ai_explanation
                except Exception as e:
                    logger.warning("orchestrator.explanation_failed", error=str(e))

            # ── Phase 5: Enterprise Alerts ───────────────────────
            if self._enterprise and analysis.brand_matches:
                try:
                    await self._enterprise.check_analysis_for_alerts(
                        url=url,
                        brand_matches=analysis.brand_matches,
                        screenshot_path=crawl_result.screenshot_path,
                    )
                except Exception as e:
                    logger.warning("orchestrator.enterprise_alerts_failed", error=str(e))

            # ── Phase 6: Complete ────────────────────────────────
            analysis.status = AnalysisStatus.COMPLETED
            analysis.completed_at = datetime.now(timezone.utc)
            await self._repo.save_result(analysis)

            logger.info(
                "orchestrator.completed",
                analysis_id=analysis.id,
                score=analysis.trust_score.overall_score if analysis.trust_score else 0,
                risk=analysis.trust_score.risk_category.value if analysis.trust_score else "unknown",
            )

        except Exception as e:
            logger.error("orchestrator.failed", analysis_id=analysis.id, error=str(e))
            analysis.status = AnalysisStatus.FAILED
            analysis.error = str(e)
            await self._repo.save_result(analysis)

        return analysis

    async def _run_ai_analysis(self, crawl: CrawlResult, url: str):
        """Prepare data and run AI analysis."""
        provider = get_ai_provider()

        # Use content extractor for cleaner text
        page_text = self._content_extractor.extract_for_ai(crawl.html_content)

        forms_info = json.dumps(crawl.forms[:5], indent=2) if crawl.forms else "None found"
        redirect_info = "\n".join(
            f"  {i+1}. {hop.url} (HTTP {hop.status_code})"
            for i, hop in enumerate(crawl.redirect_chain)
        ) or "No redirects"

        meta_info = json.dumps(crawl.meta_tags, indent=2) if crawl.meta_tags else "None"
        ssl_info = json.dumps(crawl.ssl_info, indent=2) if crawl.ssl_info else "Unknown"

        prompt = build_analysis_prompt(
            url=url,
            final_url=crawl.final_url,
            page_title=crawl.page_title,
            page_text=page_text,
            forms_info=forms_info,
            redirect_chain=redirect_info,
            meta_tags=meta_info,
            ssl_info=ssl_info,
        )

        return await provider.get_analysis(SYSTEM_PROMPT, prompt)

    def _build_signals_summary(self, analysis: URLAnalysis) -> str:
        """Build a text summary of all analysis signals for AI explanation."""
        parts: list[str] = []
        parts.append(f"URL: {analysis.url}")
        if analysis.trust_score:
            parts.append(f"Score: {analysis.trust_score.overall_score}/100 ({analysis.trust_score.risk_category.value})")
        if analysis.rule_signals:
            parts.append("Rule Signals:")
            for s in analysis.rule_signals[:8]:
                parts.append(f"  - [{s.severity.value}] {s.rule_name}: {s.description}")
        if analysis.brand_matches:
            for m in analysis.brand_matches[:3]:
                if not m.is_official:
                    parts.append(f"Brand: resembles {m.brand_name} (similarity: {m.similarity_score:.2f}, impersonation prob: {m.impersonation_probability:.2f})")
        if analysis.behavioral_signals:
            parts.append("Behavioral:")
            for b in analysis.behavioral_signals[:5]:
                parts.append(f"  - {b.signal_type}: {b.description}")
        if analysis.domain_intel:
            for s in analysis.domain_intel.signals[:3]:
                parts.append(f"Domain: {s}")
        if analysis.security_headers:
            for s in analysis.security_headers.signals[:2]:
                parts.append(f"Headers: {s}")
        # Phase 5 signals
        if analysis.screenshot_similarity and analysis.screenshot_similarity.is_visual_clone:
            parts.append(f"VISUAL CLONE: matches {analysis.screenshot_similarity.closest_brand} "
                         f"(similarity {analysis.screenshot_similarity.similarity_score:.3f})")
        if analysis.zeroday_suspicion and analysis.zeroday_suspicion.is_potential_zeroday:
            parts.append(f"ZERO-DAY SUSPICION: score {analysis.zeroday_suspicion.suspicion_score}/100")
            for s in analysis.zeroday_suspicion.anomaly_signals[:3]:
                parts.append(f"  - {s}")
        if analysis.threat_intel and analysis.threat_intel.is_known_threat:
            parts.append(f"THREAT INTEL: matched in {analysis.threat_intel.feed_count} feeds "
                         f"({', '.join(analysis.threat_intel.threat_types[:3])})")
        if analysis.community_consensus and analysis.community_consensus.total_reports > 0:
            c = analysis.community_consensus
            parts.append(f"Community: {c.total_reports} reports (crowd risk: {c.crowd_risk_score}/100)")
        return "\n".join(parts)
