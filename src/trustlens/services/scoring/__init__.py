"""
Hybrid Risk Scoring Engine (70/30 Rule-AI split).

Combines rule-based heuristic signals (70%) and AI deception confidence (30%)
into a normalized 0-100 trust score with four risk categories:
  - Safe        (75-100)
  - Low Risk    (50-74)
  - Suspicious  (25-49)
  - High Risk   (0-24)

Design Principle: AI is advisory – it contributes a weighted signal but
NEVER directly determines the final risk level.
"""

from __future__ import annotations

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.models import (
    AIAnalysisResult,
    BehavioralSignal,
    BrandMatch,
    CommunityConsensus,
    ComponentScore,
    DomainIntelligence,
    RiskCategory,
    RiskLevel,
    RuleSignal,
    ScreenshotSimilarityResult,
    SecurityHeaderResult,
    ThreatIntelResult,
    TrustScore,
    ZeroDaySuspicionResult,
)

logger = get_logger(__name__)


class ScoringEngine:
    """Produce explainable trust scores from multi-source signals."""

    def __init__(self) -> None:
        s = get_settings()
        self._rule_weight = s.score_weight_rules   # default 0.70
        self._ai_weight = s.score_weight_ai         # default 0.30

    def score(
        self,
        rule_signals: list[RuleSignal],
        ai_result: AIAnalysisResult | None,
        brand_matches: list[BrandMatch],
        behavioral_signals: list[BehavioralSignal],
        domain_intel: DomainIntelligence | None = None,
        security_headers: SecurityHeaderResult | None = None,
        screenshot_similarity: ScreenshotSimilarityResult | None = None,
        zeroday_suspicion: ZeroDaySuspicionResult | None = None,
        threat_intel: ThreatIntelResult | None = None,
        community_consensus: CommunityConsensus | None = None,
    ) -> TrustScore:
        """Compute the final trust score with 70/30 split and component breakdown."""

        components: list[ComponentScore] = []

        # ── Rule-based sub-components (all feed into rule_score) ─

        # 1a. Heuristic rule signals
        rule_raw, rule_conf, rule_sigs = self._score_rules(rule_signals)
        components.append(ComponentScore(
            component="heuristic_rules", raw_score=rule_raw,
            weight=0.30, weighted_score=rule_raw * 0.30,
            confidence=rule_conf, signals=rule_sigs,
        ))

        # 1b. Brand impersonation
        brand_raw, brand_conf, brand_sigs = self._score_brand(brand_matches)
        components.append(ComponentScore(
            component="brand_impersonation", raw_score=brand_raw,
            weight=0.25, weighted_score=brand_raw * 0.25,
            confidence=brand_conf, signals=brand_sigs,
        ))

        # 1c. Behavioral redirect analysis
        behav_raw, behav_conf, behav_sigs = self._score_behavioral(behavioral_signals)
        components.append(ComponentScore(
            component="behavioral_analysis", raw_score=behav_raw,
            weight=0.20, weighted_score=behav_raw * 0.20,
            confidence=behav_conf, signals=behav_sigs,
        ))

        # 1d. Domain intelligence
        domain_raw, domain_conf, domain_sigs = self._score_domain(domain_intel)
        components.append(ComponentScore(
            component="domain_intelligence", raw_score=domain_raw,
            weight=0.15, weighted_score=domain_raw * 0.15,
            confidence=domain_conf, signals=domain_sigs,
        ))

        # 1e. Security headers (minor influence)
        headers_raw, headers_conf, headers_sigs = self._score_headers(security_headers)
        components.append(ComponentScore(
            component="security_headers", raw_score=headers_raw,
            weight=0.10, weighted_score=headers_raw * 0.10,
            confidence=headers_conf, signals=headers_sigs,
        ))

        # ── Aggregate rule score (weighted sum of sub-components) ─
        rule_score = sum(c.weighted_score for c in components)
        rule_score = max(0.0, min(100.0, rule_score))

        # ── AI confidence score ──────────────────────────────────
        ai_score, ai_conf, ai_sigs = self._score_ai(ai_result)
        components.append(ComponentScore(
            component="ai_deception_classifier", raw_score=ai_score,
            weight=self._ai_weight, weighted_score=ai_score * self._ai_weight,
            confidence=ai_conf, signals=ai_sigs,
        ))

        # ── Final hybrid score: 70% rules + 30% AI ──────────────
        overall = rule_score * self._rule_weight + ai_score * self._ai_weight
        overall = max(0.0, min(100.0, overall))

        # ── Supplementary signal adjustments ─────────────────────
        # These don't change the 70/30 weight structure but can adjust
        # the overall score based on strong external evidence.

        # Screenshot visual clone penalty
        if screenshot_similarity and screenshot_similarity.is_visual_clone:
            penalty = screenshot_similarity.similarity_score * 15  # up to -15 pts
            overall = max(0.0, overall - penalty)
            components.append(ComponentScore(
                component="screenshot_similarity", raw_score=max(0, 100 - penalty * 5),
                weight=0.0, weighted_score=-penalty,
                confidence=screenshot_similarity.similarity_score,
                signals=screenshot_similarity.signals[:3],
            ))

        # Zero-day suspicion penalty
        if zeroday_suspicion and zeroday_suspicion.is_potential_zeroday:
            penalty = min(10.0, zeroday_suspicion.suspicion_score / 10)
            overall = max(0.0, overall - penalty)
            components.append(ComponentScore(
                component="zeroday_suspicion", raw_score=max(0, 100 - zeroday_suspicion.suspicion_score),
                weight=0.0, weighted_score=-penalty,
                confidence=0.6,
                signals=zeroday_suspicion.anomaly_signals[:3],
            ))

        # Threat intelligence penalty (hard evidence)
        if threat_intel and threat_intel.is_known_threat:
            penalty = min(30.0, threat_intel.highest_confidence * 40)
            overall = max(0.0, overall - penalty)
            components.append(ComponentScore(
                component="threat_intelligence", raw_score=max(0, 100 - penalty * 3),
                weight=0.0, weighted_score=-penalty,
                confidence=threat_intel.highest_confidence,
                signals=threat_intel.signals[:3],
            ))

        # Community consensus adjustment
        if community_consensus and community_consensus.total_reports > 0:
            crowd_adjustment = (community_consensus.crowd_risk_score - 50) / 10  # -5 to +5
            crowd_adjustment *= community_consensus.consensus_confidence
            overall = max(0.0, min(100.0, overall + crowd_adjustment))
            components.append(ComponentScore(
                component="community_consensus",
                raw_score=community_consensus.crowd_risk_score,
                weight=0.0, weighted_score=round(crowd_adjustment, 2),
                confidence=community_consensus.consensus_confidence,
                signals=[
                    f"{community_consensus.total_reports} community reports",
                    f"Crowd risk score: {community_consensus.crowd_risk_score}/100",
                ],
            ))

        overall = max(0.0, min(100.0, overall))

        # Confidence is weighted average
        all_confs = [(c.confidence, c.weight) for c in components]
        total_w = sum(w for _, w in all_confs)
        confidence = sum(c * w for c, w in all_confs) / total_w if total_w > 0 else 0.5

        risk_level = self._classify_risk_level(overall)
        risk_category = self._classify_risk_category(overall)
        explanation = self._build_explanation(overall, risk_category, rule_score, ai_score, components)

        trust = TrustScore(
            overall_score=round(overall, 1),
            risk_level=risk_level,
            risk_category=risk_category,
            confidence=round(confidence, 3),
            rule_score=round(rule_score, 1),
            ai_confidence=round(ai_conf, 3),
            component_scores=components,
            explanation=explanation,
        )

        logger.info(
            "scoring_engine.scored",
            overall=trust.overall_score,
            risk=trust.risk_category.value,
            rule_score=trust.rule_score,
            ai_conf=trust.ai_confidence,
        )
        return trust

    # ── Component scorers ────────────────────────────────────────

    def _score_rules(self, signals: list[RuleSignal]) -> tuple[float, float, list[str]]:
        if not signals:
            return 100.0, 0.7, ["No rule violations detected"]
        total_impact = sum(s.score_impact for s in signals)
        score = max(0.0, 100.0 - total_impact)
        confidence = min(0.95, 0.5 + len(signals) * 0.05)
        summaries = [f"{s.rule_name}: {s.description}" for s in signals[:5]]
        return score, confidence, summaries

    def _score_ai(self, result: AIAnalysisResult | None) -> tuple[float, float, list[str]]:
        if result is None:
            return 75.0, 0.3, ["AI analysis not available"]

        # AI risk_score 0-100 → invert to trust score
        trust_score = max(0.0, 100.0 - result.risk_score)
        confidence = result.intent_confidence * 0.8  # dampen

        # If classifier is available, also factor in deception_confidence
        if result.classifier and result.classifier.deception_confidence > 0:
            dec_trust = (1.0 - result.classifier.deception_confidence) * 100
            trust_score = (trust_score + dec_trust) / 2
            confidence = max(confidence, result.classifier.deception_confidence * 0.7)

        signals = []
        if result.deception_indicators:
            signals.append(f"Deception: {', '.join(result.deception_indicators[:3])}")
        if result.legitimacy_indicators:
            signals.append(f"Legitimacy: {', '.join(result.legitimacy_indicators[:3])}")
        if result.social_engineering_tactics:
            signals.append(f"Social eng: {', '.join(result.social_engineering_tactics[:3])}")
        if result.classifier:
            c = result.classifier
            signals.append(
                f"Classifier: impersonation={c.impersonation:.2f}, "
                f"credential_harvesting={c.credential_harvesting:.2f}, "
                f"urgency={c.urgency_manipulation:.2f}"
            )
        if result.explanation:
            signals.append(result.explanation[:200])

        return trust_score, confidence, signals or ["AI returned no specific signals"]

    def _score_brand(self, matches: list[BrandMatch]) -> tuple[float, float, list[str]]:
        if not matches:
            return 90.0, 0.5, ["No brand associations detected"]

        official = [m for m in matches if m.is_official]
        if official:
            return 100.0, 0.95, [f"Official {official[0].brand_name} domain"]

        top = matches[0]

        # High domain similarity alone is very suspicious (typosquatting)
        if top.domain_similarity >= 0.85:
            score = max(0.0, 100.0 - top.domain_similarity * 95)
            return score, min(0.95, top.domain_similarity), [
                f"TYPOSQUATTING: Domain is {top.domain_similarity:.0%} similar to {top.brand_name}",
                f"Impersonation probability: {top.impersonation_probability:.0%}",
                f"This looks like a fake version of {top.brand_name}'s official domain",
            ]

        if top.impersonation_probability >= 0.6:
            score = max(0.0, 100.0 - top.impersonation_probability * 90)
            return score, min(0.9, top.impersonation_probability), [
                f"High impersonation probability for {top.brand_name}: {top.impersonation_probability:.2f}",
                f"Domain similarity: {top.domain_similarity:.2f}",
                f"Features: {', '.join(top.matched_features[:3])}",
            ]
        elif top.similarity_score >= 0.4 or top.domain_similarity >= 0.6:
            score = max(20.0, 100.0 - max(top.similarity_score, top.domain_similarity) * 70)
            return score, 0.7, [
                f"Suspicious similarity to {top.brand_name} (domain: {top.domain_similarity:.0%}, content: {top.content_similarity:.0%})"
            ]

        return 85.0, 0.5, [f"Low brand similarity (top: {top.brand_name})"]

    def _score_behavioral(self, signals: list[BehavioralSignal]) -> tuple[float, float, list[str]]:
        if not signals:
            return 95.0, 0.6, ["No suspicious behavior detected"]
        total_impact = sum(s.score_impact for s in signals)
        score = max(0.0, 100.0 - total_impact)
        confidence = min(0.9, 0.5 + len(signals) * 0.05)
        summaries = [f"{s.signal_type}: {s.description}" for s in signals[:5]]
        return score, confidence, summaries

    def _score_domain(self, intel: DomainIntelligence | None) -> tuple[float, float, list[str]]:
        if intel is None:
            return 80.0, 0.4, ["Domain intelligence not available"]
        confidence = 0.7 if intel.domain_age_days is not None else 0.4
        return intel.domain_score, confidence, intel.signals[:5] or ["Domain appears normal"]

    def _score_headers(self, headers: SecurityHeaderResult | None) -> tuple[float, float, list[str]]:
        if headers is None:
            return 70.0, 0.3, ["Security headers not analyzed"]
        return headers.header_score, 0.8, headers.signals[:3] or ["Headers analyzed"]

    # ── Risk classification ──────────────────────────────────────

    @staticmethod
    def _classify_risk_level(score: float) -> RiskLevel:
        if score >= 75:
            return RiskLevel.SAFE
        elif score >= 50:
            return RiskLevel.LOW
        elif score >= 25:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.HIGH

    @staticmethod
    def _classify_risk_category(score: float) -> RiskCategory:
        if score >= 75:
            return RiskCategory.SAFE
        elif score >= 50:
            return RiskCategory.LOW_RISK
        elif score >= 25:
            return RiskCategory.SUSPICIOUS
        else:
            return RiskCategory.HIGH_RISK

    @staticmethod
    def _build_explanation(
        score: float,
        risk: RiskCategory,
        rule_score: float,
        ai_score: float,
        components: list[ComponentScore],
    ) -> str:
        parts = [
            f"Overall trust score: {score:.1f}/100 — {risk.value}.",
            f"Rule-based score: {rule_score:.1f}/100 (70% weight) | "
            f"AI confidence score: {ai_score:.1f}/100 (30% weight).",
        ]
        for c in components:
            if c.raw_score < 60:
                parts.append(
                    f"  ⚠ {c.component}: {c.raw_score:.1f}/100 — "
                    + (c.signals[0] if c.signals else "flagged")
                )
        return "\n".join(parts)
