"""
Transparency report endpoint – full explainability view.
"""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status

from trustlens.core.logging import get_logger
from trustlens.models import AnalysisStatus
from trustlens.schemas import (
    AIInsightResponse,
    TransparencyReport,
    TrustScoreResponse,
)
from trustlens.api.deps import get_analysis_repo
from trustlens.db import AnalysisRepository

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["report"])


def _parse_json_field(raw, fallback=None):
    """Safely parse a JSON string field from the DB."""
    if raw is None:
        return fallback
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return fallback
    return raw


@router.get(
    "/analysis/{analysis_id}/report",
    response_model=TransparencyReport,
    summary="Full transparency report for a completed analysis",
)
async def get_report(
    analysis_id: str,
    repo: AnalysisRepository = Depends(get_analysis_repo),
):
    """
    Returns the complete explainability report including:
    - Trust score breakdown
    - Domain intelligence
    - All rule signals with evidence
    - AI insights and classifier output
    - Brand impersonation matches
    - Behavioral signals
    - Security header analysis
    - Redirect chain
    """
    analysis = await repo.get_by_id(analysis_id)
    if analysis is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis {analysis_id} not found",
        )

    if analysis.status != AnalysisStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Analysis is still {analysis.status.value}. Report is only available after completion.",
        )

    # Build trust score response
    trust_score = None
    if analysis.trust_score is not None:
        ts = analysis.trust_score
        trust_score = TrustScoreResponse(
            overall_score=ts.overall_score,
            risk_level=ts.risk_level,
            risk_category=ts.risk_category,
            confidence=ts.confidence,
            rule_score=ts.rule_score,
            ai_confidence=ts.ai_confidence,
            components=ts.component_scores,
            explanation=ts.explanation,
            ai_explanation=ts.ai_explanation,
        )

    # Build AI insights response
    ai_insights = None
    if analysis.ai_result is not None:
        ai = analysis.ai_result
        ai_insights = AIInsightResponse(
            deception_indicators=ai.deception_indicators if hasattr(ai, 'deception_indicators') else [],
            legitimacy_indicators=ai.legitimacy_indicators if hasattr(ai, 'legitimacy_indicators') else [],
            social_engineering_tactics=ai.social_engineering_tactics if hasattr(ai, 'social_engineering_tactics') else [],
            intent=ai.intent if hasattr(ai, 'intent') else "unknown",
            intent_confidence=ai.intent_confidence if hasattr(ai, 'intent_confidence') else 0.0,
            classifier=ai.classifier if hasattr(ai, 'classifier') else None,
            explanation=ai.explanation if hasattr(ai, 'explanation') else "",
        )

    # Crawl data
    crawl = analysis.crawl_result
    redirect_chain = crawl.redirect_chain if crawl and hasattr(crawl, 'redirect_chain') else []
    page_title = crawl.page_title if crawl and hasattr(crawl, 'page_title') else ""
    final_url = crawl.final_url if crawl and hasattr(crawl, 'final_url') else ""
    ssl_valid = None
    if crawl and hasattr(crawl, 'ssl_info') and crawl.ssl_info:
        ssl_valid = crawl.ssl_info.valid if hasattr(crawl.ssl_info, 'valid') else None
    screenshot_path = crawl.screenshot_path if crawl and hasattr(crawl, 'screenshot_path') else None

    return TransparencyReport(
        analysis_id=analysis_id,
        url=analysis.url,
        submitted_at=analysis.submitted_at,
        completed_at=analysis.completed_at,
        status=analysis.status,
        trust_score=trust_score,
        domain_intelligence=analysis.domain_intel,
        rule_signals=analysis.rule_signals,
        ai_insights=ai_insights,
        brand_matches=analysis.brand_matches,
        behavioral_signals=analysis.behavioral_signals,
        security_headers=analysis.security_headers,
        screenshot_similarity=analysis.screenshot_similarity,
        logo_detection=analysis.logo_detection,
        zeroday_suspicion=analysis.zeroday_suspicion,
        community_consensus=analysis.community_consensus,
        threat_intel=analysis.threat_intel,
        redirect_chain=[r.model_dump() if hasattr(r, 'model_dump') else r for r in redirect_chain] if redirect_chain else [],
        page_title=page_title,
        final_url=final_url,
        ssl_valid=ssl_valid,
        screenshot_url=screenshot_path,
    )
