"""
Community reporting API routes.

POST /api/v1/community/report       – Submit a scam/phishing report
GET  /api/v1/community/consensus    – Get crowd consensus for a URL
GET  /api/v1/community/reports      – List reports for a URL
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from trustlens.api.deps import get_community_service
from trustlens.schemas import (
    CommunityConsensusResponse,
    CommunityReportRequest,
    CommunityReportResponse,
)

router = APIRouter(prefix="/api/v1/community", tags=["Community"])


@router.post("/report", response_model=CommunityReportResponse, status_code=201)
async def submit_report(body: CommunityReportRequest, request: Request):
    """Submit a community scam/phishing report for a URL."""
    service = get_community_service()
    if service is None:
        raise HTTPException(503, "Community reporting is not enabled")

    client_ip = request.client.host if request.client else ""

    try:
        report = await service.submit_report(
            url=str(body.url),
            report_type=body.report_type,
            reporter_ip=client_ip,
            description=body.description,
            evidence_urls=body.evidence_urls,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))

    return CommunityReportResponse(
        report_id=report.id,
        url=str(body.url),
        report_type=report.report_type,
        trust_weight=report.trust_weight,
    )


@router.get("/consensus", response_model=CommunityConsensusResponse)
async def get_consensus(url: str = Query(..., description="URL to check consensus for")):
    """Get aggregated community consensus for a URL."""
    service = get_community_service()
    if service is None:
        raise HTTPException(503, "Community reporting is not enabled")

    consensus = await service.get_consensus(url)
    return CommunityConsensusResponse(url=url, consensus=consensus)


@router.get("/reports")
async def list_reports(
    url: str = Query(..., description="URL to list reports for"),
    limit: int = Query(50, ge=1, le=200),
):
    """List individual community reports for a URL."""
    service = get_community_service()
    if service is None:
        raise HTTPException(503, "Community reporting is not enabled")

    reports = await service.get_reports_for_url(url, limit)
    return {
        "url": url,
        "total": len(reports),
        "reports": [r.model_dump() for r in reports],
    }
