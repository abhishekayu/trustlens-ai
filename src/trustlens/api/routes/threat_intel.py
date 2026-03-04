"""
Threat intelligence API routes.

GET  /api/v1/threat-intel/lookup   – Look up a domain/URL in threat feeds
GET  /api/v1/threat-intel/stats    – Feed statistics
POST /api/v1/threat-intel/ingest   – Manually trigger feed ingestion (admin)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from trustlens.api.deps import get_threat_intel_service, get_feed_ingester
from trustlens.schemas import ThreatIntelStatsResponse

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])


@router.get("/lookup")
async def lookup_threat(
    url: str = Query(..., description="URL or domain to check against threat feeds"),
):
    """Look up a URL or domain in the local threat intelligence cache."""
    service = get_threat_intel_service()
    if service is None:
        raise HTTPException(503, "Threat intelligence is not available")

    result = await service.lookup(url)
    return result.model_dump()


@router.get("/stats", response_model=ThreatIntelStatsResponse)
async def threat_stats():
    """Get threat intelligence feed statistics."""
    service = get_threat_intel_service()
    if service is None:
        raise HTTPException(503, "Threat intelligence is not available")

    stats = await service.get_stats()
    total = sum(stats.values())
    return ThreatIntelStatsResponse(feeds=stats, total_entries=total)


@router.post("/ingest")
async def ingest_feeds():
    """
    Manually trigger ingestion of all configured threat feeds.

    Requires enterprise or admin API key scope.
    """
    ingester = get_feed_ingester()
    if ingester is None:
        raise HTTPException(503, "Feed ingestion is not available")

    results = await ingester.ingest_all_configured()
    total = sum(results.values())
    return {
        "message": f"Ingested {total} entries from {len(results)} feeds",
        "feeds": results,
    }
