"""
Enterprise API routes (requires enterprise_mode=True).

POST /api/v1/enterprise/monitors           – Create a brand monitor
GET  /api/v1/enterprise/monitors           – List active monitors
GET  /api/v1/enterprise/alerts             – List brand alerts
GET  /api/v1/enterprise/alerts/{monitor_id} – Alerts for a specific monitor
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from trustlens.api.deps import get_brand_monitor_service
from trustlens.schemas import BrandMonitorRequest

router = APIRouter(prefix="/api/v1/enterprise", tags=["Enterprise"])


@router.post("/monitors", status_code=201)
async def create_monitor(body: BrandMonitorRequest):
    """
    Create a brand monitoring configuration.

    Requires enterprise mode to be enabled.
    """
    service = get_brand_monitor_service()
    if service is None:
        raise HTTPException(503, "Enterprise mode is not enabled")

    try:
        monitor = await service.create_monitor(
            brand_name=body.brand_name,
            official_domains=body.official_domains,
            keywords=body.keywords,
            logo_hashes=body.logo_hashes,
            alert_threshold=body.alert_threshold,
            alert_webhook=body.alert_webhook,
            scan_interval_hours=body.scan_interval_hours,
        )
    except RuntimeError as e:
        raise HTTPException(403, str(e))

    return {
        "monitor_id": monitor.id,
        "brand_name": monitor.brand_name,
        "official_domains": monitor.official_domains,
        "alert_threshold": monitor.alert_threshold,
        "message": "Brand monitor created successfully",
    }


@router.get("/monitors")
async def list_monitors():
    """List all active brand monitors."""
    service = get_brand_monitor_service()
    if service is None:
        raise HTTPException(503, "Enterprise mode is not enabled")

    monitors = await service.get_active_monitors()
    return {
        "total": len(monitors),
        "monitors": [m.model_dump() for m in monitors],
    }


@router.get("/alerts")
async def list_alerts(
    monitor_id: Optional[str] = Query(None, description="Filter by monitor ID"),
    limit: int = Query(50, ge=1, le=500),
):
    """List brand impersonation alerts."""
    service = get_brand_monitor_service()
    if service is None:
        raise HTTPException(503, "Enterprise mode is not enabled")

    alerts = await service.get_alerts(monitor_id=monitor_id, limit=limit)
    return {
        "total": len(alerts),
        "alerts": [a.model_dump() for a in alerts],
    }
