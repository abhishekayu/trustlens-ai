"""
TrustLens AI – FastAPI application entry-point.

Run with:
    uvicorn trustlens.main:app --reload
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from trustlens.core import get_settings
from trustlens.core.logging import get_logger, setup_logging
from trustlens.db import (
    APIKeyRepository,
    AuditLogRepository,
    BrandMonitorRepository,
    BrandRepository,
    CommunityReportRepository,
    Database,
    ScreenshotHashRepository,
    ThreatIntelRepository,
)
from trustlens.api.deps import (
    set_api_key_repo,
    set_brand_monitor_service,
    set_community_service,
    set_db,
    set_feed_ingester,
    set_task_queue,
    set_threat_intel_service,
)
from trustlens.api.middleware.api_auth import APIKeyAuthMiddleware
from trustlens.api.middleware.rate_limit import RateLimitMiddleware
from trustlens.api.middleware.domain_filter import DomainFilterMiddleware
from trustlens.api.routes.analyze import router as analyze_router
from trustlens.api.routes.community import router as community_router
from trustlens.api.routes.enterprise import router as enterprise_router
from trustlens.api.routes.health import router as health_router
from trustlens.api.routes.keys import router as keys_router
from trustlens.api.routes.report import router as report_router
from trustlens.api.routes.threat_intel import router as threat_intel_router
from trustlens.observability import AuditLogger, EventTypes, get_audit_logger, set_audit_logger
from trustlens.services.community import CommunityReportingService
from trustlens.services.enterprise import BrandMonitorService
from trustlens.services.queue import AsyncTaskQueue
from trustlens.services.threat_intel import FeedIngester, ThreatIntelService

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan – startup & shutdown hooks."""
    settings = get_settings()
    setup_logging(settings.log_level.value, json_output=not settings.debug)

    logger.info(
        "trustlens.starting",
        host=settings.host,
        port=settings.port,
        ai_provider=settings.ai_provider.value,
    )

    # ── Startup ──────────────────────────────────────────────────────────
    # 1. Database
    db = Database(settings.db_url)
    await db.connect()
    set_db(db)

    # 2. Seed default brands
    brand_repo = BrandRepository(db)
    await brand_repo.seed_defaults()

    # 3. Screenshot directory
    settings.screenshot_dir.mkdir(parents=True, exist_ok=True)

    # 4. Task queue
    queue = AsyncTaskQueue(max_concurrent=5)
    await queue.start()
    set_task_queue(queue)

    # 5. Audit logger
    audit_repo = AuditLogRepository(db)
    audit = AuditLogger(repo=audit_repo)
    set_audit_logger(audit)

    # 6. API key repository
    api_key_repo = APIKeyRepository(db)
    set_api_key_repo(api_key_repo)

    # Set API key repo on middleware (if middleware requires it)
    for mw in app.user_middleware:
        if hasattr(mw, 'cls') and mw.cls is APIKeyAuthMiddleware:
            pass  # Middleware will use the repo from deps

    # 7. Community reporting service
    if settings.community_reports_enabled:
        community_repo = CommunityReportRepository(db)
        community_service = CommunityReportingService(community_repo)
        set_community_service(community_service)

    # 8. Threat intelligence service
    threat_repo = ThreatIntelRepository(db)
    threat_service = ThreatIntelService(threat_repo)
    set_threat_intel_service(threat_service)

    feed_ingester = FeedIngester(threat_repo)
    set_feed_ingester(feed_ingester)

    # Auto-ingest configured feeds at startup
    if settings.threat_feed_urls.strip():
        try:
            results = await feed_ingester.ingest_all_configured()
            total = sum(results.values())
            logger.info("trustlens.threat_feeds_loaded", total_entries=total)
        except Exception as e:
            logger.warning("trustlens.threat_feed_ingest_failed", error=str(e))

    # 9. Enterprise brand monitor service
    if settings.enterprise_mode:
        monitor_repo = BrandMonitorRepository(db)
        monitor_service = BrandMonitorService(monitor_repo)
        set_brand_monitor_service(monitor_service)
        logger.info("trustlens.enterprise_mode_enabled")

    # 10. Emit startup audit event
    await audit.emit(
        event_type=EventTypes.SYSTEM_STARTUP,
        action="startup",
        metadata={
            "ai_provider": settings.ai_provider.value,
            "enterprise_mode": settings.enterprise_mode,
            "community_enabled": settings.community_reports_enabled,
        },
    )

    logger.info("trustlens.ready")

    yield  # ── Application runs here ──

    # ── Shutdown ─────────────────────────────────────────────────────────
    logger.info("trustlens.shutting_down")
    await audit.emit(event_type=EventTypes.SYSTEM_SHUTDOWN, action="shutdown")
    await queue.stop()
    await db.disconnect()
    logger.info("trustlens.stopped")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title="TrustLens AI",
        description=(
            "Explainable AI-Powered URL Trust Intelligence Engine. "
            "Provides transparent, evidence-based trust scoring for any URL "
            "with screenshot similarity detection, threat intelligence feeds, "
            "community reporting, and enterprise brand monitoring."
        ),
        version="0.2.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── Middleware (order matters – outermost first) ──────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(
        RateLimitMiddleware,
        max_requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )

    app.add_middleware(DomainFilterMiddleware)
    app.add_middleware(APIKeyAuthMiddleware)

    # ── Routes ───────────────────────────────────────────────────────────
    app.include_router(analyze_router)
    app.include_router(report_router)
    app.include_router(health_router)
    app.include_router(community_router)
    app.include_router(keys_router)
    app.include_router(threat_intel_router)
    app.include_router(enterprise_router)

    return app


app = create_app()
