"""
Domain models – internal representations used across the engine.

These are *not* API schemas; see trustlens.schemas for request/response models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskCategory(str, Enum):
    """Human-readable risk classification for the 70/30 scoring output."""
    SAFE = "Safe"
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"


class AnalysisStatus(str, Enum):
    PENDING = "pending"
    CRAWLING = "crawling"
    ANALYZING = "analyzing"
    SCORING = "scoring"
    COMPLETED = "completed"
    FAILED = "failed"


class IntentCategory(str, Enum):
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    CREDENTIAL_HARVEST = "credential_harvest"
    MALWARE_DELIVERY = "malware_delivery"
    SOCIAL_ENGINEERING = "social_engineering"
    SCAM = "scam"
    UNKNOWN = "unknown"


# ── Crawl Result ─────────────────────────────────────────────────────────────


class RedirectHop(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)


class CrawlResult(BaseModel):
    """Raw data collected by the sandbox crawler."""

    final_url: str
    status_code: int
    redirect_chain: list[RedirectHop] = Field(default_factory=list)
    html_content: str = ""
    page_title: str = ""
    meta_tags: dict[str, str] = Field(default_factory=dict)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    external_links: list[str] = Field(default_factory=list)
    scripts: list[str] = Field(default_factory=list)
    ssl_info: Optional[dict[str, Any]] = None
    screenshot_path: Optional[str] = None
    screenshot_base64: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: list[dict[str, Any]] = Field(default_factory=list)
    load_time_ms: int = 0
    errors: list[str] = Field(default_factory=list)


# ── Domain Intelligence ──────────────────────────────────────────────────────


class DomainIntelligence(BaseModel):
    """Result from RDAP / DNS / TLD analysis."""

    domain: str
    registered_domain: str = ""
    tld: str = ""
    is_suspicious_tld: bool = False
    domain_age_days: Optional[int] = None
    registrar: str = ""
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    dns_records: dict[str, list[str]] = Field(default_factory=dict)
    rdap_raw: Optional[dict[str, Any]] = None
    age_score: float = 100.0          # 0-100, 100 = trusted mature domain
    tld_score: float = 100.0          # 0-100
    domain_score: float = 100.0       # aggregated domain intelligence score
    signals: list[str] = Field(default_factory=list)


# ── Analysis Sub-Results ─────────────────────────────────────────────────────


class RuleSignal(BaseModel):
    """A single rule-based detection signal."""

    rule_id: str
    rule_name: str
    category: str
    severity: RiskLevel
    description: str
    evidence: str = ""
    score_impact: float = 0.0  # 0-100 contribution


class AIClassifierResult(BaseModel):
    """
    Structured output from the AI Intent & Deception Classifier.

    The AI must return exactly this shape — it never decides final risk.
    """

    impersonation: float = 0.0              # 0-1 confidence
    credential_harvesting: float = 0.0      # 0-1
    urgency_manipulation: float = 0.0       # 0-1
    fear_tactics: float = 0.0              # 0-1
    payment_demand: float = 0.0            # 0-1
    data_collection: float = 0.0           # 0-1
    deception_confidence: float = 0.0      # 0-1 overall
    reasoning: str = ""
    raw_response: Optional[dict[str, Any]] = None


class AIAnalysisResult(BaseModel):
    """Structured output from the AI deception analysis (legacy compat)."""

    deception_indicators: list[str] = Field(default_factory=list)
    legitimacy_indicators: list[str] = Field(default_factory=list)
    social_engineering_tactics: list[str] = Field(default_factory=list)
    intent_classification: IntentCategory = IntentCategory.UNKNOWN
    intent_confidence: float = 0.0  # 0-1
    risk_score: float = 0.0  # 0-100
    explanation: str = ""
    classifier: Optional[AIClassifierResult] = None
    url_perspective: Optional[dict[str, Any]] = None
    raw_response: Optional[dict[str, Any]] = None


class BrandMatch(BaseModel):
    """Result of brand impersonation similarity analysis."""

    brand_name: str
    similarity_score: float  # 0-1
    matched_features: list[str] = Field(default_factory=list)
    domain_similarity: float = 0.0
    visual_similarity: float = 0.0
    content_similarity: float = 0.0
    impersonation_probability: float = 0.0  # 0-1
    is_official: bool = False


class BehavioralSignal(BaseModel):
    """Behavioral analysis signal from redirect / runtime analysis."""

    signal_type: str
    description: str
    severity: RiskLevel
    evidence: str = ""
    score_impact: float = 0.0


class SecurityHeaderResult(BaseModel):
    """Result from security header analysis."""

    is_https: bool = False
    has_hsts: bool = False
    has_csp: bool = False
    has_x_frame_options: bool = False
    has_x_content_type_options: bool = False
    has_referrer_policy: bool = False
    has_permissions_policy: bool = False
    missing_headers: list[str] = Field(default_factory=list)
    header_score: float = 100.0   # 0-100
    signals: list[str] = Field(default_factory=list)


# ── Screenshot Similarity ────────────────────────────────────────────────────


class ScreenshotSimilarityResult(BaseModel):
    """Result from perceptual-hash visual similarity engine."""

    phash: str = ""                              # hex string of perceptual hash
    dhash: str = ""                              # hex string of difference hash
    closest_brand: Optional[str] = None
    closest_brand_distance: float = 1.0          # 0 = identical, 1 = totally different
    similarity_score: float = 0.0                # 0-1, 1 = visually identical to a brand
    is_visual_clone: bool = False                # True if similarity > threshold
    matched_screenshots: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)


# ── Logo Detection ───────────────────────────────────────────────────────────


class LogoDetectionResult(BaseModel):
    """Placeholder for vision-based logo detection (future ML model)."""

    logos_detected: list[dict[str, Any]] = Field(default_factory=list)
    brand_logos_matched: list[str] = Field(default_factory=list)
    confidence: float = 0.0           # 0-1
    model_used: str = "placeholder"   # future: "yolov8", "clip", etc.
    signals: list[str] = Field(default_factory=list)


# ── Zero-Day Suspicion ───────────────────────────────────────────────────────


class ZeroDaySuspicionResult(BaseModel):
    """Heuristic anomaly scoring for never-before-seen threat patterns."""

    suspicion_score: float = 0.0      # 0-100, 100 = highly suspicious
    anomaly_signals: list[str] = Field(default_factory=list)
    language_anomaly_score: float = 0.0     # 0-1
    structural_anomaly_score: float = 0.0   # 0-1
    behavioral_anomaly_score: float = 0.0   # 0-1
    domain_novelty_score: float = 0.0       # 0-1, 1 = brand new domain never seen
    is_potential_zeroday: bool = False


# ── Community Reporting ──────────────────────────────────────────────────────


class CommunityReport(BaseModel):
    """A user-submitted scam/phishing report."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    url: str
    reporter_id: str = ""                    # hashed IP or API key
    report_type: str = "phishing"            # phishing, scam, malware, safe
    description: str = ""
    evidence_urls: list[str] = Field(default_factory=list)
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False
    trust_weight: float = 1.0                # reputation-weighted credibility


class CommunityConsensus(BaseModel):
    """Aggregated community consensus for a URL/domain."""

    url_or_domain: str
    total_reports: int = 0
    phishing_reports: int = 0
    safe_reports: int = 0
    scam_reports: int = 0
    crowd_risk_score: float = 50.0    # 0-100, 50 = neutral, 0 = crowd says dangerous
    consensus_confidence: float = 0.0  # 0-1, based on report count + diversity
    last_report_at: Optional[datetime] = None


# ── Threat Intelligence ──────────────────────────────────────────────────────


# ── Payment Detection ─────────────────────────────────────────────────────


class PaymentDetectionResult(BaseModel):
    """Result from payment form/gateway detection analysis."""

    has_payment_form: bool = False
    payment_gateways_detected: list[str] = Field(default_factory=list)
    payment_form_fields: list[str] = Field(default_factory=list)
    crypto_addresses: list[dict[str, str]] = Field(default_factory=list)  # {type, address}
    suspicious_payment_patterns: list[str] = Field(default_factory=list)
    legitimate_payment_indicators: list[str] = Field(default_factory=list)
    payment_security_score: float = 100.0   # 0-100, 100 = secure
    risk_level: RiskLevel = RiskLevel.SAFE
    signals: list[str] = Field(default_factory=list)


# ── Tracker / Malware Detection ──────────────────────────────────────────


class TrackerInfo(BaseModel):
    """A single detected tracker/script."""

    name: str
    category: str  # analytics, advertising, fingerprinting, social, malware, mining
    url: str = ""
    severity: RiskLevel = RiskLevel.LOW
    description: str = ""


class TrackerDetectionResult(BaseModel):
    """Result from tracker, spyware, and malware detection analysis."""

    total_trackers: int = 0
    trackers: list[TrackerInfo] = Field(default_factory=list)
    categories: dict[str, int] = Field(default_factory=dict)  # category → count
    analytics_trackers: list[str] = Field(default_factory=list)
    advertising_trackers: list[str] = Field(default_factory=list)
    fingerprinting_scripts: list[str] = Field(default_factory=list)
    malware_scripts: list[str] = Field(default_factory=list)
    mining_scripts: list[str] = Field(default_factory=list)
    suspicious_scripts: list[str] = Field(default_factory=list)
    known_spyware: list[str] = Field(default_factory=list)
    privacy_score: float = 100.0     # 0-100, 100 = private
    risk_level: RiskLevel = RiskLevel.SAFE
    signals: list[str] = Field(default_factory=list)


# ── Download & Permission Threat Detection ───────────────────────────────


class DownloadThreatResult(BaseModel):
    """Result from download threat, auto-download, and permission abuse detection."""

    has_auto_download: bool = False
    download_links: list[str] = Field(default_factory=list)
    dangerous_file_types: list[str] = Field(default_factory=list)
    auto_download_triggers: list[str] = Field(default_factory=list)
    permissions_requested: list[str] = Field(default_factory=list)
    permission_details: list[dict[str, Any]] = Field(default_factory=list)
    notification_spam_detected: bool = False
    pup_indicators: list[str] = Field(default_factory=list)
    safety_score: float = 100.0      # 0-100, 100 = safe
    risk_level: RiskLevel = RiskLevel.SAFE
    signals: list[str] = Field(default_factory=list)


# ── Threat Intelligence ──────────────────────────────────────────────────


class ThreatFeedEntry(BaseModel):
    """A single threat indicator from an intelligence feed."""

    indicator: str                     # domain, URL, or IP
    indicator_type: str = "domain"     # domain, url, ip, hash
    feed_name: str = ""
    threat_type: str = ""              # phishing, malware, c2, etc.
    confidence: float = 0.0            # 0-1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)


class ThreatIntelResult(BaseModel):
    """Aggregated threat intelligence lookup result."""

    matches: list[ThreatFeedEntry] = Field(default_factory=list)
    is_known_threat: bool = False
    highest_confidence: float = 0.0
    feed_count: int = 0               # how many feeds flagged this
    threat_types: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)


# ── API Key / Tier ───────────────────────────────────────────────────────────


class APITier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class APIKeyRecord(BaseModel):
    """An API key with its associated tier and limits."""

    key_hash: str                      # SHA-256 of the actual key
    owner: str = ""
    tier: APITier = APITier.FREE
    rate_limit: int = 30               # requests per window
    rate_window: int = 60              # seconds
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    scopes: list[str] = Field(default_factory=list)  # e.g. ["analyze", "report", "batch"]


# ── Audit / Observability ────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    """Structured audit log entry."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str                    # "analysis.started", "api_key.created", etc.
    actor: str = ""                    # API key hash or IP
    resource: str = ""                 # URL, analysis_id
    action: str = ""                   # "create", "read", "delete"
    outcome: str = "success"           # success, failure, denied
    metadata: dict[str, Any] = Field(default_factory=dict)
    ip_address: str = ""
    user_agent: str = ""


# ── Enterprise Mode ─────────────────────────────────────────────────────────


class BrandMonitor(BaseModel):
    """Enterprise brand monitoring configuration."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    brand_name: str
    official_domains: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    logo_hashes: list[str] = Field(default_factory=list)
    monitoring_enabled: bool = True
    scan_interval_hours: int = 24
    alert_threshold: float = 0.7      # similarity above this triggers alert
    alert_webhook: str = ""
    last_scan_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BrandAlert(BaseModel):
    """Alert generated when brand impersonation is detected."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    monitor_id: str
    brand_name: str
    suspicious_url: str
    similarity_score: float
    detection_type: str = ""           # "domain", "visual", "content"
    screenshot_path: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False


# ── Scoring ──────────────────────────────────────────────────────────────────


class ComponentScore(BaseModel):
    """Score from a single analysis component."""

    component: str
    raw_score: float  # 0-100
    weight: float  # 0-1
    weighted_score: float  # raw * weight
    confidence: float  # 0-1
    signals: list[str] = Field(default_factory=list)


class TrustScore(BaseModel):
    """Final aggregated trust score with full breakdown."""

    overall_score: float  # 0-100 (100 = fully trusted)
    risk_level: RiskLevel
    risk_category: RiskCategory = RiskCategory.SAFE
    confidence: float  # 0-1
    rule_score: float = 0.0
    ai_confidence: float = 0.0
    component_scores: list[ComponentScore] = Field(default_factory=list)
    explanation: str = ""
    ai_explanation: str = ""


# ── Top-Level Analysis ───────────────────────────────────────────────────────


class URLAnalysis(BaseModel):
    """Complete analysis result for a single URL."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    url: str
    submitted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: AnalysisStatus = AnalysisStatus.PENDING

    crawl_result: Optional[CrawlResult] = None
    domain_intel: Optional[DomainIntelligence] = None
    rule_signals: list[RuleSignal] = Field(default_factory=list)
    ai_result: Optional[AIAnalysisResult] = None
    brand_matches: list[BrandMatch] = Field(default_factory=list)
    behavioral_signals: list[BehavioralSignal] = Field(default_factory=list)
    security_headers: Optional[SecurityHeaderResult] = None
    screenshot_similarity: Optional[ScreenshotSimilarityResult] = None
    logo_detection: Optional[LogoDetectionResult] = None
    zeroday_suspicion: Optional[ZeroDaySuspicionResult] = None
    community_consensus: Optional[CommunityConsensus] = None
    threat_intel: Optional[ThreatIntelResult] = None
    payment_detection: Optional[PaymentDetectionResult] = None
    tracker_detection: Optional[TrackerDetectionResult] = None
    download_threat: Optional[DownloadThreatResult] = None
    trust_score: Optional[TrustScore] = None

    error: Optional[str] = None
