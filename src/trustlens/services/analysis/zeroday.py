"""
Zero-Day Suspicion Scoring – heuristic anomaly detection for unknown threats.

Unlike rule-based detection (which matches known patterns), this module
looks for *anomalous combinations* of signals that don't match any known
benign pattern.  High suspicion scores indicate a URL that is "weird enough"
to warrant extra scrutiny, even if no specific rule fires.

Signal categories:
    1. Language anomalies   – unusual Unicode, mixed scripts, invisible chars
    2. Structural anomalies – DOM shape mismatches, excessive obfuscation
    3. Behavioral anomalies – redirect patterns, timing, evasion tactics
    4. Domain novelty       – brand-new domain + suspicious structure
"""

from __future__ import annotations

import math
import re
import unicodedata
from typing import Any, Optional
from urllib.parse import urlparse

from trustlens.core.logging import get_logger
from trustlens.models import (
    BehavioralSignal,
    BrandMatch,
    CrawlResult,
    DomainIntelligence,
    RiskLevel,
    RuleSignal,
    SecurityHeaderResult,
    ZeroDaySuspicionResult,
)

logger = get_logger(__name__)

# ── Unicode / script anomaly patterns ────────────────────────────────────────

_INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064"
    r"\ufeff\u00ad\u034f\u061c\u180e\u2028\u2029\u202a-\u202e]"
)

_HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ј": "j", "ɡ": "g", "ɩ": "l", "ɪ": "I",
    "ᴏ": "o", "ᴜ": "u",
}

# ── Obfuscation patterns ────────────────────────────────────────────────────

_BASE64_INLINE = re.compile(r"(?:data:[\w/]+;base64,|atob\s*\(|btoa\s*\()")
_EVAL_PATTERNS = re.compile(r"(?:eval\s*\(|Function\s*\(|setTimeout\s*\(\s*['\"]|document\.write)")
_HEX_ENCODED = re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}")
_CHAR_CODE = re.compile(r"String\.fromCharCode|charCodeAt")


class ZeroDaySuspicionScorer:
    """
    Compute a suspicion score for anomalies that don't match known rules.

    Each sub-scorer returns 0-1.  The final score is a weighted combination
    mapped to 0-100.
    """

    # Sub-component weights (must sum to 1.0)
    WEIGHTS = {
        "language": 0.25,
        "structural": 0.30,
        "behavioral": 0.25,
        "domain_novelty": 0.20,
    }

    def analyze(
        self,
        crawl: CrawlResult,
        url: str,
        rule_signals: list[RuleSignal] | None = None,
        brand_matches: list[BrandMatch] | None = None,
        behavioral_signals: list[BehavioralSignal] | None = None,
        domain_intel: DomainIntelligence | None = None,
        security_headers: SecurityHeaderResult | None = None,
    ) -> ZeroDaySuspicionResult:
        """Run all anomaly sub-scorers and produce a combined suspicion score."""

        signals: list[str] = []

        # ── 1. Language anomaly ──────────────────────────────────────────
        lang_score, lang_sigs = self._language_anomaly(crawl, url)
        signals.extend(lang_sigs)

        # ── 2. Structural anomaly ────────────────────────────────────────
        struct_score, struct_sigs = self._structural_anomaly(crawl)
        signals.extend(struct_sigs)

        # ── 3. Behavioral anomaly ────────────────────────────────────────
        behav_score, behav_sigs = self._behavioral_anomaly(
            crawl, behavioral_signals or []
        )
        signals.extend(behav_sigs)

        # ── 4. Domain novelty ────────────────────────────────────────────
        novelty_score, novelty_sigs = self._domain_novelty(
            url, domain_intel, rule_signals or [], brand_matches or []
        )
        signals.extend(novelty_sigs)

        # ── Weighted combination ─────────────────────────────────────────
        raw_suspicion = (
            lang_score * self.WEIGHTS["language"]
            + struct_score * self.WEIGHTS["structural"]
            + behav_score * self.WEIGHTS["behavioral"]
            + novelty_score * self.WEIGHTS["domain_novelty"]
        )

        # Scale to 0-100
        suspicion_100 = max(0.0, min(100.0, raw_suspicion * 100))

        # Apply sigmoid compression to avoid extreme values on sparse evidence
        compressed = self._sigmoid_compress(suspicion_100, midpoint=50, steepness=0.08)

        is_potential_zeroday = compressed >= 65 and len(signals) >= 3

        result = ZeroDaySuspicionResult(
            suspicion_score=round(compressed, 1),
            anomaly_signals=signals,
            language_anomaly_score=round(lang_score, 3),
            structural_anomaly_score=round(struct_score, 3),
            behavioral_anomaly_score=round(behav_score, 3),
            domain_novelty_score=round(novelty_score, 3),
            is_potential_zeroday=is_potential_zeroday,
        )

        logger.info(
            "zeroday.scored",
            suspicion=result.suspicion_score,
            is_zeroday=is_potential_zeroday,
            signal_count=len(signals),
        )

        return result

    # ── Sub-scorers ──────────────────────────────────────────────────────

    def _language_anomaly(self, crawl: CrawlResult, url: str) -> tuple[float, list[str]]:
        """Detect language-level anomalies: mixed scripts, homoglyphs, invisible chars."""
        score = 0.0
        signals: list[str] = []
        text = crawl.html_content[:50_000]  # Cap scan length

        # Invisible Unicode characters
        invisible_count = len(_INVISIBLE_CHARS.findall(text))
        if invisible_count > 0:
            score += min(0.4, invisible_count * 0.05)
            signals.append(f"Invisible Unicode characters detected: {invisible_count}")

        # Homoglyph detection in domain
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        homoglyph_count = sum(1 for c in domain if c in _HOMOGLYPH_MAP)
        if homoglyph_count > 0:
            score += min(0.5, homoglyph_count * 0.15)
            signals.append(f"Homoglyph characters in domain: {homoglyph_count}")

        # Mixed script detection in page title + domain
        check_text = f"{domain} {crawl.page_title}"
        scripts_found = set()
        for ch in check_text:
            try:
                script = unicodedata.name(ch, "").split()[0]
                if script not in ("SPACE", "DIGIT", "FULL", "HYPHEN", "LOW", "SOLIDUS"):
                    scripts_found.add(script)
            except (ValueError, IndexError):
                pass
        if len(scripts_found) > 2:
            score += 0.3
            signals.append(f"Mixed Unicode scripts in page: {', '.join(list(scripts_found)[:5])}")

        # Right-to-left override
        if "\u202e" in text or "\u200f" in text:
            score += 0.3
            signals.append("Right-to-left override character detected (text spoofing)")

        return min(1.0, score), signals

    def _structural_anomaly(self, crawl: CrawlResult) -> tuple[float, list[str]]:
        """Detect structural anomalies: obfuscation, unusual DOM patterns."""
        score = 0.0
        signals: list[str] = []
        html = crawl.html_content[:100_000]

        # JavaScript obfuscation density
        eval_count = len(_EVAL_PATTERNS.findall(html))
        if eval_count >= 3:
            score += min(0.4, eval_count * 0.08)
            signals.append(f"High eval/dynamic execution count: {eval_count}")

        # Inline base64 data
        b64_count = len(_BASE64_INLINE.findall(html))
        if b64_count >= 2:
            score += min(0.3, b64_count * 0.05)
            signals.append(f"Inline Base64 encoded data blocks: {b64_count}")

        # Hex-encoded strings
        hex_count = len(_HEX_ENCODED.findall(html))
        if hex_count >= 3:
            score += min(0.3, hex_count * 0.05)
            signals.append(f"Hex-encoded string sequences: {hex_count}")

        # CharCode usage
        if _CHAR_CODE.search(html):
            score += 0.15
            signals.append("String.fromCharCode usage (potential obfuscation)")

        # Empty or near-empty body with scripts (blank page loader)
        body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.DOTALL | re.IGNORECASE)
        if body_match:
            body_text = re.sub(r"<script[^>]*>.*?</script>", "", body_match.group(1), flags=re.DOTALL | re.IGNORECASE)
            body_text = re.sub(r"<[^>]+>", "", body_text).strip()
            if len(body_text) < 50 and len(crawl.scripts) > 2:
                score += 0.35
                signals.append("Near-empty body with multiple scripts (dynamic loader pattern)")

        # Iframe overload
        iframe_count = html.lower().count("<iframe")
        if iframe_count >= 3:
            score += min(0.3, iframe_count * 0.08)
            signals.append(f"Multiple iframes detected: {iframe_count}")

        return min(1.0, score), signals

    def _behavioral_anomaly(
        self, crawl: CrawlResult, behavioral: list[BehavioralSignal]
    ) -> tuple[float, list[str]]:
        """Detect behavioral anomalies from crawl timing and redirect patterns."""
        score = 0.0
        signals: list[str] = []

        # Redirect chain anomalies
        chain_len = len(crawl.redirect_chain)
        if chain_len >= 4:
            score += min(0.4, chain_len * 0.08)
            signals.append(f"Long redirect chain: {chain_len} hops")

        # Cross-domain redirects
        if chain_len > 0:
            domains_in_chain = set()
            for hop in crawl.redirect_chain:
                try:
                    domains_in_chain.add(urlparse(hop.url).netloc.lower())
                except Exception:
                    pass
            if len(domains_in_chain) >= 3:
                score += 0.25
                signals.append(f"Cross-domain redirect chain ({len(domains_in_chain)} domains)")

        # Suspiciously fast or slow page load
        if crawl.load_time_ms > 0:
            if crawl.load_time_ms < 100:
                score += 0.15
                signals.append(f"Suspiciously fast page load: {crawl.load_time_ms}ms")
            elif crawl.load_time_ms > 15000:
                score += 0.15
                signals.append(f"Very slow page load: {crawl.load_time_ms}ms (possible delay tactic)")

        # High-severity behavioral signals from existing analyzer
        high_severity = [s for s in behavioral if s.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
        if len(high_severity) >= 2:
            score += min(0.4, len(high_severity) * 0.1)
            signals.append(f"Multiple high-severity behavioral signals: {len(high_severity)}")

        return min(1.0, score), signals

    def _domain_novelty(
        self,
        url: str,
        domain_intel: DomainIntelligence | None,
        rule_signals: list[RuleSignal],
        brand_matches: list[BrandMatch],
    ) -> tuple[float, list[str]]:
        """Score how novel/suspicious the domain is in combination with other signals."""
        score = 0.0
        signals: list[str] = []

        # Very new domain
        if domain_intel and domain_intel.domain_age_days is not None:
            if domain_intel.domain_age_days <= 7:
                score += 0.5
                signals.append(f"Brand-new domain: {domain_intel.domain_age_days} days old")
            elif domain_intel.domain_age_days <= 30:
                score += 0.3
                signals.append(f"Very young domain: {domain_intel.domain_age_days} days old")
            elif domain_intel.domain_age_days <= 90:
                score += 0.1

        # Suspicious TLD
        if domain_intel and domain_intel.is_suspicious_tld:
            score += 0.2
            signals.append(f"Suspicious TLD: .{domain_intel.tld}")

        # New domain + brand similarity = high novelty suspicion
        not_official = [m for m in brand_matches if not m.is_official and m.similarity_score >= 0.4]
        if not_official and domain_intel and domain_intel.domain_age_days is not None:
            if domain_intel.domain_age_days <= 30:
                score += 0.3
                signals.append(
                    f"New domain resembles {not_official[0].brand_name} "
                    f"(similarity {not_official[0].similarity_score:.2f})"
                )

        # Many rule violations on a new domain
        if domain_intel and domain_intel.domain_age_days is not None and domain_intel.domain_age_days <= 60:
            critical_rules = [s for s in rule_signals if s.severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
            if len(critical_rules) >= 2:
                score += 0.2
                signals.append(
                    f"Multiple critical rule violations on young domain: {len(critical_rules)}"
                )

        return min(1.0, score), signals

    @staticmethod
    def _sigmoid_compress(value: float, midpoint: float = 50, steepness: float = 0.08) -> float:
        """Apply sigmoid compression to avoid overconfident extremes."""
        x = (value - midpoint) * steepness
        return 100.0 / (1.0 + math.exp(-x))
