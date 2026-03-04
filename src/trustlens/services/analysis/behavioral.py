"""
Behavioral redirect & runtime analysis.

Analyzes redirect chains, timing patterns, and page behavior for
evasion / deception signals. This complements the rule engine by
focusing specifically on dynamic behavioral patterns.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from trustlens.core.logging import get_logger
from trustlens.models import BehavioralSignal, CrawlResult, RiskLevel
from trustlens.security import extract_domain

logger = get_logger(__name__)


class BehavioralAnalyzer:
    """Analyze page/redirect behavior for evasion and deception."""

    async def analyze(self, crawl: CrawlResult, original_url: str) -> list[BehavioralSignal]:
        """Run all behavioral checks."""
        signals: list[BehavioralSignal] = []

        signals.extend(self._analyze_redirects(crawl, original_url))
        signals.extend(self._analyze_page_behavior(crawl))
        signals.extend(self._analyze_timing(crawl))
        signals.extend(self._analyze_evasion_techniques(crawl))

        logger.info("behavioral_analyzer.completed", total_signals=len(signals))
        return signals

    def _analyze_redirects(self, crawl: CrawlResult, original_url: str) -> list[BehavioralSignal]:
        """Deep redirect chain analysis."""
        signals = []
        chain = crawl.redirect_chain

        if not chain:
            return signals

        # JavaScript-based redirect detection
        html_lower = crawl.html_content.lower()
        js_redirect_patterns = [
            r"window\.location\s*=",
            r"window\.location\.href\s*=",
            r"window\.location\.replace\(",
            r"document\.location\s*=",
            r"meta\s+http-equiv\s*=\s*[\"']refresh",
            r"window\.navigate\(",
        ]
        js_redirects_found = []
        for pattern in js_redirect_patterns:
            if re.search(pattern, html_lower):
                js_redirects_found.append(pattern.replace("\\", ""))

        if js_redirects_found:
            signals.append(
                BehavioralSignal(
                    signal_type="js_redirect",
                    description="Page contains JavaScript-based redirect mechanisms",
                    severity=RiskLevel.MEDIUM,
                    evidence=f"Patterns: {', '.join(js_redirects_found[:3])}",
                    score_impact=15.0,
                )
            )

        # URL shortener / tracker detection
        shortener_domains = {
            "bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly",
            "is.gd", "buff.ly", "short.link", "rebrand.ly",
        }
        for hop in chain:
            hop_domain = extract_domain(hop.url).lower()
            if hop_domain in shortener_domains:
                signals.append(
                    BehavioralSignal(
                        signal_type="url_shortener",
                        description=f"Redirect chain passes through URL shortener: {hop_domain}",
                        severity=RiskLevel.LOW,
                        evidence=hop.url[:100],
                        score_impact=8.0,
                    )
                )
                break

        # Suspicious query parameter forwarding (e.g., email in URL)
        for hop in chain:
            parsed = urlparse(hop.url)
            params = parse_qs(parsed.query)
            suspicious_params = {
                k for k in params
                if any(s in k.lower() for s in ["email", "user", "login", "token", "session"])
            }
            if suspicious_params:
                signals.append(
                    BehavioralSignal(
                        signal_type="sensitive_params",
                        description="Redirect chain passes sensitive parameters",
                        severity=RiskLevel.MEDIUM,
                        evidence=f"Params: {', '.join(suspicious_params)}",
                        score_impact=12.0,
                    )
                )
                break

        return signals

    def _analyze_page_behavior(self, crawl: CrawlResult) -> list[BehavioralSignal]:
        """Analyze page-level behavioral signals."""
        signals = []
        html_lower = crawl.html_content.lower()

        # Right-click / copy disabled (anti-analysis)
        anti_analysis = [
            (r"oncontextmenu\s*=\s*[\"']return\s+false", "right-click disabled"),
            (r"onselectstart\s*=\s*[\"']return\s+false", "text selection disabled"),
            (r"onkeydown.*?F12", "F12 key blocked"),
            (r"devtools", "devtools detection"),
        ]
        for pattern, desc in anti_analysis:
            if re.search(pattern, html_lower):
                signals.append(
                    BehavioralSignal(
                        signal_type="anti_analysis",
                        description=f"Anti-analysis technique detected: {desc}",
                        severity=RiskLevel.MEDIUM,
                        evidence=desc,
                        score_impact=15.0,
                    )
                )

        # Countdown timers / urgency mechanisms
        if re.search(r"countdown|timer|setTimeout.*redirect|setInterval.*redirect", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="countdown",
                    description="Page contains countdown/timer-based mechanisms",
                    severity=RiskLevel.MEDIUM,
                    evidence="Timed urgency mechanism detected",
                    score_impact=10.0,
                )
            )

        # Auto-submit forms
        if re.search(r"\.submit\(\)|autosubmit|auto-submit", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="auto_submit",
                    description="Page appears to auto-submit forms",
                    severity=RiskLevel.HIGH,
                    evidence="Form auto-submission detected",
                    score_impact=25.0,
                )
            )

        # Clipboard manipulation
        if re.search(r"navigator\.clipboard|execCommand.*copy|clipboardData", html_lower):
            signals.append(
                BehavioralSignal(
                    signal_type="clipboard_access",
                    description="Page attempts to access the clipboard",
                    severity=RiskLevel.MEDIUM,
                    evidence="Clipboard API usage detected",
                    score_impact=10.0,
                )
            )

        return signals

    def _analyze_timing(self, crawl: CrawlResult) -> list[BehavioralSignal]:
        """Analyze timing-related signals."""
        signals = []

        # Very fast load might indicate a simple phishing page
        if crawl.load_time_ms > 0 and crawl.load_time_ms < 200 and len(crawl.html_content) < 5000:
            signals.append(
                BehavioralSignal(
                    signal_type="fast_simple_page",
                    description="Very fast load time with minimal content (typical of phishing pages)",
                    severity=RiskLevel.LOW,
                    evidence=f"Load time: {crawl.load_time_ms}ms, HTML size: {len(crawl.html_content)} bytes",
                    score_impact=5.0,
                )
            )

        return signals

    def _analyze_evasion_techniques(self, crawl: CrawlResult) -> list[BehavioralSignal]:
        """Detect common phishing evasion techniques."""
        signals = []
        html_lower = crawl.html_content.lower()

        # Base64 encoded content
        import re as re_mod
        b64_count = len(re_mod.findall(r"data:image/[^;]+;base64,", html_lower))
        if b64_count > 5:
            signals.append(
                BehavioralSignal(
                    signal_type="excessive_base64",
                    description=f"Page embeds {b64_count} base64-encoded images (evasion technique)",
                    severity=RiskLevel.MEDIUM,
                    evidence=f"{b64_count} base64 images found",
                    score_impact=12.0,
                )
            )

        # Obfuscated JavaScript
        obfuscation_patterns = [
            (r"eval\s*\(\s*atob\s*\(", "eval(atob()) – base64 JS execution"),
            (r"eval\s*\(\s*unescape\s*\(", "eval(unescape()) – URL-encoded JS"),
            (r"String\.fromCharCode", "String.fromCharCode – char code obfuscation"),
            (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "hex-encoded strings"),
        ]
        for pattern, desc in obfuscation_patterns:
            if re.search(pattern, html_lower):
                signals.append(
                    BehavioralSignal(
                        signal_type="js_obfuscation",
                        description=f"JavaScript obfuscation detected: {desc}",
                        severity=RiskLevel.HIGH,
                        evidence=desc,
                        score_impact=20.0,
                    )
                )

        return signals
