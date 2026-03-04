"""
Tracker, Spyware, and Malware detection engine.

Scans crawled page data for:
  - Analytics trackers (Google Analytics, Facebook Pixel, Hotjar, etc.)
  - Advertising trackers (DoubleClick, AdSense, Criteo, etc.)
  - Fingerprinting scripts (Canvas, WebGL, AudioContext fingerprinting)
  - Known malware / crypto-mining scripts
  - Suspicious script loading patterns (eval, obfuscation, external injections)
  - Spyware indicators (keyloggers, session recorders, clipboard access)
  - Known tracking domain cross-references
"""

from __future__ import annotations

import re
from typing import Any

from trustlens.core.logging import get_logger
from trustlens.models import CrawlResult, RiskLevel, TrackerDetectionResult, TrackerInfo

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# TRACKER / SCRIPT DATABASES
# ═══════════════════════════════════════════════════════════════════════════════

ANALYTICS_TRACKERS: dict[str, list[str]] = {
    "Google Analytics": ["google-analytics.com/analytics.js", "googletagmanager.com", "gtag(", "ga('send", "UA-", "G-", "analytics.js"],
    "Google Tag Manager": ["googletagmanager.com/gtm.js", "GTM-"],
    "Facebook Pixel": ["connect.facebook.net", "fbq(", "facebook.com/tr", "fb-pixel"],
    "Meta Pixel": ["connect.facebook.net/en_US/fbevents.js"],
    "Hotjar": ["hotjar.com", "hj(", "hjid", "_hjSettings"],
    "Mixpanel": ["mixpanel.com", "mixpanel.track", "mixpanel.init"],
    "Amplitude": ["amplitude.com", "amplitude.getInstance"],
    "Segment": ["segment.com/analytics.js", "analytics.track", "segment.io"],
    "Heap": ["heap-analytics.com", "heap.track"],
    "Matomo/Piwik": ["matomo.", "piwik.", "_paq.push"],
    "Plausible": ["plausible.io"],
    "Fathom": ["usefathom.com", "fathom.trackPageview"],
    "Clarity": ["clarity.ms", "microsoft.com/clarity"],
    "FullStory": ["fullstory.com", "FS.init"],
    "LogRocket": ["logrocket.com", "LogRocket.init"],
    "PostHog": ["posthog.com", "posthog.init"],
    "Snowplow": ["snowplow", "sp.js"],
    "Yandex Metrica": ["mc.yandex.ru", "ym("],
    "Baidu Analytics": ["hm.baidu.com"],
    "Adobe Analytics": ["omniture.com", "sc.omtrdc.net", "adobedtm.com"],
    "Clicky": ["getclicky.com", "clicky.com"],
    "New Relic": ["newrelic.com", "NREUM", "nr-data.net"],
    "Datadog RUM": ["datadoghq.com", "DD_RUM"],
    "Sentry": ["sentry.io", "Sentry.init"],
}

ADVERTISING_TRACKERS: dict[str, list[str]] = {
    "Google AdSense": ["pagead2.googlesyndication.com", "adsbygoogle"],
    "Google Ads": ["googleads.g.doubleclick.net", "googlesyndication"],
    "DoubleClick": ["doubleclick.net", "dcm."],
    "Facebook Ads": ["facebook.com/tr", "fbevents.js"],
    "Amazon Ads": ["amazon-adsystem.com"],
    "Criteo": ["criteo.com", "criteo.net"],
    "AdRoll": ["adroll.com", "d.adroll.com"],
    "Taboola": ["taboola.com", "trc.taboola.com"],
    "Outbrain": ["outbrain.com", "widgets.outbrain.com"],
    "AppNexus": ["appnexus.com", "adnxs.com"],
    "MediaNet": ["media.net", "contextad"],
    "Twitter Ads": ["ads-twitter.com", "static.ads-twitter.com"],
    "LinkedIn Insight": ["snap.licdn.com", "linkedin.com/px"],
    "TikTok Pixel": ["analytics.tiktok.com", "ttq.track"],
    "Pinterest Tag": ["pintrk", "ct.pinterest.com"],
    "Snapchat Pixel": ["sc-static.net/scevent.min.js"],
    "Yahoo/Verizon": ["ads.yahoo.com", "gemini.yahoo.com"],
}

FINGERPRINTING_INDICATORS: list[tuple[str, re.Pattern]] = [
    ("canvas_fingerprint", re.compile(r"(?:canvas|toDataURL|getImageData|measureText).*fingerprint", re.I)),
    ("canvas_toDataURL", re.compile(r"\.toDataURL\s*\(", re.I)),
    ("webgl_fingerprint", re.compile(r"(?:webgl|getExtension|getParameter).*(?:render|vendor|RENDERER|VENDOR)", re.I)),
    ("audio_fingerprint", re.compile(r"(?:AudioContext|OfflineAudioContext|createOscillator).*(?:fingerprint|frequency)", re.I)),
    ("font_detection", re.compile(r"(?:font|detect).*(?:list|enumerate|available|installed)", re.I)),
    ("battery_api", re.compile(r"navigator\.getBattery", re.I)),
    ("connection_info", re.compile(r"navigator\.connection\b", re.I)),
    ("hardware_concurrency", re.compile(r"navigator\.hardwareConcurrency\b", re.I)),
    ("device_memory", re.compile(r"navigator\.deviceMemory\b", re.I)),
    ("screen_fingerprint", re.compile(r"screen\.\w+Depth|screen\.availWidth|screen\.colorDepth", re.I)),
    ("webrtc_leak", re.compile(r"RTCPeerConnection|createDataChannel|createOffer.*sdp", re.I)),
    ("evercookie", re.compile(r"evercookie", re.I)),
    ("supercookie", re.compile(r"supercookie|localStorage.*sessionStorage.*cookie", re.I)),
    ("FingerprintJS", re.compile(r"fingerprint(?:js|2|pro)|fpjs|FingerprintJS", re.I)),
    ("ClientJS", re.compile(r"ClientJS|clientjs", re.I)),
]

MALWARE_INDICATORS: dict[str, list[str]] = {
    "CoinHive (Mining)": ["coinhive.min.js", "coinhive.com", "CoinHive.Anonymous"],
    "CryptoLoot (Mining)": ["cryptoloot.pro", "CryptoLoot.Anonymous"],
    "JSEcoin (Mining)": ["jsecoin.com", "load.jsecoin.com"],
    "CoinImp (Mining)": ["coinimp.com", "Client.Anonymous"],
    "Webmine.pro": ["webmine.pro", "webmine.cz"],
    "MineroPool": ["minero.cc", "mineropool"],
    "DeepMiner": ["deepminer.js", "deepMiner.Anonymous"],
    "Crypto-Loot": ["crypto-loot.com", "crypta.js"],
    "Cloudflare IPFS Abuse": ["cf-ipfs.com/ipfs"],
    "Magecart (Card Skimmer)": ["gafrede", "sfrfrde", "gfrdes", "grfrde", "googlefr", "jquerycdn.su"],
    "Inter Skimmer": ["inter.js", "cdn-inter.com"],
    "FormJacker": ["formjacker", "formstealer"],
}

KNOWN_MALWARE_DOMAINS: list[str] = [
    "coinhive.com", "cryptoloot.pro", "jsecoin.com", "coinimp.com",
    "webmine.pro", "minero.cc", "deepminer.js", "crypto-loot.com",
    "coin-service.com", "load.jsecoin.com", "afminer.com",
    "miner.pr0gramm.com", "minr.pw", "cnt.statistic.date",
    "jquerycdn.su", "gafrede.com", "sfrfrde.com", "gfrdes.com",
    "grfrde.com", "googlefr.com", "anfrfrde.com",
    "evil.js", "malware-traffic.com",
]

SPYWARE_INDICATORS: list[tuple[str, re.Pattern]] = [
    ("keylogger", re.compile(r"(?:keylog|key[\s_-]?(?:log|capture|record|stroke))", re.I)),
    ("keyboard_capture", re.compile(r"(?:addEventListener|attachEvent)\s*\(\s*['\"]key(?:down|up|press)['\"]", re.I)),
    ("clipboard_access", re.compile(r"navigator\.clipboard|document\.execCommand\s*\(\s*['\"](?:copy|paste)['\"]", re.I)),
    ("clipboard_listener", re.compile(r"addEventListener\s*\(\s*['\"](?:copy|paste|cut)['\"]", re.I)),
    ("screen_capture", re.compile(r"getDisplayMedia|captureStream|MediaRecorder", re.I)),
    ("camera_access", re.compile(r"getUserMedia.*video|navigator\.mediaDevices", re.I)),
    ("microphone_access", re.compile(r"getUserMedia.*audio", re.I)),
    ("geolocation_tracking", re.compile(r"navigator\.geolocation\.(?:watchPosition|getCurrentPosition)", re.I)),
    ("session_recording", re.compile(r"(?:session|mouse)[\s_-]?(?:record|replay|capture)", re.I)),
    ("form_grabber", re.compile(r"querySelector.*(?:input|form).*value.*(?:send|post|fetch|XMLHttpRequest)", re.I)),
    ("data_exfiltration", re.compile(r"(?:btoa|atob|Base64|encode).*(?:fetch|XMLHttpRequest|sendBeacon)", re.I)),
]

SUSPICIOUS_SCRIPT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("eval_usage", re.compile(r"\beval\s*\(", re.I)),
    ("document_write", re.compile(r"document\.write\s*\(", re.I)),
    ("base64_decode", re.compile(r"atob\s*\(|base64[_-]?decode", re.I)),
    ("string_fromcharcode", re.compile(r"String\.fromCharCode\s*\(", re.I)),
    ("obfuscated_hex", re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}", re.I)),
    ("packed_code", re.compile(r"p,a,c,k,e,d|eval\s*\(\s*function\s*\(\s*p", re.I)),
    ("dynamic_script_injection", re.compile(r"createElement\s*\(\s*['\"]script['\"].*?\.src\s*=", re.I)),
    ("iframe_injection", re.compile(r"createElement\s*\(\s*['\"]iframe['\"].*?(?:display\s*[:=]\s*['\"]?none|visibility\s*[:=]\s*['\"]?hidden)", re.I)),
    ("beacon_exfil", re.compile(r"navigator\.sendBeacon\s*\(", re.I)),
    ("websocket_c2", re.compile(r"new\s+WebSocket\s*\(\s*['\"]wss?://", re.I)),
]


class TrackerDetector:
    """Detect trackers, fingerprinting scripts, malware, and spyware in crawled page data."""

    async def analyze(self, crawl: CrawlResult, url: str) -> TrackerDetectionResult:
        """Analyze the crawled page for trackers, malware, and privacy threats."""
        result = TrackerDetectionResult()
        html = crawl.html_content
        scripts_text = " ".join(crawl.scripts)
        combined = html + " " + scripts_text

        # 1. Analytics trackers
        self._detect_category(combined, ANALYTICS_TRACKERS, "analytics", result)

        # 2. Advertising trackers
        self._detect_category(combined, ADVERTISING_TRACKERS, "advertising", result)

        # 3. Fingerprinting scripts
        self._detect_fingerprinting(combined, result)

        # 4. Malware / mining scripts
        self._detect_malware(combined, crawl, result)

        # 5. Spyware indicators
        self._detect_spyware(combined, result)

        # 6. Suspicious script patterns
        self._detect_suspicious_scripts(combined, result)

        # 7. Check against known malware domains
        self._check_malware_domains(crawl, result)

        # 8. Compute totals and risk
        self._compute_totals(result)

        logger.info(
            "tracker_detector.completed",
            url=url,
            total_trackers=result.total_trackers,
            categories=dict(result.categories),
            risk=result.risk_level.value,
        )
        return result

    def _detect_category(
        self,
        text: str,
        database: dict[str, list[str]],
        category: str,
        result: TrackerDetectionResult,
    ) -> None:
        """Detect trackers from a given category database."""
        text_lower = text.lower()
        for tracker_name, patterns in database.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    tracker = TrackerInfo(
                        name=tracker_name,
                        category=category,
                        severity=RiskLevel.LOW if category == "analytics" else RiskLevel.MEDIUM,
                        description=f"{category.title()} tracker detected",
                    )
                    result.trackers.append(tracker)
                    if category == "analytics":
                        if tracker_name not in result.analytics_trackers:
                            result.analytics_trackers.append(tracker_name)
                    elif category == "advertising":
                        if tracker_name not in result.advertising_trackers:
                            result.advertising_trackers.append(tracker_name)
                    result.signals.append(f"{category.title()} tracker: {tracker_name}")
                    break  # Only detect each tracker once

    def _detect_fingerprinting(self, text: str, result: TrackerDetectionResult) -> None:
        """Detect browser fingerprinting scripts."""
        for fp_name, pattern in FINGERPRINTING_INDICATORS:
            if pattern.search(text):
                tracker = TrackerInfo(
                    name=fp_name,
                    category="fingerprinting",
                    severity=RiskLevel.MEDIUM,
                    description=f"Browser fingerprinting technique: {fp_name}",
                )
                result.trackers.append(tracker)
                if fp_name not in result.fingerprinting_scripts:
                    result.fingerprinting_scripts.append(fp_name)
                result.signals.append(f"Fingerprinting: {fp_name}")

    def _detect_malware(self, text: str, crawl: CrawlResult, result: TrackerDetectionResult) -> None:
        """Detect known malware and crypto-mining scripts."""
        text_lower = text.lower()
        for malware_name, patterns in MALWARE_INDICATORS.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    tracker = TrackerInfo(
                        name=malware_name,
                        category="malware" if "Skim" in malware_name or "Jack" in malware_name else "mining",
                        severity=RiskLevel.CRITICAL,
                        description=f"Malicious script: {malware_name}",
                    )
                    result.trackers.append(tracker)
                    category = tracker.category
                    if category == "malware":
                        if malware_name not in result.malware_scripts:
                            result.malware_scripts.append(malware_name)
                    else:
                        if malware_name not in result.mining_scripts:
                            result.mining_scripts.append(malware_name)
                    result.signals.append(f"MALWARE/MINING DETECTED: {malware_name}")
                    break

    def _detect_spyware(self, text: str, result: TrackerDetectionResult) -> None:
        """Detect spyware-like behavior patterns."""
        for spy_name, pattern in SPYWARE_INDICATORS:
            if pattern.search(text):
                tracker = TrackerInfo(
                    name=spy_name,
                    category="spyware",
                    severity=RiskLevel.HIGH,
                    description=f"Spyware behavior: {spy_name}",
                )
                result.trackers.append(tracker)
                if spy_name not in result.known_spyware:
                    result.known_spyware.append(spy_name)
                result.signals.append(f"Spyware: {spy_name}")

    def _detect_suspicious_scripts(self, text: str, result: TrackerDetectionResult) -> None:
        """Detect suspicious script patterns that could indicate malicious intent."""
        for pattern_name, pattern in SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.search(text):
                tracker = TrackerInfo(
                    name=pattern_name,
                    category="suspicious",
                    severity=RiskLevel.MEDIUM,
                    description=f"Suspicious script pattern: {pattern_name}",
                )
                result.trackers.append(tracker)
                if pattern_name not in result.suspicious_scripts:
                    result.suspicious_scripts.append(pattern_name)
                result.signals.append(f"Suspicious pattern: {pattern_name}")

    def _check_malware_domains(self, crawl: CrawlResult, result: TrackerDetectionResult) -> None:
        """Check external links and script sources against known malware domains."""
        # Check script sources
        for script_src in crawl.scripts:
            for domain in KNOWN_MALWARE_DOMAINS:
                if domain in script_src.lower():
                    tracker = TrackerInfo(
                        name=f"Malware domain: {domain}",
                        category="malware",
                        url=script_src,
                        severity=RiskLevel.CRITICAL,
                        description=f"Script loaded from known malware domain: {domain}",
                    )
                    result.trackers.append(tracker)
                    if domain not in result.malware_scripts:
                        result.malware_scripts.append(domain)
                    result.signals.append(f"MALWARE DOMAIN: {domain}")

        # Check external links
        for link in crawl.external_links:
            for domain in KNOWN_MALWARE_DOMAINS:
                if domain in link.lower():
                    result.signals.append(f"Link to malware domain: {domain}")

    def _compute_totals(self, result: TrackerDetectionResult) -> None:
        """Compute category totals and overall privacy score."""
        # Category counts
        categories: dict[str, int] = {}
        for tracker in result.trackers:
            categories[tracker.category] = categories.get(tracker.category, 0) + 1
        result.categories = categories
        result.total_trackers = len(result.trackers)

        # Privacy score computation
        score = 100.0
        score -= len(result.analytics_trackers) * 3         # -3 per analytics tracker
        score -= len(result.advertising_trackers) * 5        # -5 per ad tracker
        score -= len(result.fingerprinting_scripts) * 8      # -8 per fingerprinting
        score -= len(result.malware_scripts) * 30            # -30 per malware
        score -= len(result.mining_scripts) * 25             # -25 per miner
        score -= len(result.known_spyware) * 15              # -15 per spyware
        score -= len(result.suspicious_scripts) * 5          # -5 per suspicious pattern
        result.privacy_score = max(0.0, min(100.0, score))

        # Determine risk level
        if result.malware_scripts or result.mining_scripts:
            result.risk_level = RiskLevel.CRITICAL
        elif result.known_spyware:
            result.risk_level = RiskLevel.HIGH
        elif result.fingerprinting_scripts or len(result.advertising_trackers) > 3:
            result.risk_level = RiskLevel.MEDIUM
        elif result.total_trackers > 5:
            result.risk_level = RiskLevel.LOW
        else:
            result.risk_level = RiskLevel.SAFE
