"""
Download & Permission Threat Detector.

Scans crawled page data for:
  - Auto-download triggers (Content-Disposition, meta refresh downloads, JS downloads)
  - Download links to dangerous file types (.exe, .msi, .scr, .bat, .cmd, .ps1, etc.)
  - Drive-by download patterns (hidden iframes, obfuscated script downloads)
  - Excessive browser permission requests (camera, microphone, geolocation, notifications, clipboard)
  - Web Push / Notification spam patterns
  - Clipboard hijacking (document.execCommand('copy'), navigator.clipboard)
  - Suspicious blob/data URL usage for payload delivery
  - Hidden or deceptive download buttons
  - Software bundling / PUP (Potentially Unwanted Program) indicators
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, unquote

from trustlens.core.logging import get_logger
from trustlens.models import CrawlResult, DownloadThreatResult, RiskLevel

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# DANGEROUS FILE EXTENSIONS
# ═══════════════════════════════════════════════════════════════════════════════

# High-risk: directly executable
DANGEROUS_EXTENSIONS_HIGH: set[str] = {
    ".exe", ".msi", ".scr", ".pif", ".cmd", ".bat", ".com", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".psd1",
    ".msp", ".mst", ".cpl", ".hta", ".inf", ".ins", ".isp", ".reg",
    ".rgs", ".sct", ".shb", ".shs", ".ws", ".wsc", ".lnk", ".appref-ms",
    ".action", ".command", ".osx", ".workflow",  # macOS
    ".deb", ".rpm", ".sh", ".run", ".bin", ".elf",  # Linux
    ".apk", ".xapk", ".aab",  # Android
    ".ipa",  # iOS side-loading
}

# Medium-risk: archives, disk images, macros
DANGEROUS_EXTENSIONS_MEDIUM: set[str] = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab",
    ".iso", ".img", ".dmg", ".vhd", ".vmdk",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm",  # Office macros
    ".jar", ".jnlp",  # Java
    ".swf", ".fla",  # Flash
    ".dll", ".sys", ".drv", ".ocx",  # Windows system
    ".torrent", ".crx", ".xpi",  # Browser extensions / torrents
    ".svg",  # Can contain JS
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-DOWNLOAD / DRIVE-BY DOWNLOAD PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

AUTO_DOWNLOAD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # JavaScript-triggered downloads
    ("js_blob_download", re.compile(
        r"(?:URL\.createObjectURL|window\.URL\.createObjectURL)\s*\(.*?(?:Blob|File)", re.I | re.S)),
    ("js_download_click", re.compile(
        r"\.(?:download|click)\s*\(\s*\).*?(?:createElement\s*\(\s*['\"]a['\"]\s*\)|\.href\s*=)", re.I | re.S)),
    ("js_save_as", re.compile(
        r"(?:saveAs|FileSaver|download)\s*\(.*?(?:blob|Blob|arraybuffer|ArrayBuffer)", re.I | re.S)),
    ("js_location_download", re.compile(
        r"(?:window\.)?location\s*(?:\.href)?\s*=\s*['\"](?:data:|blob:)", re.I)),
    ("navigator_msSaveBlob", re.compile(
        r"navigator\.msSaveBlob|navigator\.msSaveOrOpenBlob", re.I)),

    # Meta refresh with download
    ("meta_refresh_download", re.compile(
        r"<meta[^>]+http-equiv\s*=\s*['\"]refresh['\"][^>]+url\s*=\s*['\"]?[^'\"]*\.(?:exe|msi|zip|dmg|apk|bat|cmd|ps1)", re.I)),

    # Hidden iframe loading executables
    ("hidden_iframe_download", re.compile(
        r"<iframe[^>]*(?:style\s*=\s*['\"][^'\"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)|hidden)[^>]*src\s*=\s*['\"][^'\"]*\.(?:exe|msi|zip|dmg|apk|scr|bat)", re.I)),

    # Object/embed tags loading executables
    ("object_embed_download", re.compile(
        r"<(?:object|embed)[^>]*(?:data|src)\s*=\s*['\"][^'\"]*\.(?:exe|msi|zip|scr|bat|cmd|hta|jar)", re.I)),

    # Deceptive download patterns
    ("fake_update_download", re.compile(
        r"(?:your\s+(?:browser|flash|java|system|computer|device)\s+(?:is\s+)?(?:out\s+of\s+date|needs?\s+(?:an?\s+)?update|requires?\s+(?:an?\s+)?update))", re.I)),
    ("fake_scan_download", re.compile(
        r"(?:virus(?:es)?\s+(?:detected|found)|threat(?:s)?\s+(?:detected|found)|your\s+(?:computer|device|system)\s+is\s+infected)", re.I)),
    ("fake_codec_download", re.compile(
        r"(?:(?:media|video)\s+(?:player|codec)\s+(?:required|needed|not\s+found)|install\s+(?:codec|plugin|player)\s+to\s+(?:view|play|watch))", re.I)),

    # Service Worker registration (can intercept all requests)
    ("service_worker_registration", re.compile(
        r"navigator\.serviceWorker\.register\s*\(", re.I)),

    # eval-based payload delivery
    ("eval_payload", re.compile(
        r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(", re.I)),
]


# ═══════════════════════════════════════════════════════════════════════════════
# PERMISSION REQUEST PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

PERMISSION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Geolocation
    ("geolocation", "Location Access", re.compile(
        r"navigator\.geolocation\.(?:getCurrentPosition|watchPosition)", re.I)),

    # Camera / Microphone
    ("camera_microphone", "Camera/Microphone Access", re.compile(
        r"(?:navigator\.mediaDevices\.getUserMedia|navigator\.getUserMedia|"
        r"webkitGetUserMedia|mozGetUserMedia|msGetUserMedia)", re.I)),

    # Notifications
    ("notifications", "Push Notifications", re.compile(
        r"(?:Notification\.requestPermission|PushManager\.subscribe|"
        r"ServiceWorkerRegistration\.pushManager)", re.I)),

    # Clipboard
    ("clipboard_read", "Clipboard Read Access", re.compile(
        r"navigator\.clipboard\.(?:read|readText)", re.I)),
    ("clipboard_write", "Clipboard Write/Hijack", re.compile(
        r"(?:navigator\.clipboard\.(?:write|writeText)|"
        r"document\.execCommand\s*\(\s*['\"]copy['\"]|"
        r"oncopy\s*=|addEventListener\s*\(\s*['\"]copy['\"])", re.I)),

    # Screen capture
    ("screen_capture", "Screen Capture", re.compile(
        r"(?:navigator\.mediaDevices\.getDisplayMedia|"
        r"navigator\.getDisplayMedia|screen\.capture)", re.I)),

    # Bluetooth
    ("bluetooth", "Bluetooth Access", re.compile(
        r"navigator\.bluetooth\.requestDevice", re.I)),

    # USB
    ("usb", "USB Device Access", re.compile(
        r"navigator\.usb\.requestDevice", re.I)),

    # Serial port
    ("serial", "Serial Port Access", re.compile(
        r"navigator\.serial\.requestPort", re.I)),

    # HID (Human Interface Device)
    ("hid", "HID Device Access", re.compile(
        r"navigator\.hid\.requestDevice", re.I)),

    # File System Access API (can read/write local files)
    ("file_system", "File System Access", re.compile(
        r"(?:window\.showOpenFilePicker|window\.showSaveFilePicker|"
        r"window\.showDirectoryPicker|FileSystemFileHandle|"
        r"FileSystemDirectoryHandle)", re.I)),

    # Payment Request API (could be legitimate but worth flagging)
    ("payment_request", "Payment Request API", re.compile(
        r"new\s+PaymentRequest\s*\(", re.I)),

    # Idle detection
    ("idle_detection", "Idle Detection", re.compile(
        r"IdleDetector\.requestPermission", re.I)),

    # Wake Lock (keeps screen on)
    ("wake_lock", "Wake Lock", re.compile(
        r"navigator\.wakeLock\.request", re.I)),

    # Sensor access
    ("sensors", "Sensor Access", re.compile(
        r"(?:Accelerometer|Gyroscope|Magnetometer|AbsoluteOrientationSensor|"
        r"AmbientLightSensor)\s*\(", re.I)),
]


# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION SPAM PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

NOTIFICATION_SPAM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("allow_button_trick", re.compile(
        r"(?:click\s+(?:allow|accept|continue|ok)\s+(?:to|button)|"
        r"press\s+(?:allow|accept)\s+to\s+(?:continue|proceed|verify|access|watch))", re.I)),
    ("robot_verification", re.compile(
        r"(?:click\s+allow\s+(?:to\s+)?(?:verify|confirm|prove)\s+(?:you\s+are|you're)\s+(?:not\s+a\s+)?(?:robot|bot|human)|"
        r"I\s*(?:am|'m)\s+not\s+a\s+robot.*allow)", re.I)),
    ("age_verification_trick", re.compile(
        r"(?:click\s+allow\s+(?:to\s+)?(?:verify|confirm)\s+(?:you\s+are|your)\s+(?:age|18\+|21\+|adult))", re.I)),
    ("subscription_spam", re.compile(
        r"(?:subscribe\s+to\s+(?:push\s+)?notifications?\s+(?:for|to\s+receive)\s+(?:updates?|news|deals?|offers?))", re.I)),
    ("notification_overlay", re.compile(
        r"(?:notification.*(?:enable|allow|subscribe|turn\s+on)|"
        r"(?:enable|allow|subscribe|turn\s+on).*notification)", re.I)),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SOFTWARE BUNDLING / PUP INDICATORS
# ═══════════════════════════════════════════════════════════════════════════════

PUP_INDICATORS: list[tuple[str, re.Pattern[str]]] = [
    ("custom_install", re.compile(
        r"(?:custom|advanced)\s+(?:install(?:ation)?|setup).*(?:recommend|default|express|typical)", re.I)),
    ("bundled_software", re.compile(
        r"(?:also\s+install|bundled\s+with|includes?\s+(?:free|bonus)|optional\s+(?:software|offers?|programs?))", re.I)),
    ("toolbar_offer", re.compile(
        r"(?:install\s+(?:our\s+)?(?:toolbar|extension|add-on|browser\s+helper)|"
        r"(?:toolbar|extension|add-on)\s+(?:will|may)\s+be\s+installed)", re.I)),
    ("homepage_change", re.compile(
        r"(?:set\s+(?:as\s+)?(?:my\s+)?(?:home\s*page|default\s+(?:search|browser))|"
        r"change\s+(?:your\s+)?(?:home\s*page|default\s+(?:search|browser)))", re.I)),
    ("adware_indicator", re.compile(
        r"(?:powered\s+by\s+ads|ad[\s-]?supported|special\s+offers|partner\s+offers)", re.I)),
]


# ═══════════════════════════════════════════════════════════════════════════════
# SAFE EXTENSIONS / TLDs — NOT dangerous file types
# ═══════════════════════════════════════════════════════════════════════════════

_COMMON_TLDS: set[str] = {
    ".com", ".org", ".net", ".edu", ".gov", ".mil", ".int",
    ".io", ".co", ".me", ".us", ".uk", ".de", ".fr", ".jp", ".cn",
    ".in", ".ru", ".br", ".au", ".ca", ".it", ".nl", ".es", ".se",
    ".ch", ".at", ".be", ".pl", ".cz", ".info", ".biz", ".tv", ".cc",
    ".app", ".dev", ".ai", ".xyz", ".online", ".site", ".tech", ".store",
    ".cloud", ".space", ".live", ".pro", ".page", ".blog", ".shop",
    ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".do", ".cgi",
    ".shtml", ".xhtml", ".cfm", ".py", ".rb", ".json", ".xml",
    ".css", ".scss", ".less", ".txt", ".md", ".csv", ".tsv", ".yaml",
    ".yml", ".toml", ".cfg", ".conf", ".ini", ".log", ".ico", ".png",
    ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".pdf", ".doc",
    ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp",
    ".rtf", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm",
    ".wav", ".ogg", ".flac", ".aac", ".m4a",
}


class DownloadThreatDetector:
    """Detect auto-downloads, dangerous file downloads, permission abuse, and drive-by threats."""

    async def analyze(self, crawl: CrawlResult, url: str) -> DownloadThreatResult:
        """Analyze the crawled page for download & permission threats."""
        result = DownloadThreatResult()
        html = crawl.html_content
        scripts_text = " ".join(crawl.scripts)
        page_text = (crawl.page_title + " " + html).lower()

        # 1. Check response headers for auto-download
        self._check_headers(crawl, result)

        # 2. Detect download links to dangerous files
        self._detect_download_links(crawl, html, result)

        # 3. Detect auto-download / drive-by download patterns
        self._detect_auto_downloads(html, scripts_text, result)

        # 4. Detect permission requests
        self._detect_permissions(html, scripts_text, result)

        # 5. Detect notification spam / social engineering
        self._detect_notification_spam(html, page_text, result)

        # 6. Detect PUP / software bundling
        self._detect_pup_indicators(html, page_text, result)

        # 7. Compute overall risk
        self._compute_risk(result)

        logger.info(
            "download_threat_detector.completed",
            url=url,
            download_links=len(result.download_links),
            auto_downloads=len(result.auto_download_triggers),
            permissions_requested=len(result.permissions_requested),
            risk=result.risk_level.value,
        )

        return result

    def _check_headers(self, crawl: CrawlResult, result: DownloadThreatResult) -> None:
        """Check response headers for auto-download (Content-Disposition: attachment)."""
        headers = crawl.headers
        cd = headers.get("content-disposition", "")
        ct = headers.get("content-type", "")

        if "attachment" in cd.lower():
            filename = ""
            match = re.search(r'filename\s*=\s*"?([^";]+)', cd, re.I)
            if match:
                filename = unquote(match.group(1).strip())
            result.auto_download_triggers.append(
                f"Content-Disposition: attachment (filename: {filename or 'unknown'})"
            )
            result.has_auto_download = True
            result.signals.append(
                f"Server forces file download via Content-Disposition header"
                + (f": {filename}" if filename else "")
            )

            ext = self._get_extension(filename)
            if ext in DANGEROUS_EXTENSIONS_HIGH:
                result.dangerous_file_types.append(f"HIGH-RISK: {filename} ({ext})")
                result.signals.append(f"CRITICAL: Auto-download of high-risk executable: {filename}")
            elif ext in DANGEROUS_EXTENSIONS_MEDIUM:
                result.dangerous_file_types.append(f"MEDIUM-RISK: {filename} ({ext})")
                result.signals.append(f"Warning: Auto-download of potentially dangerous archive/macro: {filename}")

        # Check for application/octet-stream with no obvious reason
        if "application/octet-stream" in ct.lower() and "attachment" not in cd.lower():
            result.signals.append(
                "Content-Type is application/octet-stream (binary download) without Content-Disposition"
            )
            result.has_auto_download = True

    def _detect_download_links(self, crawl: CrawlResult, html: str, result: DownloadThreatResult) -> None:
        """Detect links pointing to dangerous file types."""
        # Find all <a> tags with href or download attribute
        link_pattern = re.compile(
            r'<a\s[^>]*?(?:href|download)\s*=\s*["\']([^"\']+)["\'][^>]*?>',
            re.I | re.S,
        )

        seen: set[str] = set()
        for match in link_pattern.finditer(html):
            href = match.group(1).strip()
            if href in seen or href.startswith("#") or href.startswith("javascript:"):
                continue
            # Skip non-downloadable schemes
            if href.startswith("mailto:") or href.startswith("tel:") or href.startswith("data:text/"):
                continue
            seen.add(href)

            ext = self._get_extension(href)
            if ext in DANGEROUS_EXTENSIONS_HIGH:
                result.download_links.append(href[:200])
                result.dangerous_file_types.append(f"HIGH-RISK: {ext}")
                result.signals.append(f"Download link to high-risk file type: {ext} ({self._truncate_url(href)})")
            elif ext in DANGEROUS_EXTENSIONS_MEDIUM:
                result.download_links.append(href[:200])
                result.dangerous_file_types.append(f"MEDIUM-RISK: {ext}")
                result.signals.append(f"Download link to medium-risk file type: {ext} ({self._truncate_url(href)})")

        # Check for `download` attribute in <a> tags (forces download regardless of type)
        download_attr_pattern = re.compile(
            r'<a\s[^>]*?download(?:\s*=\s*["\']([^"\']*)["\'])?\s[^>]*?>',
            re.I | re.S,
        )
        for match in download_attr_pattern.finditer(html):
            result.has_auto_download = True
            fname = match.group(1) or "unnamed"
            ext = self._get_extension(fname)
            if ext in DANGEROUS_EXTENSIONS_HIGH or ext in DANGEROUS_EXTENSIONS_MEDIUM:
                result.auto_download_triggers.append(f"HTML download attribute (filename: {fname})")

        # Check for data: URIs with dangerous content
        data_uri_pattern = re.compile(
            r'(?:href|src)\s*=\s*["\']data:application/(?:octet-stream|x-msdownload|x-executable|x-dosexec)',
            re.I,
        )
        for _ in data_uri_pattern.finditer(html):
            result.has_auto_download = True
            result.auto_download_triggers.append("Data URI with executable MIME type")
            result.signals.append("Data URI containing executable content detected")

    def _detect_auto_downloads(self, html: str, scripts_text: str, result: DownloadThreatResult) -> None:
        """Detect JavaScript-based auto-download and drive-by patterns."""
        combined = html + "\n" + scripts_text

        for pattern_name, pattern in AUTO_DOWNLOAD_PATTERNS:
            matches = pattern.findall(combined)
            if matches:
                result.auto_download_triggers.append(pattern_name)
                result.has_auto_download = True

                desc = pattern_name.replace("_", " ").title()
                if pattern_name.startswith("fake_"):
                    result.signals.append(f"DECEPTIVE: {desc} — social engineering download trick")
                elif pattern_name == "eval_payload":
                    result.signals.append("Obfuscated eval() payload delivery detected")
                elif pattern_name == "service_worker_registration":
                    result.signals.append("Service Worker registration — can intercept/modify all network requests")
                elif pattern_name == "hidden_iframe_download":
                    result.signals.append("Hidden iframe loading executable file — drive-by download attempt")
                else:
                    result.signals.append(f"Auto-download pattern detected: {desc}")

    def _detect_permissions(self, html: str, scripts_text: str, result: DownloadThreatResult) -> None:
        """Detect browser API permission requests."""
        combined = html + "\n" + scripts_text

        for perm_id, perm_label, pattern in PERMISSION_PATTERNS:
            if pattern.search(combined):
                result.permissions_requested.append(perm_label)
                result.permission_details.append({
                    "permission": perm_id,
                    "label": perm_label,
                    "risk": "high" if perm_id in (
                        "camera_microphone", "clipboard_read", "screen_capture",
                        "bluetooth", "usb", "serial", "hid", "file_system"
                    ) else "medium",
                })
                result.signals.append(f"Permission request: {perm_label}")

    def _detect_notification_spam(self, html: str, page_text: str, result: DownloadThreatResult) -> None:
        """Detect notification spam and social engineering permission tricks."""
        combined = html + "\n" + page_text

        for pattern_name, pattern in NOTIFICATION_SPAM_PATTERNS:
            if pattern.search(combined):
                result.notification_spam_detected = True
                desc = pattern_name.replace("_", " ").title()
                result.signals.append(f"DECEPTIVE: Notification spam technique — {desc}")

        # Count push notification indicators in general  
        if "Notification.requestPermission" in html or "Notification.requestPermission" in combined:
            if "notifications" not in [d.get("permission") for d in result.permission_details]:
                result.permissions_requested.append("Push Notifications")
                result.permission_details.append({
                    "permission": "notifications",
                    "label": "Push Notifications",
                    "risk": "medium",
                })

    def _detect_pup_indicators(self, html: str, page_text: str, result: DownloadThreatResult) -> None:
        """Detect potentially unwanted program / software bundling indicators."""
        combined = html + "\n" + page_text

        for pattern_name, pattern in PUP_INDICATORS:
            if pattern.search(combined):
                result.pup_indicators.append(pattern_name.replace("_", " ").title())
                result.signals.append(f"PUP indicator: {pattern_name.replace('_', ' ').title()}")

    def _compute_risk(self, result: DownloadThreatResult) -> None:
        """Compute overall risk level based on all findings."""
        risk_points = 0

        # High-risk executables
        high_risk_count = sum(1 for d in result.dangerous_file_types if "HIGH-RISK" in d)
        risk_points += high_risk_count * 30

        # Medium-risk files
        medium_risk_count = sum(1 for d in result.dangerous_file_types if "MEDIUM-RISK" in d)
        risk_points += medium_risk_count * 10

        # Auto-download triggers
        risk_points += len(result.auto_download_triggers) * 15

        # Deceptive patterns (fake update, fake scan, etc.)
        deceptive_count = sum(1 for s in result.signals if "DECEPTIVE" in s or "CRITICAL" in s)
        risk_points += deceptive_count * 25

        # High-risk permissions
        high_perm_count = sum(1 for d in result.permission_details if d.get("risk") == "high")
        risk_points += high_perm_count * 15

        # Medium-risk permissions
        med_perm_count = sum(1 for d in result.permission_details if d.get("risk") == "medium")
        risk_points += med_perm_count * 5

        # Notification spam
        if result.notification_spam_detected:
            risk_points += 20

        # PUP indicators
        risk_points += len(result.pup_indicators) * 10

        # Compute safety score (inverse of risk)
        result.safety_score = max(0.0, min(100.0, 100.0 - risk_points))

        # Determine risk level
        if risk_points >= 50:
            result.risk_level = RiskLevel.CRITICAL
        elif risk_points >= 30:
            result.risk_level = RiskLevel.HIGH
        elif risk_points >= 15:
            result.risk_level = RiskLevel.MEDIUM
        elif risk_points > 0:
            result.risk_level = RiskLevel.LOW
        else:
            result.risk_level = RiskLevel.SAFE

        # If nothing found, add a positive signal
        if not result.signals:
            result.signals.append("No download threats, auto-download triggers, or suspicious permission requests detected")

    @staticmethod
    def _get_extension(url_or_filename: str) -> str:
        """Extract file extension from URL or filename."""
        # Remove query string and fragment
        clean = url_or_filename.split("?")[0].split("#")[0]
        # Get extension from last path segment
        last_segment = clean.rsplit("/", 1)[-1] if "/" in clean else clean
        if "." in last_segment:
            ext = "." + last_segment.rsplit(".", 1)[-1].lower()
            # Sanity checks: must be a plausible file ext, not a TLD or domain
            if len(ext) <= 10 and ext not in _COMMON_TLDS:
                return ext
        return ""

    @staticmethod
    def _truncate_url(url: str, max_len: int = 80) -> str:
        """Truncate URL for display in signals."""
        if len(url) <= max_len:
            return url
        return url[:max_len - 3] + "..."
