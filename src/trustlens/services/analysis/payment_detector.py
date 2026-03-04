"""
Payment detection engine.

Scans crawled page data for:
  - Payment form fields (credit card, CVV, expiry, billing)
  - Known payment gateway scripts/SDKs (Stripe, PayPal, Square, Razorpay, etc.)
  - Cryptocurrency wallet addresses (BTC, ETH, XMR, etc.)
  - Suspicious payment patterns (no https, hidden fields, unusual destinations)
  - Legitimate payment indicators (PCI-DSS compliance signals, known processors)
"""

from __future__ import annotations

import re
from typing import Any

from trustlens.core.logging import get_logger
from trustlens.models import CrawlResult, PaymentDetectionResult, RiskLevel

logger = get_logger(__name__)

# ── Payment gateway patterns ─────────────────────────────────────────────

PAYMENT_GATEWAYS: dict[str, list[str]] = {
    "Stripe": ["js.stripe.com", "stripe.com/v3", "Stripe(", "stripe-js", "data-stripe"],
    "PayPal": ["paypal.com/sdk", "paypalobjects.com", "paypal-button", "paypal.Buttons"],
    "Square": ["squareup.com", "square.js", "SqPaymentForm"],
    "Braintree": ["braintreegateway.com", "braintree-web", "braintree.client"],
    "Razorpay": ["razorpay.com/v1", "Razorpay(", "rzp_"],
    "Adyen": ["adyen.com", "adyen-checkout", "AdyenCheckout"],
    "Klarna": ["klarna.com", "klarna-payments", "Klarna.Payments"],
    "Affirm": ["affirm.com", "affirm.js"],
    "Shopify Payments": ["shopify.com/pay", "shop-pay"],
    "Apple Pay": ["apple-pay", "ApplePaySession", "apple-pay-button"],
    "Google Pay": ["google-pay", "google.payments", "gpay-button"],
    "Amazon Pay": ["amazonpay", "amazon.Pay", "OffAmazonPayments"],
    "2Checkout": ["2checkout.com", "2co.com"],
    "Authorize.Net": ["authorize.net", "Accept.js"],
    "Worldpay": ["worldpay.com", "Worldpay"],
    "Mollie": ["mollie.com", "js.mollie.com"],
    "Paytm": ["paytm.in", "paytm.com"],
    "PhonePe": ["phonepe.com"],
    "Cash App": ["cash.app", "cashapp"],
}

# ── Form field patterns for payment ──────────────────────────────────────

PAYMENT_FIELD_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("credit_card_number", re.compile(r"card[\s_-]?(?:number|num|no)|cc[\s_-]?(?:number|num)|creditcard", re.I)),
    ("card_holder", re.compile(r"card[\s_-]?holder|name[\s_-]?on[\s_-]?card|cardholder", re.I)),
    ("expiry_date", re.compile(r"exp(?:iry|iration)?[\s_-]?(?:date|month|year|mm|yy)|card[\s_-]?exp", re.I)),
    ("cvv", re.compile(r"\bcvv\b|\bcvc\b|\bcvv2\b|security[\s_-]?code|card[\s_-]?verification", re.I)),
    ("billing_address", re.compile(r"billing[\s_-]?(?:address|street|city|state|zip|postal)", re.I)),
    ("bank_account", re.compile(r"(?:bank|account)[\s_-]?(?:number|no|routing|iban|swift|bic)", re.I)),
    ("ssn", re.compile(r"\bssn\b|social[\s_-]?security|tax[\s_-]?(?:id|number)", re.I)),
    ("pin", re.compile(r"\b(?:enter|your)\s*pin\b|atm[\s_-]?pin|debit[\s_-]?pin", re.I)),
    ("wire_transfer", re.compile(r"wire[\s_-]?transfer|swift[\s_-]?code|beneficiary[\s_-]?account", re.I)),
    ("upi", re.compile(r"\bupi\b|upi[\s_-]?id|unified[\s_-]?payment", re.I)),
]

# ── Crypto address patterns ──────────────────────────────────────────────

CRYPTO_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Bitcoin (BTC)", re.compile(r"\b((?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62})\b")),
    ("Ethereum (ETH)", re.compile(r"\b(0x[a-fA-F0-9]{40})\b")),
    ("Monero (XMR)", re.compile(r"\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b")),
    ("Litecoin (LTC)", re.compile(r"\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b")),
    ("Ripple (XRP)", re.compile(r"\b(r[0-9a-zA-Z]{24,34})\b")),
    ("USDT/USDC (TRC20)", re.compile(r"\b(T[a-zA-Z0-9]{33})\b")),
    ("Dogecoin (DOGE)", re.compile(r"\b(D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32})\b")),
    ("Bitcoin Cash (BCH)", re.compile(r"\b(bitcoincash:q[a-z0-9]{41})\b")),
]

# ── Suspicious payment text cues ─────────────────────────────────────────

SUSPICIOUS_PAYMENT_TEXTS: list[tuple[str, re.Pattern]] = [
    ("gift_card_demand", re.compile(r"(?:buy|purchase|send)\s+(?:gift[\s_-]?card|itunes|google[\s_-]?play[\s_-]?card|amazon[\s_-]?card)", re.I)),
    ("wire_urgency", re.compile(r"(?:urgent|immediate)(?:ly)?.*(?:wire|transfer|send|pay)", re.I)),
    ("ransom_language", re.compile(r"(?:pay|send|transfer).*(?:bitcoin|btc|crypto|wallet).*(?:within|before|deadline|hours)", re.I)),
    ("fee_scam", re.compile(r"(?:processing|handling|shipping|customs|clearance)\s+fee.*(?:pay|send|transfer)", re.I)),
    ("advance_payment", re.compile(r"(?:advance|upfront)\s+(?:fee|payment|deposit)", re.I)),
    ("money_mule", re.compile(r"(?:receive|accept)\s+(?:funds|money|payment)\s+(?:in\s+your|into)", re.I)),
    ("lottery_prize", re.compile(r"(?:won|winning|prize|lottery).*(?:claim|collect).*(?:pay|fee|charge)", re.I)),
    ("tax_threat", re.compile(r"(?:irs|tax|revenue).*(?:owe|pay|penalty|arrest|warrant)", re.I)),
]


class PaymentDetector:
    """Detect payment forms, gateways, crypto addresses, and suspicious payment patterns."""

    async def analyze(self, crawl: CrawlResult, url: str) -> PaymentDetectionResult:
        """Analyze the crawled page for payment-related signals."""
        result = PaymentDetectionResult()
        html = crawl.html_content
        page_text = (crawl.page_title + " " + html).lower()
        scripts_text = " ".join(crawl.scripts)

        # 1. Detect payment gateways
        self._detect_gateways(html, scripts_text, result)

        # 2. Detect payment form fields
        self._detect_form_fields(crawl, html, result)

        # 3. Detect crypto addresses
        self._detect_crypto(page_text, html, result)

        # 4. Detect suspicious payment patterns
        self._detect_suspicious_patterns(page_text, html, crawl, result)

        # 5. Detect legitimate payment indicators
        self._detect_legitimate_indicators(html, crawl, result)

        # 6. Compute risk
        self._compute_risk(result, crawl)

        logger.info(
            "payment_detector.completed",
            url=url,
            has_payment_form=result.has_payment_form,
            gateways=len(result.payment_gateways_detected),
            crypto_addresses=len(result.crypto_addresses),
            risk=result.risk_level.value,
        )
        return result

    def _detect_gateways(self, html: str, scripts: str, result: PaymentDetectionResult) -> None:
        """Check HTML and scripts for known payment gateway fingerprints."""
        combined = html + " " + scripts
        for gateway, patterns in PAYMENT_GATEWAYS.items():
            for pattern in patterns:
                if pattern.lower() in combined.lower():
                    if gateway not in result.payment_gateways_detected:
                        result.payment_gateways_detected.append(gateway)
                        result.signals.append(f"Payment gateway detected: {gateway}")
                    break

    def _detect_form_fields(self, crawl: CrawlResult, html: str, result: PaymentDetectionResult) -> None:
        """Check forms and page HTML for payment-related input fields."""
        # Check structured form data from crawler
        for form in crawl.forms:
            form_str = str(form).lower()
            for field_name, pattern in PAYMENT_FIELD_PATTERNS:
                if pattern.search(form_str):
                    if field_name not in result.payment_form_fields:
                        result.payment_form_fields.append(field_name)

        # Also check raw HTML for input fields
        input_pattern = re.compile(
            r'<input[^>]*(?:name|id|placeholder|aria-label|autocomplete)\s*=\s*["\']([^"\']+)["\']',
            re.I,
        )
        for match in input_pattern.finditer(html):
            attr_val = match.group(1)
            for field_name, pattern in PAYMENT_FIELD_PATTERNS:
                if pattern.search(attr_val):
                    if field_name not in result.payment_form_fields:
                        result.payment_form_fields.append(field_name)

        # Check for autocomplete hints
        autocomplete_payment = re.compile(
            r'autocomplete\s*=\s*["\'](?:cc-number|cc-name|cc-exp|cc-csc|cc-type)["\']', re.I
        )
        if autocomplete_payment.search(html):
            result.has_payment_form = True
            if "autocomplete_payment_hints" not in result.payment_form_fields:
                result.payment_form_fields.append("autocomplete_payment_hints")

        # Determine if it's a payment form
        payment_fields = {"credit_card_number", "cvv", "expiry_date"}
        detected_set = set(result.payment_form_fields)
        if detected_set & payment_fields:
            result.has_payment_form = True
        if "bank_account" in detected_set or "wire_transfer" in detected_set:
            result.has_payment_form = True

    def _detect_crypto(self, page_text: str, html: str, result: PaymentDetectionResult) -> None:
        """Detect cryptocurrency wallet addresses in page content."""
        # Search in both visible text and full HTML
        search_text = page_text + " " + html
        for crypto_name, pattern in CRYPTO_PATTERNS:
            matches = pattern.findall(search_text)
            for addr in matches[:3]:  # Limit to 3 per type
                addr_str = addr if isinstance(addr, str) else addr[0]
                # Skip short matches or common false positives
                if len(addr_str) < 20:
                    continue
                result.crypto_addresses.append({"type": crypto_name, "address": addr_str[:64]})
                result.signals.append(f"Cryptocurrency address found: {crypto_name}")

    def _detect_suspicious_patterns(
        self, page_text: str, html: str, crawl: CrawlResult, result: PaymentDetectionResult
    ) -> None:
        """Detect suspicious payment text patterns."""
        for pattern_name, pattern in SUSPICIOUS_PAYMENT_TEXTS:
            if pattern.search(page_text):
                result.suspicious_payment_patterns.append(pattern_name)
                result.signals.append(f"Suspicious payment pattern: {pattern_name}")

        # Check for payment form over HTTP (no SSL)
        if result.has_payment_form and crawl.ssl_info:
            if not crawl.ssl_info.get("is_https", False):
                result.suspicious_payment_patterns.append("payment_form_no_ssl")
                result.signals.append("Payment form detected on non-HTTPS page")

        # Hidden payment fields
        hidden_payment = re.compile(r'<input[^>]*type\s*=\s*["\']hidden["\'][^>]*(?:card|payment|amount|price)', re.I)
        if hidden_payment.search(html):
            result.suspicious_payment_patterns.append("hidden_payment_fields")
            result.signals.append("Hidden payment-related form fields detected")

        # Form action to different domain
        if result.has_payment_form:
            form_action_pattern = re.compile(r'<form[^>]*action\s*=\s*["\'](https?://[^"\']+)["\']', re.I)
            for match in form_action_pattern.finditer(html):
                action_url = match.group(1).lower()
                from trustlens.security import extract_domain
                form_domain = extract_domain(action_url)
                page_domain = extract_domain(crawl.final_url)
                if form_domain and page_domain and form_domain != page_domain:
                    # Check if it's a known payment processor
                    known_processors = ["stripe.com", "paypal.com", "square.com", "braintreegateway.com", "adyen.com"]
                    if not any(proc in form_domain for proc in known_processors):
                        result.suspicious_payment_patterns.append(f"payment_form_cross_domain:{form_domain}")
                        result.signals.append(f"Payment form submits to different domain: {form_domain}")

    def _detect_legitimate_indicators(self, html: str, crawl: CrawlResult, result: PaymentDetectionResult) -> None:
        """Detect signals indicating legitimate payment processing."""
        html_lower = html.lower()

        # Known secure payment processor integration
        if result.payment_gateways_detected:
            for gw in result.payment_gateways_detected:
                if gw in ("Stripe", "PayPal", "Square", "Braintree", "Adyen"):
                    result.legitimate_payment_indicators.append(f"established_processor:{gw}")

        # PCI-DSS compliance indicators
        if "pci" in html_lower and ("dss" in html_lower or "complian" in html_lower):
            result.legitimate_payment_indicators.append("pci_dss_mention")

        # SSL/HTTPS on payment page
        if crawl.ssl_info and crawl.ssl_info.get("is_https") and crawl.ssl_info.get("has_hsts"):
            result.legitimate_payment_indicators.append("https_with_hsts")

        # Tokenized/iframe payment
        if re.search(r'(?:iframe|data-elements|stripe-element|hosted-field)', html_lower):
            result.legitimate_payment_indicators.append("tokenized_payment")

        # Privacy policy / terms links
        if re.search(r'(?:privacy[\s_-]?policy|terms[\s_-]?(?:of[\s_-]?)?(?:service|use))', html_lower):
            result.legitimate_payment_indicators.append("privacy_terms_present")

        # Refund/return policy
        if re.search(r'(?:refund|return)[\s_-]?policy', html_lower):
            result.legitimate_payment_indicators.append("refund_policy")

    def _compute_risk(self, result: PaymentDetectionResult, crawl: CrawlResult) -> None:
        """Compute overall payment security score and risk level."""
        score = 100.0

        # Deductions for suspicious patterns
        score -= len(result.suspicious_payment_patterns) * 15
        score -= len(result.crypto_addresses) * 10

        # SSN/PIN fields are very suspicious
        if "ssn" in result.payment_form_fields:
            score -= 25
        if "pin" in result.payment_form_fields:
            score -= 20

        # Bonuses for legitimate indicators
        score += len(result.legitimate_payment_indicators) * 5

        # No payment activity → neutral
        if not result.has_payment_form and not result.payment_gateways_detected and not result.crypto_addresses:
            score = 100.0

        result.payment_security_score = max(0.0, min(100.0, score))

        # Determine risk level
        if result.payment_security_score >= 80:
            result.risk_level = RiskLevel.SAFE
        elif result.payment_security_score >= 60:
            result.risk_level = RiskLevel.LOW
        elif result.payment_security_score >= 40:
            result.risk_level = RiskLevel.MEDIUM
        elif result.payment_security_score >= 20:
            result.risk_level = RiskLevel.HIGH
        else:
            result.risk_level = RiskLevel.CRITICAL
