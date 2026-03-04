"""
Brand impersonation similarity engine.

Compares crawled page data against a registry of known brands using:
  - Domain name similarity (Levenshtein distance)
  - Content keyword matching
  - Title / meta tag analysis
  - Impersonation probability scoring

This is a core differentiator – detects when a page tries to look like
a well-known brand without being the official site.
"""

from __future__ import annotations

import re
from typing import Any

from Levenshtein import ratio as levenshtein_ratio

from trustlens.core.logging import get_logger
from trustlens.models import BrandMatch, CrawlResult
from trustlens.security import extract_domain

logger = get_logger(__name__)

# Known brands dataset (used when no DB registry is available)
DEFAULT_BRANDS = [
    {"brand_name": "Google", "domains": ["google.com", "googleapis.com"], "keywords": ["google", "gmail", "drive"]},
    {"brand_name": "Microsoft", "domains": ["microsoft.com", "live.com", "outlook.com", "office.com"], "keywords": ["microsoft", "outlook", "onedrive", "teams"]},
    {"brand_name": "Apple", "domains": ["apple.com", "icloud.com"], "keywords": ["apple", "icloud", "itunes"]},
    {"brand_name": "Amazon", "domains": ["amazon.com", "aws.amazon.com"], "keywords": ["amazon", "aws", "prime"]},
    {"brand_name": "PayPal", "domains": ["paypal.com"], "keywords": ["paypal"]},
    {"brand_name": "Facebook", "domains": ["facebook.com", "fb.com", "meta.com"], "keywords": ["facebook", "meta", "instagram"]},
    {"brand_name": "Netflix", "domains": ["netflix.com"], "keywords": ["netflix"]},
    {"brand_name": "Bank of America", "domains": ["bankofamerica.com"], "keywords": ["bankofamerica", "bofa"]},
    {"brand_name": "Chase", "domains": ["chase.com", "jpmorganchase.com"], "keywords": ["chase", "jpmorgan"]},
    {"brand_name": "Wells Fargo", "domains": ["wellsfargo.com"], "keywords": ["wellsfargo"]},
    {"brand_name": "DHL", "domains": ["dhl.com"], "keywords": ["dhl", "shipment", "tracking"]},
    {"brand_name": "LinkedIn", "domains": ["linkedin.com"], "keywords": ["linkedin"]},
    {"brand_name": "Dropbox", "domains": ["dropbox.com"], "keywords": ["dropbox"]},
    {"brand_name": "DocuSign", "domains": ["docusign.com", "docusign.net"], "keywords": ["docusign", "signature"]},
    {"brand_name": "Stripe", "domains": ["stripe.com"], "keywords": ["stripe", "payment"]},
    {"brand_name": "USPS", "domains": ["usps.com"], "keywords": ["usps", "postal"]},
    {"brand_name": "FedEx", "domains": ["fedex.com"], "keywords": ["fedex"]},
    {"brand_name": "Coinbase", "domains": ["coinbase.com"], "keywords": ["coinbase", "crypto"]},
    {"brand_name": "WhatsApp", "domains": ["whatsapp.com", "web.whatsapp.com"], "keywords": ["whatsapp"]},
    {"brand_name": "Twitter/X", "domains": ["twitter.com", "x.com"], "keywords": ["twitter"]},
]


class BrandSimilarityEngine:
    """Detect brand impersonation by comparing against known brands."""

    def __init__(self, brand_registry: list[dict[str, Any]] | None = None) -> None:
        self._brands = brand_registry if brand_registry else DEFAULT_BRANDS

    async def analyze(self, crawl: CrawlResult, original_url: str) -> list[BrandMatch]:
        """Check the crawled page against all known brands."""
        matches: list[BrandMatch] = []
        page_domain = extract_domain(crawl.final_url).lower()
        original_domain = extract_domain(original_url).lower()
        page_text = (crawl.page_title + " " + crawl.html_content[:5000]).lower()
        is_redirect = original_domain != page_domain

        for brand in self._brands:
            brand_name: str = brand["brand_name"]
            official_domains: list[str] = [d.lower() for d in brand["domains"]]
            keywords: list[str] = [k.lower() for k in brand.get("keywords", [])]

            # Check if the FINAL domain is official
            final_is_official = any(
                page_domain == d or page_domain.endswith(f".{d}")
                for d in official_domains
            )

            # Check if the ORIGINAL submitted domain is official
            original_is_official = any(
                original_domain == d or original_domain.endswith(f".{d}")
                for d in official_domains
            )

            # If both original and final are official, it's genuine
            if original_is_official and final_is_official:
                matches.append(
                    BrandMatch(
                        brand_name=brand_name,
                        similarity_score=0.0,
                        is_official=True,
                        impersonation_probability=0.0,
                        matched_features=["official_domain"],
                    )
                )
                continue

            # If only the original is official (no redirect), it's genuine
            if original_is_official and not is_redirect:
                matches.append(
                    BrandMatch(
                        brand_name=brand_name,
                        similarity_score=0.0,
                        is_official=True,
                        impersonation_probability=0.0,
                        matched_features=["official_domain"],
                    )
                )
                continue

            # ── Check ORIGINAL domain for typosquatting ──────────
            # This catches domains like microsft.com even if they redirect
            # to the official microsoft.com
            original_domain_similarity = self._domain_similarity(
                original_domain, official_domains, brand_name
            )

            # Also check the final domain (if different)
            final_domain_similarity = 0.0
            if is_redirect and not final_is_official:
                final_domain_similarity = self._domain_similarity(
                    page_domain, official_domains, brand_name
                )

            domain_similarity = max(original_domain_similarity, final_domain_similarity)

            # ── Content similarity ───────────────────────────────
            content_hits: list[str] = []

            for kw in keywords:
                if kw in page_text:
                    content_hits.append(f"keyword:{kw}")

            if brand_name.lower() in crawl.page_title.lower():
                content_hits.append("brand_in_title")

            for key, val in crawl.meta_tags.items():
                if brand_name.lower() in val.lower():
                    content_hits.append(f"meta:{key}")
                    break

            # Login/form context amplifies suspicion
            has_login_context = any(
                kw in page_text for kw in ["login", "sign in", "password", "verify", "confirm"]
            )
            if content_hits and has_login_context:
                content_hits.append("login_context")

            content_similarity = min(len(content_hits) / 5.0, 1.0)

            # ── Aggregate similarity ─────────────────────────────
            # Domain similarity is weighted more heavily — a near-identical
            # domain name is suspicious even when the page content is blank.
            similarity = domain_similarity * 0.7 + content_similarity * 0.3

            # If the original domain is a typosquat but it redirected to
            # the official domain, it might be a defensive registration.
            # Still flag it, but note the redirect.
            if is_redirect and final_is_official and original_domain_similarity >= 0.7:
                content_hits.append(f"redirect_to_official:{brand_name}")
                # Still suspicious — typosquatting domain exists
                content_hits.append("typosquat_domain")

            # ── Impersonation probability ────────────────────────
            # Higher when: domain is similar + content references brand + login forms
            impersonation_prob = self._compute_impersonation_probability(
                domain_similarity, content_similarity, has_login_context, content_hits
            )

            # Only report meaningful similarity
            if similarity >= 0.3 or domain_similarity >= 0.55:
                matches.append(
                    BrandMatch(
                        brand_name=brand_name,
                        similarity_score=round(similarity, 3),
                        matched_features=content_hits,
                        domain_similarity=round(domain_similarity, 3),
                        content_similarity=round(content_similarity, 3),
                        impersonation_probability=round(impersonation_prob, 3),
                        is_official=False,
                    )
                )

        matches.sort(key=lambda m: m.similarity_score, reverse=True)
        logger.info(
            "brand_similarity.completed",
            total_matches=len(matches),
            top_match=matches[0].brand_name if matches else "none",
        )
        return matches

    @staticmethod
    def _compute_impersonation_probability(
        domain_sim: float,
        content_sim: float,
        has_login: bool,
        features: list[str],
    ) -> float:
        """
        Compute the probability that this is a brand impersonation attempt.

        Considers domain similarity, content match, and presence of login context.
        Very high domain similarity alone (>= 0.85) is strong evidence of
        typosquatting and should push probability high even without content.
        """
        # Domain similarity is the primary signal for typosquatting
        if domain_sim >= 0.85:
            # Very close domain name → high impersonation confidence
            base = 0.7 + (domain_sim - 0.85) * 2.0  # 0.85→0.7, 0.95→0.9, 1.0→1.0
            base = min(base, 0.95)
        elif domain_sim >= 0.7:
            base = 0.4 + (domain_sim - 0.7) * 2.0  # 0.7→0.4, 0.85→0.7
        else:
            base = domain_sim * 0.5

        # Content signals amplify
        base += content_sim * 0.2
        if has_login:
            base += 0.15
        if "brand_in_title" in features:
            base += 0.1
        return min(base, 1.0)

    @staticmethod
    def _domain_similarity(
        domain: str,
        official_domains: list[str],
        brand_name: str,
    ) -> float:
        """Compute how similar a domain is to a brand's official domains."""
        domain_scores = [levenshtein_ratio(domain, d) for d in official_domains]
        similarity = max(domain_scores) if domain_scores else 0.0

        # Brand name embedded in domain (e.g. "paypa1-secure.com")
        brand_name_lower = brand_name.lower().replace(" ", "")
        if brand_name_lower in domain.replace(".", ""):
            similarity = max(similarity, 0.7)

        # Typosquatting: brand with char substitutions
        brand_stripped = re.sub(r"[^a-z0-9]", "", brand_name_lower)
        domain_stripped = re.sub(r"[^a-z0-9]", "", domain)
        typo_ratio = levenshtein_ratio(brand_stripped, domain_stripped)
        if typo_ratio > similarity:
            similarity = typo_ratio

        return similarity
