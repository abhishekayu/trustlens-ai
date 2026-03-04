"""
Content Extraction Service.

Extracts clean visible text from HTML by removing scripts, styles,
and non-visible elements. Provides safe, structured text for downstream
analysis and AI consumption.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment

from trustlens.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ExtractedContent:
    """Clean extracted page content."""

    visible_text: str
    title: str
    meta_description: str
    headings: list[str]
    link_texts: list[str]
    form_labels: list[str]
    word_count: int
    language_hint: str


class ContentExtractor:
    """Extract and sanitize visible text content from HTML."""

    # Tags whose content is never visible
    _INVISIBLE_TAGS = {"script", "style", "noscript", "svg", "path", "head", "meta", "link"}

    def extract(self, html: str, max_length: int = 50_000) -> ExtractedContent:
        """
        Parse HTML and extract all visible text content.

        Removes scripts, styles, comments, hidden elements, and normalizes whitespace.
        """
        if not html:
            return ExtractedContent(
                visible_text="", title="", meta_description="",
                headings=[], link_texts=[], form_labels=[],
                word_count=0, language_hint="",
            )

        soup = BeautifulSoup(html, "lxml")

        # ── Remove invisible elements ────────────────────────────
        for tag in soup.find_all(self._INVISIBLE_TAGS):
            tag.decompose()

        # Remove HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        # Remove elements with display:none or visibility:hidden
        for tag in soup.find_all(style=re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)):
            tag.decompose()

        # ── Extract structured data ──────────────────────────────
        title = soup.title.get_text(strip=True) if soup.title else ""

        meta_desc = ""
        meta_tag = soup.find("meta", attrs={"name": "description"})
        if meta_tag and meta_tag.get("content"):
            meta_desc = meta_tag["content"]

        headings = [
            h.get_text(strip=True)
            for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
            if h.get_text(strip=True)
        ]

        link_texts = [
            a.get_text(strip=True)
            for a in soup.find_all("a")
            if a.get_text(strip=True)
        ][:50]

        form_labels = []
        for label in soup.find_all("label"):
            text = label.get_text(strip=True)
            if text:
                form_labels.append(text)
        for inp in soup.find_all("input", attrs={"placeholder": True}):
            form_labels.append(inp["placeholder"])

        # ── Extract visible text ─────────────────────────────────
        raw_text = soup.get_text(separator="\n", strip=True)

        # Normalize whitespace: collapse multiple blank lines
        lines = [line.strip() for line in raw_text.splitlines()]
        lines = [line for line in lines if line]
        visible_text = "\n".join(lines)

        if len(visible_text) > max_length:
            visible_text = visible_text[:max_length] + "\n[TRUNCATED]"

        word_count = len(visible_text.split())

        # Language hint from <html lang="...">
        html_tag = soup.find("html")
        language_hint = ""
        if html_tag and html_tag.get("lang"):
            language_hint = html_tag["lang"]

        return ExtractedContent(
            visible_text=visible_text,
            title=title,
            meta_description=meta_desc,
            headings=headings[:20],
            link_texts=link_texts,
            form_labels=form_labels[:30],
            word_count=word_count,
            language_hint=language_hint,
        )

    def extract_for_ai(self, html: str, max_length: int = 8_000) -> str:
        """Return a compact text representation suitable for AI prompt injection."""
        content = self.extract(html, max_length=max_length * 2)

        parts: list[str] = []
        if content.title:
            parts.append(f"Page Title: {content.title}")
        if content.meta_description:
            parts.append(f"Description: {content.meta_description}")
        if content.headings:
            parts.append(f"Headings: {' | '.join(content.headings[:10])}")
        if content.form_labels:
            parts.append(f"Form Fields: {', '.join(content.form_labels[:15])}")

        parts.append(f"\nVisible Text ({content.word_count} words):")
        parts.append(content.visible_text)

        result = "\n".join(parts)
        if len(result) > max_length:
            result = result[:max_length] + "\n[TRUNCATED]"
        return result
