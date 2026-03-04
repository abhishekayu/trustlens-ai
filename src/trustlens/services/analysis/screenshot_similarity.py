"""
Screenshot Similarity Engine – perceptual hashing for visual clone detection.

Uses perceptual hashing (pHash) and difference hashing (dHash) to compare
screenshots against a database of known brand page screenshots.  A high
similarity score indicates a visual clone of a legitimate site — strong
evidence of phishing.

Requires: Pillow, imagehash (gracefully degrades if unavailable).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from trustlens.core import get_settings
from trustlens.core.logging import get_logger
from trustlens.models import ScreenshotSimilarityResult

logger = get_logger(__name__)

# Lazy imports — these are optional heavy dependencies
_imagehash = None
_Image = None


def _ensure_imports() -> bool:
    """Attempt to import imagehash + PIL. Returns True if available."""
    global _imagehash, _Image
    if _imagehash is not None:
        return True
    try:
        import imagehash as ih  # type: ignore[import-untyped]
        from PIL import Image  # type: ignore[import-untyped]

        _imagehash = ih
        _Image = Image
        return True
    except ImportError:
        logger.warning(
            "screenshot_similarity.dependencies_missing",
            hint="Install 'imagehash' and 'Pillow' for visual clone detection",
        )
        return False


def _hamming_distance(hash1: str, hash2: str) -> int:
    """Compute Hamming distance between two hex-encoded hashes."""
    if len(hash1) != len(hash2):
        return 64  # max for 64-bit hashes
    bin1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
    bin2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
    return sum(c1 != c2 for c1, c2 in zip(bin1, bin2))


def _hash_similarity(hash1: str, hash2: str, hash_bits: int = 64) -> float:
    """Convert Hamming distance to similarity 0-1 (1 = identical)."""
    if not hash1 or not hash2:
        return 0.0
    distance = _hamming_distance(hash1, hash2)
    return max(0.0, 1.0 - distance / hash_bits)


class ScreenshotSimilarityEngine:
    """Compare page screenshots against known brand baselines via perceptual hashing."""

    def __init__(self, brand_hashes: list[dict] | None = None) -> None:
        """
        Args:
            brand_hashes: Pre-loaded list of dicts with keys:
                brand_name, phash, dhash, source_url
        """
        self._brand_hashes: list[dict] = brand_hashes or []
        self._settings = get_settings()
        self._threshold = self._settings.screenshot_similarity_threshold

    def set_brand_hashes(self, hashes: list[dict]) -> None:
        """Update the brand hash database at runtime."""
        self._brand_hashes = hashes

    def compute_hashes(self, image_path: str) -> tuple[str, str]:
        """
        Compute perceptual hash (pHash) and difference hash (dHash) for an image.

        Returns:
            (phash_hex, dhash_hex)  or  ("", "") if hashing fails.
        """
        if not _ensure_imports():
            return "", ""

        try:
            img = _Image.open(image_path)
            phash = str(_imagehash.phash(img))
            dhash = str(_imagehash.dhash(img))
            logger.debug("screenshot_similarity.hashed", path=image_path, phash=phash, dhash=dhash)
            return phash, dhash
        except Exception as e:
            logger.error("screenshot_similarity.hash_failed", path=image_path, error=str(e))
            return "", ""

    def compare(self, image_path: str) -> ScreenshotSimilarityResult:
        """
        Compare a screenshot against ALL known brand hashes.

        Returns:
            ScreenshotSimilarityResult with the closest match.
        """
        phash, dhash = self.compute_hashes(image_path)
        if not phash:
            return ScreenshotSimilarityResult(
                signals=["Screenshot hashing unavailable – install imagehash + Pillow"]
            )

        result = ScreenshotSimilarityResult(phash=phash, dhash=dhash)

        if not self._brand_hashes:
            result.signals.append("No brand screenshot baselines available for comparison")
            return result

        best_similarity = 0.0
        best_brand = ""
        matched: list[str] = []

        for brand_hash in self._brand_hashes:
            brand_name = brand_hash.get("brand_name", "unknown")
            ref_phash = brand_hash.get("phash", "")
            ref_dhash = brand_hash.get("dhash", "")

            # Compute similarity using the configured algorithm
            if self._settings.screenshot_hash_algorithm == "dhash" and ref_dhash:
                sim = _hash_similarity(dhash, ref_dhash)
            elif ref_phash:
                sim = _hash_similarity(phash, ref_phash)
            else:
                continue

            if sim > best_similarity:
                best_similarity = sim
                best_brand = brand_name

            if sim >= self._threshold:
                matched.append(f"{brand_name} (similarity: {sim:.3f})")

        result.closest_brand = best_brand if best_brand else None
        result.closest_brand_distance = 1.0 - best_similarity
        result.similarity_score = best_similarity
        result.is_visual_clone = best_similarity >= self._threshold
        result.matched_screenshots = matched

        if result.is_visual_clone:
            result.signals.append(
                f"VISUAL CLONE DETECTED: page visually matches {best_brand} "
                f"(similarity {best_similarity:.3f} >= threshold {self._threshold})"
            )
        elif best_similarity >= 0.5:
            result.signals.append(
                f"Moderate visual similarity to {best_brand} ({best_similarity:.3f})"
            )
        else:
            result.signals.append("No significant visual similarity to known brands")

        logger.info(
            "screenshot_similarity.compared",
            best_brand=best_brand,
            similarity=round(best_similarity, 3),
            is_clone=result.is_visual_clone,
        )

        return result

    async def analyze(self, screenshot_path: Optional[str]) -> ScreenshotSimilarityResult:
        """
        Async wrapper for the orchestrator pipeline.

        Args:
            screenshot_path: Path to the captured screenshot (from crawler).
        """
        if not screenshot_path or not Path(screenshot_path).exists():
            return ScreenshotSimilarityResult(
                signals=["No screenshot available for visual similarity analysis"]
            )

        return self.compare(screenshot_path)
