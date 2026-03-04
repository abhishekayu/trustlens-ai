"""
Anthropic (Claude) provider – hardened for structured JSON output.
"""

from __future__ import annotations

import json
import re
from typing import Any

from trustlens.core import AIProvider, get_settings
from trustlens.core.logging import get_logger
from trustlens.services.ai import BaseAIProvider, register_provider

logger = get_logger(__name__)

_JSON_OBJECT_RE = re.compile(r"\{[\s\S]*\}", re.MULTILINE)


@register_provider(AIProvider.ANTHROPIC)
class AnthropicProvider(BaseAIProvider):
    """
    Anthropic Claude provider with structured JSON output.

    Claude doesn't have native JSON mode, so we enforce via:
    - System prompt with strict JSON-only instruction
    - User prompt suffix demanding raw JSON
    - Multi-layer JSON extraction from response
    """

    @property
    def name(self) -> str:
        return "anthropic"

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        from anthropic import AsyncAnthropic

        settings = get_settings()
        if not settings.anthropic_api_key:
            raise ValueError("TRUSTLENS_ANTHROPIC_API_KEY is not set")

        client = AsyncAnthropic(api_key=settings.anthropic_api_key)

        # Append JSON enforcement to user prompt
        enforced_prompt = (
            user_prompt
            + "\n\nCRITICAL: Respond with ONLY a raw JSON object. "
            "No markdown fences, no explanation text, no preamble. "
            "Start your response with { and end with }."
        )

        logger.info("anthropic.sending_request", model=settings.anthropic_model)
        try:
            response = await client.messages.create(
                model=settings.anthropic_model,
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": enforced_prompt}],
                temperature=0.05,
            )
        except Exception as e:
            raise ConnectionError(f"Anthropic API call failed: {e}") from e

        content = response.content[0].text if response.content else ""

        if not content.strip():
            raise ValueError("Anthropic returned empty response")

        # Multi-layer JSON extraction
        # Layer 1: direct parse
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            pass

        # Layer 2: markdown fences
        for fence in ("```json", "```"):
            if fence in content:
                parts = content.split(fence)
                if len(parts) >= 2:
                    candidate = parts[1].split("```")[0].strip()
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        continue

        # Layer 3: regex
        match = _JSON_OBJECT_RE.search(content)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        raise json.JSONDecodeError(
            f"No valid JSON in Anthropic response ({len(content)} chars)", content, 0
        )
