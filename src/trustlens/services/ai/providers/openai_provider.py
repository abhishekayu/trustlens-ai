"""
OpenAI provider (GPT-4o, etc.) – hardened for structured JSON output.
"""

from __future__ import annotations

import json
from typing import Any

from trustlens.core import AIProvider, get_settings
from trustlens.core.logging import get_logger
from trustlens.services.ai import BaseAIProvider, register_provider

logger = get_logger(__name__)


@register_provider(AIProvider.OPENAI)
class OpenAIProvider(BaseAIProvider):
    """
    OpenAI API provider with structured JSON output.

    Uses response_format=json_object for guaranteed JSON.
    Temperature set near-zero for deterministic output.
    """

    @property
    def name(self) -> str:
        return "openai"

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        from openai import AsyncOpenAI

        settings = get_settings()
        if not settings.openai_api_key:
            raise ValueError("TRUSTLENS_OPENAI_API_KEY is not set")

        client = AsyncOpenAI(api_key=settings.openai_api_key)

        logger.info("openai.sending_request", model=settings.openai_model)
        try:
            response = await client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.05,
                max_tokens=4096,
                seed=42,  # Deterministic mode (best-effort on OpenAI side)
            )
        except Exception as e:
            raise ConnectionError(f"OpenAI API call failed: {e}") from e

        content = response.choices[0].message.content or ""

        if not content.strip():
            raise ValueError("OpenAI returned empty response")

        return json.loads(content)
