"""
Ollama (local LLM) provider – hardened for structured JSON output.

Optimised for Llama 3 / Mistral with:
- Forced JSON mode
- Low temperature for determinism
- Multi-layer JSON extraction fallback
- Timeout handling for slow local hardware
"""

from __future__ import annotations

import json
import re
from typing import Any

from trustlens.core import AIProvider, get_settings
from trustlens.core.logging import get_logger
from trustlens.services.ai import BaseAIProvider, register_provider

logger = get_logger(__name__)

# Regex to find the outermost JSON object in messy model output
_JSON_OBJECT_RE = re.compile(r"\{[\s\S]*\}", re.MULTILINE)


def _extract_json(content: str) -> dict[str, Any]:
    """
    Multi-layer JSON extraction from LLM text output.

    Layer 1: Direct parse (model returned clean JSON)
    Layer 2: Strip markdown code fences
    Layer 3: Regex extraction of outermost { ... }
    Layer 4: Raise on total failure
    """
    content = content.strip()

    # Layer 1: direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Layer 2: markdown fences
    for fence in ("```json", "```JSON", "```"):
        if fence in content:
            parts = content.split(fence)
            if len(parts) >= 2:
                candidate = parts[1].split("```")[0].strip()
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    continue

    # Layer 3: regex outermost object
    match = _JSON_OBJECT_RE.search(content)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError(
        f"No valid JSON found in model output ({len(content)} chars)", content, 0
    )


@register_provider(AIProvider.OLLAMA)
class OllamaProvider(BaseAIProvider):
    """
    Ollama local LLM provider – zero external API calls.

    Recommended models: llama3, mistral, llama3.1, mistral-nemo
    All models are instructed to return JSON via Ollama's format="json" param.
    """

    @property
    def name(self) -> str:
        return "ollama"

    async def analyze(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        import httpx

        settings = get_settings()
        url = f"{settings.ollama_base_url}/api/chat"

        payload = {
            "model": settings.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "format": "json",          # Force JSON mode in Ollama
            "options": {
                "temperature": 0.05,   # Near-deterministic for consistency
                "top_p": 0.9,
                "num_predict": 4096,   # Enough tokens for full classifier output
                "repeat_penalty": 1.1, # Reduce repetition
                "seed": 42,           # Deterministic seed
            },
        }

        async with httpx.AsyncClient(timeout=180.0) as client:
            logger.info(
                "ollama.sending_request",
                model=settings.ollama_model,
                base_url=settings.ollama_base_url,
            )
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
            except httpx.ConnectError as e:
                raise ConnectionError(
                    f"Cannot connect to Ollama at {settings.ollama_base_url}. "
                    f"Is Ollama running? Error: {e}"
                ) from e
            except httpx.TimeoutException as e:
                raise TimeoutError(
                    f"Ollama request timed out after 180s. "
                    f"The model may be too large for your hardware. Error: {e}"
                ) from e

        data = response.json()
        content = data.get("message", {}).get("content", "")

        if not content.strip():
            raise ValueError("Ollama returned empty response")

        return _extract_json(content)
