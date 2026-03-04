"""
API key management routes.

POST /api/v1/keys/register   – Register a new API key
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from trustlens.api.deps import get_api_key_repo
from trustlens.schemas import APIKeyRegisterRequest, APIKeyResponse

router = APIRouter(prefix="/api/v1/keys", tags=["API Keys"])


@router.post("/register", response_model=APIKeyResponse, status_code=201)
async def register_api_key(body: APIKeyRegisterRequest):
    """
    Register a new API key.

    Returns the raw API key — store it securely, it cannot be retrieved again.
    Rate limits are determined by the tier:
    - free:       30 req/min
    - pro:        200 req/min
    - enterprise: 2000 req/min
    """
    repo = get_api_key_repo()
    if repo is None:
        raise HTTPException(503, "API key management is not available")

    raw_key, key_hash = repo.generate_key()

    record = await repo.create(
        key_hash=key_hash,
        owner=body.owner,
        tier=body.tier,
    )

    return APIKeyResponse(
        api_key=raw_key,
        tier=record.tier,
        rate_limit=record.rate_limit,
        rate_window=record.rate_window,
        scopes=record.scopes,
    )
