import hashlib
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import verify_token
from app.core.config import settings
from app.schemas.passwords import (
    PasswordEvaluateRequest,
    PasswordEvaluateResponse,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
)
from app.services import hibp_client, ai_engine
from app.services.ai_engine import AI_EVALUATE_VERSION
from app.services.cache import evaluate_cache
from app.services.entropy import calculate as calc_entropy, meets_threshold
from app.services.password_factory import generate_password_core

logger = logging.getLogger("sparkgate.passwords")
router = APIRouter(prefix="/api/v1/passwords", tags=["passwords"])

KEY_EVALUATE = "evaluate"


def _evaluate_cache_key(password: str, context: str | None) -> tuple:
    return (
        KEY_EVALUATE,
        hashlib.sha256(password.encode()).hexdigest(),
        context or "",
        settings.ai_backend,
        AI_EVALUATE_VERSION,
    )


@router.post("/evaluate", response_model=PasswordEvaluateResponse)
async def evaluate_password(
    request: PasswordEvaluateRequest,
    user: dict | None = Depends(verify_token),
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    cache_key = _evaluate_cache_key(request.password, request.context)
    cached = evaluate_cache.get(cache_key)
    if cached is not None:
        logger.info("Evaluate cache hit for user %s", user.get("id", "unknown"))
        return PasswordEvaluateResponse(**cached)

    entropy_bits = calc_entropy(request.password)
    entropy_threshold_met = meets_threshold(request.password)

    is_compromised, pwned_count = False, 0
    hibp_available = True
    try:
        is_compromised, pwned_count = await hibp_client.check_password(request.password)
    except Exception as e:
        logger.warning("HIBP check failed for user %s: %s", user.get("id", "unknown"), e)
        hibp_available = False

    try:
        ai_result = await ai_engine.evaluate_security(request.password, is_compromised, pwned_count)
    except Exception as e:
        logger.error("AI evaluate failed for user %s: %s", user.get("id", "unknown"), e)
        ai_result = ai_engine.UNAVAILABLE_RESULT

    logger.info(
        "Evaluate: entropy=%.1f, compromised=%s, ai_score=%s",
        entropy_bits, is_compromised, ai_result.get("ai_score"),
    )
    response = PasswordEvaluateResponse(
        is_compromised=is_compromised,
        pwned_count=pwned_count,
        hibp_available=hibp_available,
        entropy_bits=entropy_bits,
        entropy_threshold_met=entropy_threshold_met,
        ai_score=ai_result["ai_score"],
        ai_feedback=ai_result["ai_feedback"],
        ai_suggestions=ai_result["ai_suggestions"],
    )
    evaluate_cache.set(cache_key, response.model_dump())
    return response


@router.post("/generate", response_model=PasswordGenerateResponse)
async def generate_password(
    request: PasswordGenerateRequest,
    user: dict | None = Depends(verify_token),
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return await generate_password_core(request)
