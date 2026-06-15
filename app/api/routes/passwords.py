import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.dependencies import verify_token
from app.schemas.passwords import (
    PasswordEvaluateRequest,
    PasswordEvaluateResponse,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
)
from app.services import hibp_client, ai_engine, random_generator
from app.services.entropy import calculate as calc_entropy, meets_threshold

logger = logging.getLogger("sparkgate.passwords")
router = APIRouter(prefix="/api/v1/passwords", tags=["passwords"])


@router.post("/evaluate", response_model=PasswordEvaluateResponse)
async def evaluate_password(
    request: PasswordEvaluateRequest,
    user: dict | None = Depends(verify_token),
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    entropy_bits = calc_entropy(request.password)
    entropy_threshold_met = meets_threshold(request.password)

    is_compromised, pwned_count = False, 0
    try:
        is_compromised, pwned_count = await hibp_client.check_password(request.password)
    except Exception as e:
        logger.warning("HIBP check failed for user %s: %s", user.get("id", "unknown"), e)

    try:
        ai_result = await ai_engine.evaluate_security(request.password, is_compromised)
    except Exception as e:
        logger.error("AI evaluate failed for user %s: %s", user.get("id", "unknown"), e)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI service unavailable. Mathematical analysis completed but semantic analysis failed.",
        )

    logger.info(
        "Evaluate: entropy=%.1f, compromised=%s, score=%d",
        entropy_bits, is_compromised, ai_result.get("ai_score", 0),
    )
    return PasswordEvaluateResponse(
        is_compromised=is_compromised,
        pwned_count=pwned_count,
        entropy_bits=entropy_bits,
        entropy_threshold_met=entropy_threshold_met,
        ai_score=ai_result["ai_score"],
        ai_feedback=ai_result["ai_feedback"],
        ai_suggestions=ai_result["ai_suggestions"],
    )


@router.post("/generate", response_model=PasswordGenerateResponse)
async def generate_password(
    request: PasswordGenerateRequest,
    user: dict | None = Depends(verify_token),
):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    if request.mode == "random":
        password = random_generator.generate(
            length=request.length,
            use_upper=request.use_upper,
            use_lower=request.use_lower,
            use_digits=request.use_digits,
            use_symbols=request.use_symbols,
        )
        entropy_bits = calc_entropy(password)
        logger.info("Generate (random): length=%d, entropy=%.1f", request.length, entropy_bits)
        return PasswordGenerateResponse(
            generated_password=password,
            explanation=f"Contraseña generada aleatoriamente con {request.length} caracteres. Entropía: {entropy_bits:.1f} bits.",
            entropy_bits=entropy_bits,
        )

    for attempt in range(3):
        try:
            result = await ai_engine.generate_password(
                length=request.length,
                context=request.context,
                complexity_level=request.complexity_level,
                style=request.style,
                word_count=request.word_count,
                theme=request.theme,
                personal_words=request.personal_words,
            )
        except Exception as e:
            logger.error("AI generate failed: %s", e)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="AI service unavailable. Please try again later.",
            )

        password = result["generated_password"]
        entropy_bits = calc_entropy(password)
        if entropy_bits >= 60.0:
            break
        logger.warning("Generate attempt %d below threshold: %.1f bits", attempt + 1, entropy_bits)
    else:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Generated password does not meet minimum entropy threshold after multiple attempts.",
        )

    logger.info("Generate (ai): length=%d, entropy=%.1f, attempts=%d", request.length, entropy_bits, attempt + 1)
    return PasswordGenerateResponse(
        generated_password=password,
        explanation=result["explanation"],
        entropy_bits=entropy_bits,
    )
