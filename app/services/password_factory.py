"""Generación de contraseñas del lado del servidor.

`generate_password_core` sirve dos caminos: POST /api/v1/passwords/generate y la rotación
del panel (revocar / sugerir, HU18 AC2/AC3: «genera una credencial nueva vía
/passwords/generate»). Vive acá y no en una ruta porque una ruta que importa a otra ruta
encadena el panel al router de contraseñas: las rutas importan servicios, no al revés.

Levanta HTTPException (502) cuando el backend de IA falla, igual que antes de moverla: el
endpoint público conserva su contrato de error. El camino `mode="random"` no llama a la IA
y por lo tanto no puede fallar así.
"""

import logging

from fastapi import HTTPException, status

from app.schemas.passwords import PasswordGenerateRequest, PasswordGenerateResponse
from app.services import ai_engine, random_generator
from app.services.entropy import calculate as calc_entropy

logger = logging.getLogger("sparkgate.passwords")


async def generate_password_core(
    request: PasswordGenerateRequest,
) -> PasswordGenerateResponse:
    """Core generation logic, shared by /passwords/generate and the dashboard rotation
    endpoints (revoke / suggest), which call it internally, not over HTTP."""
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
