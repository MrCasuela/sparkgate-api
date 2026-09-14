import json
import logging
import re

import httpx

from app.core.config import settings

logger = logging.getLogger("sparkgate.ai_engine")

EVALUATE_SYSTEM_PROMPT = """Eres un experto en seguridad de contraseñas.
Analiza la contraseña y devuelve SOLO JSON sin texto adicional.

Formato exacto:
{"ai_score": 0-100, "ai_feedback": "texto en español sin saltos de línea", "ai_suggestions": ["sugerencia 1", "sugerencia 2", "sugerencia 3"]}

Reglas:
- ai_score: 0-100. 0-20=muy débil, 21-40=débil, 41-60=moderada, 61-80=fuerte, 81-100=muy fuerte
- ai_feedback: explicación breve en español, con tildes y ortografía correcta
- ai_suggestions: 2-3 sugerencias concretas en español

Ejemplos:
Input: "Juanito2026"
Output: {"ai_score": 15, "ai_feedback": "La contraseña contiene un nombre propio y un año, patrones faciles de adivinar.", "ai_suggestions": ["Evita usar nombres personales", "No uses años o fechas predecibles", "Combina mayusculas, minusculas, numeros y simbolos"]}

Input: "CaballoAzul#72"
Output: {"ai_score": 78, "ai_feedback": "Buena combinacion de palabras mayusculas y un simbolo. Longitud adecuada.", "ai_suggestions": ["Aumenta la longitud a 14+ caracteres", "Agrega un numero aleatorio adicional"]}

Input: "password123"
Output: {"ai_score": 5, "ai_feedback": "Contrasena extremadamente debil y comun. Facil de adivinar por ataque de diccionario.", "ai_suggestions": ["No uses la palabra 'password'", "Usa una frase larga en lugar de una palabra", "Agrega simbolos especiales"]}"""

GENERATE_SYSTEM_PROMPT = """Eres un generador de contraseñas seguras y memorables en español.
Devuelve SOLO JSON sin texto adicional.

Formato exacto:
{"generated_password": "string", "explanation": "texto en español sin saltos de línea"}

Reglas generales:
- Minimo 12 caracteres
- Combinacion de mayusculas, minusculas, numeros y simbolos
- Usar vocabulario comun en español para facilitar memorabilidad

Estilos de contraseña:

1. style=compound: palabras unidas con primera mayuscula, simbolos entre medias
   Ej: CaballoAzul#72 → "Caballo" + "Azul" + "#" + "72"
   Explicacion: describe una escena visual usando las palabras

2. style=passphrase: palabras separadas por guion, en minusculas, numero y simbolo al final
   Ej: rio-mar-luna-98# → "rio" + "-" + "mar" + "-" + "luna" + "-" + "98" + "#"
   Explicacion: describe una escena usando las palabras separadas

3. style=pattern: estructura libre con patron creativo, mezcla palabras, numeros y simbolos

Parametros adicionales:
- word_count: cantidad de palabras semanticas a incluir
- theme: dominio de vocabulario (naturaleza, animales, comida, colores, deportes, tecnologia, etc.)
- personal_words: incluir estas palabras exactas en la contraseña

importante: Si se proporcionan personal_words, deben incluirse exactamente como se indican.

Ejemplos:
Input: length=16, style=compound, word_count=3, theme=naturaleza, personal_words=["toby"]
Output: {"generated_password": "Toby#Mar*Luna99", "explanation": "Incluye 'toby' combinado con palabras de la naturaleza (mar, luna) separadas por simbolos."}

Input: length=16, style=passphrase, word_count=4, theme=animales
Output: {"generated_password": "gato-perro-oso-73%", "explanation": "Cuatro animales en espanol separados por guiones, con numero y simbolo al final."}

Input: length=12, style=pattern, word_count=2, theme=colores
Output: {"generated_password": "Azul7Rojo#21", "explanation": "Dos colores combinados en un patron intercalado con numeros y simbolo."}"""


OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Bump this when prompts change so cached evaluate results are invalidated.
AI_EVALUATE_VERSION = 1

# Returned when the semantic analysis cannot be completed (service failure or
# unparseable model response). Entropy/HIBP dimensions remain available.
UNAVAILABLE_RESULT = {
    "ai_score": None,
    "ai_feedback": "El análisis semántico no está disponible.",
    "ai_suggestions": [],
}

# Tuned for local inference: bound context and output length to cut latency
# without changing semantic quality. Output cap per purpose.
OLLAMA_OPTIONS = {"num_thread": 12, "num_ctx": 1024}
EVALUATE_NUM_PREDICT = 200
GENERATE_NUM_PREDICT = 160


async def _call_ollama(
    system_prompt: str, user_prompt: str, timeout: float = 30.0,
    num_predict: int | None = None,
) -> str:
    """Call Ollama /api/generate. Returns raw response text."""
    options = dict(OLLAMA_OPTIONS)
    if num_predict is not None:
        options["num_predict"] = num_predict
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ollama_url}/api/generate",
            json={
                "model": "llama3.2:3b",
                "system": system_prompt,
                "prompt": user_prompt,
                "stream": False,
                "format": "json",
                "options": options,
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    return data.get("response", "")


async def _call_openrouter(
    system_prompt: str, user_prompt: str, timeout: float = 30.0,
    max_tokens: int = 200,
) -> str:
    """Call OpenRouter API (OpenAI-compatible). Returns raw response text."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            OPENROUTER_API_URL,
            headers={
                "Authorization": f"Bearer {settings.openrouter_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.openrouter_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.7,
                "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "reasoning": {"exclude": True},
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    return data["choices"][0]["message"]["content"]


async def _call_ai(
    system_prompt: str, user_prompt: str, timeout: float = 30.0,
    num_predict: int | None = None,
) -> str:
    """Route to active AI backend based on settings.ai_backend."""
    if settings.ai_backend == "openrouter":
        max_tokens = num_predict if num_predict is not None else 200
        return await _call_openrouter(system_prompt, user_prompt, timeout, max_tokens)
    return await _call_ollama(system_prompt, user_prompt, timeout, num_predict)


def _safe_parse_ollama_response(raw_response: str) -> dict | None:
    """Attempt to parse JSON from Ollama response. Tries direct parse first,
    then regex extraction of {...} block, then malformed JSON correction."""
    raw = raw_response.strip()

    # Try 1: direct json.loads
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try 2: extract first { ... } block
    brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    # Try 3: repair common issues
    try:
        cleaned = raw.replace("'", '"')
        cleaned = re.sub(r"(?<!\\)\\(?![\\/bfnrt\"'u])", "", cleaned)
        return json.loads(cleaned)
    except (json.JSONDecodeError, Exception):
        pass

    return None


async def evaluate_security(password: str, is_pwned: bool, pwned_count: int = 0) -> dict:
    hibp_status = "Compromised" if is_pwned else "Not found in known breaches"
    if is_pwned and pwned_count > 0:
        hibp_status += f" ({pwned_count} times)"
    user_prompt = (
        f"Password to analyze: {password}\n"
        f"HIBP breach status: {hibp_status}\n"
        "Return JSON with ai_score, ai_feedback, ai_suggestions."
    )

    try:
        raw = await _call_ai(EVALUATE_SYSTEM_PROMPT, user_prompt, num_predict=EVALUATE_NUM_PREDICT)
    except httpx.ReadTimeout:
        logger.error("AI timeout during evaluate_security")
        return UNAVAILABLE_RESULT
    except httpx.HTTPStatusError as e:
        logger.error("AI HTTP error during evaluate_security: %s", e)
        return UNAVAILABLE_RESULT
    except Exception as e:
        logger.error("AI connection error during evaluate_security: %s", e)
        return UNAVAILABLE_RESULT

    result = _safe_parse_ollama_response(raw)

    if result is None:
        logger.warning("Failed to parse Ollama response: %.200s", raw)
        return UNAVAILABLE_RESULT

    return {
        "ai_score": result.get("ai_score", 50),
        "ai_feedback": result.get("ai_feedback", ""),
        "ai_suggestions": result.get("ai_suggestions", []),
    }


async def generate_password(
    length: int = 16,
    context: str | None = None,
    complexity_level: str = "high",
    style: str = "compound",
    word_count: int | None = None,
    theme: str | None = None,
    personal_words: list[str] | None = None,
) -> dict:
    params = [f"- Length: {length} characters", f"- Style: {style}"]
    if complexity_level:
        params.append(f"- Complexity: {complexity_level}")
    if context:
        params.append(f"- Context: {context}")
    if word_count:
        params.append(f"- Word count: {word_count}")
    if theme:
        params.append(f"- Theme: {theme}")
    if personal_words:
        params.append(f"- Personal words: {', '.join(personal_words)}")
    user_prompt = (
        "Generate a password with:\n"
        + "\n".join(params)
        + "\nReturn JSON with generated_password and explanation."
    )

    try:
        raw = await _call_ai(GENERATE_SYSTEM_PROMPT, user_prompt, num_predict=GENERATE_NUM_PREDICT)
    except httpx.ReadTimeout:
        logger.error("AI timeout during generate_password")
        raise
    except httpx.HTTPStatusError as e:
        logger.error("AI HTTP error during generate_password: %s", e)
        raise
    except Exception as e:
        logger.error("AI connection error during generate_password: %s", e)
        raise

    result = _safe_parse_ollama_response(raw)

    if result is None:
        logger.warning("Failed to parse AI response during generate: %.200s", raw)
        raise ValueError("AI returned invalid response")

    return {
        "generated_password": result.get("generated_password", ""),
        "explanation": result.get("explanation", ""),
    }
