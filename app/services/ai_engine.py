import json
import logging
import re

import httpx

from app.core.config import settings
from app.services.entropy import calculate as calc_entropy

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


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


async def _call_ollama(system_prompt: str, user_prompt: str, timeout: float = 30.0) -> str:
    """Call Ollama /api/generate. Returns raw response text."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{settings.ollama_url}/api/generate",
            json={
                "model": "llama3.2:3b",
                "system": system_prompt,
                "prompt": user_prompt,
                "stream": False,
                "format": "json",
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    return data.get("response", "")


async def _call_groq(system_prompt: str, user_prompt: str, timeout: float = 30.0) -> str:
    """Call Groq API (OpenAI-compatible). Returns raw response text."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {settings.groq_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.groq_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.7,
                "max_tokens": 200,
                "response_format": {"type": "json_object"},
            },
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    return data["choices"][0]["message"]["content"]


async def _call_ai(system_prompt: str, user_prompt: str, timeout: float = 30.0) -> str:
    """Route to active AI backend based on settings.ai_backend."""
    if settings.ai_backend == "groq":
        return await _call_groq(system_prompt, user_prompt, timeout)
    return await _call_ollama(system_prompt, user_prompt, timeout)


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


async def evaluate_security(password: str, is_pwned: bool) -> dict:
    user_prompt = (
        f"Password to analyze: {password}\n"
        f"HIBP breach status: {'Compromised' if is_pwned else 'Not found in known breaches'}\n"
        "Return JSON with ai_score, ai_feedback, ai_suggestions."
    )

    try:
        raw = await _call_ai(EVALUATE_SYSTEM_PROMPT, user_prompt)
    except httpx.ReadTimeout:
        logger.error("AI timeout during evaluate_security")
        raise
    except httpx.HTTPStatusError as e:
        logger.error("AI HTTP error during evaluate_security: %s", e)
        raise
    except Exception as e:
        logger.error("AI connection error during evaluate_security: %s", e)
        raise

    result = _safe_parse_ollama_response(raw)

    if result is None:
        logger.warning("Failed to parse Ollama response: %.200s", raw)
        # Fallback: derive score from entropy
        entropy = calc_entropy(password)
        entropy_score = min(100, int(entropy / 1.5))
        return {
            "ai_score": entropy_score,
            "ai_feedback": "No se pudo analizar semanticamente. Evaluacion basada solo en complejidad matematica.",
            "ai_suggestions": [
                "Usa una combinacion de mayusculas, minusculas, numeros y simbolos",
                "Evita palabras del diccionario o nombres propios",
                "Usa al menos 12 caracteres",
            ],
        }

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
        raw = await _call_ai(GENERATE_SYSTEM_PROMPT, user_prompt)
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
