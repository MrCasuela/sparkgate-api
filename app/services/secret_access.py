"""Punto de paso único para leer un secreto que NO es del caller.

Toda lectura de un secreto ajeno pasa por `read_foreign_secret`: hoy el reveal de la
bóveda personal de un trabajador, y el de una credencial de la organización. No
existe otra forma de obtener plaintext ajeno, y un test escanea las rutas para que
siga siendo así.

Esto no es gateo de identidad (eso es dependencies.py) sino de ACCESO A SECRETOS, por
eso vive acá. Existe para que HU18 sea un solo cambio: el segundo factor (TOTP) se
verifica en `_verify_step_up` y en ningún otro lado. Ninguna ruta cambia.

Lo que NO pasa por acá: `GET /api/v1/vault/items/{id}`, el dueño leyendo lo suyo.
Meterlo obligaría a pedirle TOTP al trabajador para ver su propia contraseña, que no
es lo que HU18 pide.
"""

import logging
from typing import Callable, Literal

from app.core.exceptions import ServiceUnavailableError, StepUpRequired
from app.services import vault_crypto

logger = logging.getLogger("sparkgate.secret_access")

Scope = Literal["vault_item", "org_credential"]

# Motivos que recibe on_denied, para que cada ruta escriba SU auditoría de denegado
# (son distintas en cada log: no se fuerza acá un esquema de dos tablas).
DENIED_INTEGRITY = "integridad"
DENIED_STEP_UP = "step_up"


def require_available() -> None:
    """503 si la clave maestra falta o es inválida.

    Las rutas la llaman ANTES de tocar la base (AC8: sin KEK no se lee nada, y no se
    consulta nada para averiguarlo). read_foreign_secret la repite por defensa.
    """
    if not vault_crypto.is_available():
        raise ServiceUnavailableError(
            "Vault",
            detail="El módulo de bóveda no está operativo: falta la clave maestra.",
        )


def seal_secret(*, subject_id: str, password: str, notes: str | None = None) -> dict:
    """Cifra un secreto que va a quedar bajo un dueño distinto de quien lo escribe.

    Es la contraparte de read_foreign_secret y usa el mismo `subject_id`: el AAD es
    el dueño del dato (el org_id para una credencial de empresa), no el caller.
    Lanza RuntimeError si no hay clave maestra: quien llama decide si eso bloquea la
    operación (guardar una contraseña a mano) o solo degrada (revocar a alguien no
    puede depender de que la KEK esté arriba).
    """
    return vault_crypto.encrypt_secret({"password": password, "notes": notes}, aad=subject_id)


def is_available() -> bool:
    return vault_crypto.is_available()


def _verify_step_up(caller: dict, scope: Scope, code: str | None) -> None:
    """HU18. Hoy no hace nada.

    Mañana: leer el código TOTP, validarlo contra el secreto del caller y lanzar
    StepUpRequired si falta o no es válido. ES EL ÚNICO LUGAR QUE HU18 TIENE QUE
    TOCAR para las lecturas de secretos ajenos.
    """
    return None


def read_foreign_secret(
    *,
    caller: dict,
    scope: Scope,
    subject_id: str,
    target_id: str,
    envelope: dict,
    step_up_code: str | None = None,
    on_denied: Callable[[str], None] | None = None,
) -> dict:
    """Devuelve el plaintext `{"password": ..., "notes": ...}` de un secreto ajeno.

    Orden, que es parte del contrato:
      1. la clave maestra tiene que estar disponible  -> 503
      2. segundo factor (HU18, hoy no-op)             -> 403 StepUpRequired
      3. descifrar con AAD = subject_id               -> InvalidTag => 503

    `subject_id` es el dueño DEL DATO, leído de la misma fila que el criptograma: el
    user_id de una persona para un ítem de bóveda, el org_id de la organización para
    una credencial de empresa. Nunca es el id de quien pregunta: el AAD dice de quién
    es el dato, no quién lo pide. Por eso el acceso de la empresa no debilita el
    cifrado — mover una fila bajo otro dueño sigue rompiendo el tag GCM.

    InvalidTag responde 503, no 404 (escondería una adulteración, que es justo lo que
    el tag existe para hacer visible) ni 500 (sin traza).

    NO audita el camino feliz: los dos logs y sus nombres de acción difieren, y
    forzarlo acá acoplaría este punto de paso a los dos esquemas. Lo que sí garantiza
    es que no hay forma de obtener plaintext ajeno sin pasar por el paso 2.
    """
    require_available()

    try:
        _verify_step_up(caller, scope, step_up_code)
    except StepUpRequired:
        if on_denied is not None:
            on_denied(DENIED_STEP_UP)
        raise

    try:
        return vault_crypto.decrypt_secret(envelope, aad=subject_id)
    except vault_crypto.InvalidTag:
        if on_denied is not None:
            on_denied(DENIED_INTEGRITY)
        # Nunca el secreto ni el subject en el log: solo qué y cuál.
        logger.error(
            "Fallo de integridad al descifrar (scope=%s, target=%s, kek_version=%s)",
            scope,
            target_id,
            envelope.get("kek_version"),
        )
        raise ServiceUnavailableError(
            "Vault",
            detail="No se pudo descifrar la credencial: el registro no supera "
            "la verificación de integridad.",
        )


__all__ = [
    "DENIED_INTEGRITY",
    "DENIED_STEP_UP",
    "Scope",
    "StepUpRequired",
    "is_available",
    "read_foreign_secret",
    "require_available",
    "seal_secret",
]
