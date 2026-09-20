"""Punto de paso único para leer un secreto que NO es del caller.

Toda lectura de un secreto ajeno pasa por `read_foreign_secret`: hoy el reveal de la
bóveda personal de un trabajador, y el de una credencial de la organización. No
existe otra forma de obtener plaintext ajeno, y un test escanea las rutas para que
siga siendo así.

Esto no es gateo de identidad (eso es dependencies.py) sino de ACCESO A SECRETOS, por
eso vive acá. El segundo factor (TOTP, HU18) se verifica en `_verify_step_up` y en ningún
otro lado. Las lecturas lo alcanzan por `read_foreign_secret`; las ESCRITURAS sensibles
(rotar, sugerir, aplicar una contraseña) por `require_step_up`, que entra por el mismo
verificador: hay una sola puerta para el segundo factor, no una por ruta.

Lo que NO pasa por acá: `GET /api/v1/vault/items/{id}`, el dueño leyendo lo suyo.
Meterlo obligaría a pedirle TOTP al trabajador para ver su propia contraseña, que no
es lo que HU18 pide. Sí pasa por acá el trabajador que retira una credencial que la
ORGANIZACIÓN le asignó (/me/credentials/{id}/reveal): ese secreto no es suyo.
"""

import logging
from typing import Callable, Literal

from app.core.exceptions import ServiceUnavailableError, StepUpRequired
from app.services import totp_service, vault_crypto

logger = logging.getLogger("sparkgate.secret_access")

Scope = Literal[
    "vault_item",
    "org_credential",
    "credential_rotation",
    "credential_suggestion",
    "credential_secret_write",
]

# Motivos que recibe on_denied, para que cada ruta escriba SU auditoría de denegado
# (son distintas en cada log: no se fuerza acá un esquema de dos tablas).
#
# on_denied recibe un solo argumento: DENIED_INTEGRITY, o el `code` concreto por el que el
# segundo factor rechazó (uno de los cuatro TOTP_*). Ya no hay un motivo genérico
# "step_up": la auditoría necesita saber POR QUÉ, y la ruta se entera sin cambiar la firma
# del callback.
DENIED_INTEGRITY = "integridad"
TOTP_NO_ENROLADO = totp_service.NO_ENROLADO
TOTP_INVALIDO = totp_service.INVALIDO
TOTP_REUTILIZADO = totp_service.REUTILIZADO
TOTP_BLOQUEADO = totp_service.BLOQUEADO


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
    """HU18. El ÚNICO lugar del sistema donde se verifica el segundo factor.

    El factor es del CALLER (quien pide), no del dueño del dato: es a él a quien se le
    exige demostrar que tiene el segundo factor.

    `scope` no selecciona factor: hay uno por persona y todos los alcances lo usan. Se
    conserva en la firma porque distingue las operaciones en los logs y para que un
    factor por alcance sea un cambio local.

    Una lectura de base por operación sensible. Es aceptable: son operaciones de baja
    frecuencia y auditadas, y verify_token ya paga una ida y vuelta de red a GoTrue en
    CADA request. NO se cachea a propósito: cachear el estado de un factor es
    exactamente lo que mantendría vivo uno recién desactivado.

    Si el factor no se puede verificar (falta TOTP_MASTER_KEY, el sobre no abre) falla
    CERRADO con 503: no poder verificar no es lo mismo que un código inválido, y jamás
    se deja pasar por eso.
    """
    try:
        totp_service.verify(caller["id"], code)
    except totp_service.TotpDenied as denied:
        # Solo el motivo: nunca el código ni el secreto.
        logger.warning("Segundo factor denegado (scope=%s, motivo=%s)", scope, denied.code)
        raise StepUpRequired(code=denied.code) from None
    except totp_service.TotpUnavailable:
        logger.error("Segundo factor imposible de verificar (scope=%s): falla cerrado", scope)
        raise ServiceUnavailableError(
            "Segundo factor",
            detail="El segundo factor no se puede verificar en este momento. "
            "Se rechaza la operación en vez de omitirlo.",
        ) from None


def require_step_up(
    *,
    caller: dict,
    scope: Scope,
    code: str | None,
    on_denied: Callable[[str], None] | None = None,
) -> None:
    """Exige el segundo factor para una operación sensible que NO lee un secreto.

    Es el mismo punto de paso que usa read_foreign_secret: las dos entran por
    _verify_step_up. Existe para que las rutas de escritura no dupliquen el try/except ni
    la llamada a on_denied.

    Cada ruta la llama DESPUÉS de sus guardas (404, tipo, estado) y ANTES de cualquier
    efecto: así no se quema un código (uno cada 30 s) en una petición que igual daría 400,
    y un rechazo no deja la cuenta a medio rotar.

    No comprueba la clave maestra de la bóveda: el factor está sellado con
    TOTP_MASTER_KEY, otra clave, justamente para que revocar a alguien no dependa de que
    la KEK esté arriba.
    """
    try:
        _verify_step_up(caller, scope, code)
    except StepUpRequired as exc:
        if on_denied is not None:
            on_denied(exc.code)
        raise


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
      2. segundo factor (HU18)                        -> 403 StepUpRequired
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

    require_step_up(caller=caller, scope=scope, code=step_up_code, on_denied=on_denied)

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
    "TOTP_BLOQUEADO",
    "TOTP_INVALIDO",
    "TOTP_NO_ENROLADO",
    "TOTP_REUTILIZADO",
    "Scope",
    "StepUpRequired",
    "is_available",
    "read_foreign_secret",
    "require_available",
    "require_step_up",
    "seal_secret",
]
