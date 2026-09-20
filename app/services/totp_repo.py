"""Persistencia del factor TOTP (HU18): una fila por persona en user_totp_factors.

El sobre cifrado viaja ENTERO en la columna jsonb `secret_envelope`, así que este módulo no
nombra ninguna de las columnas del criptograma de la bóveda y el test hermético que fija
quién puede nombrarlas (tests/test_secret_access.py) sigue valiendo. Lo abre y lo sella
totp_service; acá es un valor opaco.

Mismo patrón que credential_secret_repo: funciones sync, get_supabase_admin() por llamada,
sin try/except, columnas explícitas (nunca select("*")).

`mark_used` y `confirm_factor` son UPDATEs CONDICIONALES y devuelven si tocaron una fila.
Es lo que hace atómico el anti-replay: dos peticiones simultáneas con el mismo código leen
`last_time_step` viejo las dos, pero solo una gana el UPDATE; la otra recibe False y el
servicio la rechaza como reutilizada. Un read-then-write en Python las dejaría pasar a ambas.
"""

from datetime import datetime, timezone

from app.services.db_client import get_supabase_admin

TOTP_TABLE = "user_totp_factors"

FACTOR_COLUMNS = (
    "user_id, secret_envelope, created_at, confirmed_at, "
    "last_time_step, last_used_at, failed_attempts, locked_until"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_factor(user_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(TOTP_TABLE)
        .select(FACTOR_COLUMNS)
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def upsert_pending_factor(*, user_id: str, envelope: dict) -> None:
    """Crea o REEMPLAZA un factor sin confirmar. Reintentar el enrolamiento es normal, y
    el contador anti-replay y los fallos parten de cero porque el secreto es otro."""
    admin = get_supabase_admin()
    now = _now()
    admin.table(TOTP_TABLE).upsert(
        {
            "user_id": user_id,
            "secret_envelope": envelope,
            "confirmed_at": None,
            "last_time_step": None,
            "last_used_at": None,
            "failed_attempts": 0,
            "locked_until": None,
            "updated_at": now,
        },
        on_conflict="user_id",
    ).execute()


def confirm_factor(*, user_id: str, time_step: int) -> bool:
    """Activa el factor con el primer código correcto. Condicional a que siga pendiente
    (no se puede "reconfirmar" uno ya activo) y registra el paso usado: el mismo código
    no vale de nuevo como segundo factor de una operación."""
    admin = get_supabase_admin()
    now = _now()
    result = (
        admin.table(TOTP_TABLE)
        .update(
            {
                "confirmed_at": now,
                "last_time_step": int(time_step),
                "last_used_at": now,
                "failed_attempts": 0,
                "locked_until": None,
                "updated_at": now,
            }
        )
        .eq("user_id", user_id)
        .is_("confirmed_at", "null")
        .execute()
    )
    return bool(result.data)


def mark_used(*, user_id: str, time_step: int) -> bool:
    """Registra el paso de un código ACEPTADO. False = otro request ya lo consumió (o uno
    posterior): la carrera del anti-replay, resuelta por la base y no por Python."""
    admin = get_supabase_admin()
    step = int(time_step)
    now = _now()
    result = (
        admin.table(TOTP_TABLE)
        .update(
            {
                "last_time_step": step,
                "last_used_at": now,
                "failed_attempts": 0,
                "locked_until": None,
                "updated_at": now,
            }
        )
        .eq("user_id", user_id)
        .or_(f"last_time_step.is.null,last_time_step.lt.{step}")
        .execute()
    )
    return bool(result.data)


def mark_failure(*, user_id: str, failed_attempts: int, locked_until: str | None) -> None:
    """Fija el contador de fallos (y el bloqueo, si corresponde). Es read-modify-write a
    propósito: bajo una ráfaga concurrente puede regalar un par de intentos antes de que
    el bloqueo entre, y con 10^6 combinaciones y 5 intentos por ventana no cambia nada."""
    admin = get_supabase_admin()
    admin.table(TOTP_TABLE).update(
        {
            "failed_attempts": int(failed_attempts),
            "locked_until": locked_until,
            "updated_at": _now(),
        }
    ).eq("user_id", user_id).execute()


def delete_factor(user_id: str) -> bool:
    admin = get_supabase_admin()
    result = admin.table(TOTP_TABLE).delete().eq("user_id", user_id).execute()
    return bool(result.data)
