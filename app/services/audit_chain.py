"""Hash-chained audit log (foundation for HU19).

Each entry stores the SHA-256 hash of its own payload concatenated with the
previous entry's hash. Recomputing the chain end-to-end detects any entry that
was altered or deleted after the fact — the log doesn't prevent tampering, it
makes it detectable.

Payloads must never contain secrets or free-text identifiers (service names,
emails): only UUIDs and enums. This is deliberate so that deleting a user's
account (Ley 21.719 right to erasure) never has to touch, and therefore never
has to break, the chain — the user_id simply stops mapping to a real person.

Dos formas de cadena, que comparten el cálculo del hash:

- Por columnas (`append_entry` / `verify_chain`): el payload es "todas las
  columnas de la fila salvo id/seq/prev_hash/entry_hash/created_at". Es la de
  `vault_audit_log`. Agregar una columna invalida toda la historia (lo que obligó
  a recrear la tabla en HU21), así que su key set es fijo por necesidad.
- Por payload jsonb (`append_entry_jsonb` / `verify_chain_jsonb`): el payload
  vive entero en una columna y es ESA columna la que se hashea, no la forma de la
  tabla. Un ADD COLUMN posterior ya no puede tocar lo hasheado. Es la forma
  recomendada para toda cadena nueva (ver _Leccion-cadena-hash-vs-evolucion-de-
  esquema). Es la de `dashboard_audit_log`.
"""

import hashlib
import json
import logging

from app.services.db_client import get_supabase_admin

GENESIS = "0" * 64

logger = logging.getLogger("sparkgate.audit_chain")

# Dos escritores concurrentes leen la misma cola y calculan el mismo prev_hash; el
# segundo insert choca con la restricción UNIQUE de prev_hash. Esa restricción es lo
# que impide bifurcar la cadena en silencio, así que el choque es CORRECTO y se
# reintenta releyendo la cola, en vez de dejarlo subir como un 500.
MAX_APPEND_ATTEMPTS = 3
_UNIQUE_VIOLATION = "23505"


def compute_hash(prev_hash: str, payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _tail_hash(admin, table: str) -> str:
    last = (
        admin.table(table)
        .select("entry_hash")
        .order("seq", desc=True)
        .limit(1)
        .execute()
    )
    return last.data[0]["entry_hash"] if last.data else GENESIS


def _verify(table: str, payload_of_row) -> tuple[bool, str | None]:
    """Recorre la cadena por seq y recalcula cada hash. `payload_of_row` es lo único
    que difiere entre las dos formas de cadena: cómo se obtiene el payload de una fila."""
    admin = get_supabase_admin()
    result = admin.table(table).select("*").order("seq").execute()

    prev_hash = GENESIS
    for row in result.data:
        payload = payload_of_row(row)
        if row["prev_hash"] != prev_hash:
            return False, row["id"]
        expected = compute_hash(prev_hash, payload)
        if row["entry_hash"] != expected:
            return False, row["id"]
        prev_hash = row["entry_hash"]

    return True, None


def _is_chain_race(error: Exception) -> bool:
    return getattr(error, "code", None) == _UNIQUE_VIOLATION or _UNIQUE_VIOLATION in str(error)


def _append(table: str, payload: dict, make_row) -> dict:
    """Lee la cola, calcula el hash e inserta; si otro escritor ganó la cola, relee y
    reintenta. Cada intento recalcula todo desde la cola nueva: reintentar el mismo
    insert repetiría el mismo prev_hash y volvería a chocar."""
    admin = get_supabase_admin()
    for attempt in range(1, MAX_APPEND_ATTEMPTS + 1):
        prev_hash = _tail_hash(admin, table)
        entry_hash = compute_hash(prev_hash, payload)
        row = make_row(prev_hash, entry_hash)
        try:
            result = admin.table(table).insert(row).execute()
            return result.data[0] if result.data else row
        except Exception as e:
            if attempt == MAX_APPEND_ATTEMPTS or not _is_chain_race(e):
                raise
            logger.warning(
                "Colisión de prev_hash en %s (intento %s/%s): otro escritor ganó la cola, reintento",
                table,
                attempt,
                MAX_APPEND_ATTEMPTS,
            )
    raise AssertionError("inalcanzable")  # pragma: no cover


def append_entry(table: str, payload: dict) -> dict:
    return _append(
        table,
        payload,
        lambda prev_hash, entry_hash: {**payload, "prev_hash": prev_hash, "entry_hash": entry_hash},
    )


def verify_chain(table: str) -> tuple[bool, str | None]:
    """Recompute the whole chain. Returns (True, None) if intact, or
    (False, <id of the first broken entry>) otherwise."""
    return _verify(
        table,
        lambda row: {
            k: v
            for k, v in row.items()
            if k not in ("id", "seq", "prev_hash", "entry_hash", "created_at")
        },
    )


PAYLOAD_COLUMN = "payload"


def _assert_jsonb_safe(payload: dict) -> None:
    # jsonb normaliza los números (1.0 vuelve como 1) y no serializa datetimes, así
    # que un valor así cambiaría el json.dumps al releer y rompería el hash sin que
    # nadie haya tocado la fila. Se prohíbe en el origen en vez de descubrirlo en
    # verify_chain.
    for key, value in payload.items():
        if not isinstance(value, (str, bool, type(None))):
            raise TypeError(
                f"Payload de auditoría jsonb: '{key}' es {type(value).__name__}; "
                "solo se admiten str, bool y None."
            )


def append_entry_jsonb(
    table: str,
    payload: dict,
    *,
    payload_column: str = PAYLOAD_COLUMN,
    extra: dict | None = None,
) -> dict:
    """Como append_entry, pero el payload va ENTERO a una columna jsonb y es esa
    columna la que se hashea.

    `extra` son columnas que se guardan FUERA del hash: datos personales que la
    supresión (Ley 21.719) debe poder anular sin romper la cadena, como un email.

    El key set del payload deja de ser load-bearing: agregar una clave más adelante
    no toca lo ya hasheado. Se mantiene como convención de lectura, no como
    requisito criptográfico.
    """
    _assert_jsonb_safe(payload)
    return _append(
        table,
        payload,
        lambda prev_hash, entry_hash: {
            payload_column: payload,
            **(extra or {}),
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        },
    )


def verify_chain_jsonb(
    table: str, *, payload_column: str = PAYLOAD_COLUMN
) -> tuple[bool, str | None]:
    """Recalcula la cadena leyendo el payload verbatim de la columna jsonb.
    Devuelve (True, None) o (False, <id de la primera entrada rota>)."""
    return _verify(table, lambda row: row[payload_column])


__all__ = [
    "GENESIS",
    "PAYLOAD_COLUMN",
    "compute_hash",
    "append_entry",
    "verify_chain",
    "append_entry_jsonb",
    "verify_chain_jsonb",
]
