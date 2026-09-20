"""Panel de gobernanza (HU16) con aislamiento por organización (HU21 AC3).

Toda lectura y escritura lleva el org_id del caller. El aislamiento es 100%
application-side (RLS deny-all cierra solo el acceso directo con la clave anon; el
backend usa service_role, que lo ignora): si una función de este módulo pierde su filtro, una
empresa ve las credenciales de otra. El org_id llega siempre resuelto desde la
tabla organizations por require_enterprise, nunca desde un claim del token.
"""

import re
from datetime import datetime, timezone

from app.services import audit_chain, credential_secret_repo
from app.services.db_client import get_supabase_admin

# Un motivo de denegación es un enum, nunca un valor libre (ver insert_audit_log).
_DENIED_REASON_RE = re.compile(r"[a-z_]{1,40}")

MEMBERS_TABLE = "dashboard_members"
CREDENTIALS_TABLE = "dashboard_credentials"
AUDIT_LOG_TABLE = "dashboard_audit_log"


# Columnas explícitas, nunca select("*"): dashboard_credentials va a convivir con una
# tabla de sobres cifrados, y un "*" arrastraría al proceso columnas que ningún
# listado debe tocar. Hoy Pydantic descartaría lo que sobre, pero descartar en
# silencio es exactamente el mecanismo que ya falló una vez (G8) y no debe custodiar
# un secreto. El criptograma vive en otra tabla, alcanzable desde un solo módulo.
CREDENTIAL_COLUMNS = (
    "id, org_id, member_id, type, service_name, username, "
    "supabase_user_id, status, secret_updated_at, rotation_required, updated_at"
)
MEMBER_COLUMNS = "id, org_id, full_name, email, role_title, supabase_user_id, created_at"


def list_members_with_credentials(org_id: str) -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(MEMBERS_TABLE)
        .select(f"{MEMBER_COLUMNS}, {CREDENTIALS_TABLE}({CREDENTIAL_COLUMNS})")
        .eq("org_id", org_id)
        .order("full_name")
        .execute()
    )
    members = []
    for row in result.data:
        credentials = row.pop(CREDENTIALS_TABLE, []) or []
        row["credentials"] = credentials
        members.append(row)
    return members


def get_member(member_id: str, org_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(MEMBERS_TABLE)
        .select(MEMBER_COLUMNS)
        .eq("id", member_id)
        .eq("org_id", org_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def get_credential(credential_id: str, org_id: str) -> dict | None:
    """La credencial es de la ORGANIZACIÓN y lleva su org_id en la propia fila, así
    que la tenencia es un .eq directo. Una credencial de otra organización devuelve
    None, y el `if credential is None: 404` que ya tienen los handlers cumple AC3
    sin una rama nueva (mismo criterio anti-enumeración que el vault personal).
    """
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .select(CREDENTIAL_COLUMNS)
        .eq("id", credential_id)
        .eq("org_id", org_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def list_credentials(org_id: str, *, assigned: bool | None = None) -> list[dict]:
    """Credenciales de la organización. assigned=False es el pool sin asignar, que
    por definición no aparece en list_members_with_credentials."""
    admin = get_supabase_admin()
    query = admin.table(CREDENTIALS_TABLE).select(CREDENTIAL_COLUMNS).eq("org_id", org_id)
    if assigned is False:
        query = query.is_("member_id", "null")
    elif assigned is True:
        query = query.not_.is_("member_id", "null")
    return query.order("service_name").execute().data


def list_assigned_credentials(user_id: str) -> list[dict]:
    """Credenciales EXTERNAS asignadas a un usuario, visto desde el trabajador.

    Solo externas: la cuenta interna es su propio acceso a SparkGate, no una
    credencial que la empresa le haya asignado.
    """
    admin = get_supabase_admin()
    members = (
        admin.table(MEMBERS_TABLE).select("id").eq("supabase_user_id", user_id).execute().data
    )
    if not members:
        return []
    return (
        admin.table(CREDENTIALS_TABLE)
        .select(CREDENTIAL_COLUMNS)
        .in_("member_id", [m["id"] for m in members])
        .eq("type", "externa")
        .order("service_name")
        .execute()
        .data
    )


def get_assigned_credential(credential_id: str, user_id: str) -> dict | None:
    """La credencial externa, solo si está asignada a un integrante que es este
    usuario. Una que no lo esté devuelve None: ajena e inexistente se ven igual."""
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .select(f"{CREDENTIAL_COLUMNS}, {MEMBERS_TABLE}!inner(supabase_user_id)")
        .eq("id", credential_id)
        .eq("type", "externa")
        .eq(f"{MEMBERS_TABLE}.supabase_user_id", user_id)
        .maybe_single()
        .execute()
    )
    row = result.data if result else None
    if row is not None:
        row.pop(MEMBERS_TABLE, None)
    return row


def has_revoked_internal(member_id: str) -> bool:
    """Si la cuenta SparkGate del integrante fue revocada (se fue de la empresa)."""
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .select("id")
        .eq("member_id", member_id)
        .eq("type", "interna")
        .eq("status", "revocada")
        .limit(1)
        .execute()
    )
    return bool(result.data)


def create_member(
    *,
    org_id: str,
    full_name: str,
    email: str,
    role_title: str | None,
    supabase_user_id: str | None = None,
) -> dict:
    admin = get_supabase_admin()
    result = (
        admin.table(MEMBERS_TABLE)
        .insert(
            {
                "org_id": org_id,
                "full_name": full_name,
                "email": email,
                "role_title": role_title,
                "supabase_user_id": supabase_user_id,
            }
        )
        .execute()
    )
    return result.data[0]


def create_internal_credential(
    *,
    org_id: str,
    member_id: str,
    service_name: str,
    supabase_user_id: str,
) -> dict:
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .insert(
            {
                "org_id": org_id,
                "member_id": member_id,
                "type": "interna",
                "service_name": service_name,
                "supabase_user_id": supabase_user_id,
                "status": "activa",
            }
        )
        .execute()
    )
    return result.data[0]


def create_external_credential(
    *,
    org_id: str,
    member_id: str | None,
    service_name: str,
    username: str | None,
) -> dict:
    """Cuenta en un servicio de terceros. member_id None = pool sin asignar. Hasta
    ahora solo las creaba el seed: no había forma de darlas de alta desde el panel."""
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .insert(
            {
                "org_id": org_id,
                "member_id": member_id,
                "type": "externa",
                "service_name": service_name,
                "username": username,
                "status": "activa",
            }
        )
        .execute()
    )
    return result.data[0]


def reassign_credential(credential_id: str, org_id: str, member_id: str | None) -> None:
    """Cambia el portador de la credencial. No toca criptografía: el secreto está
    atado a la organización, que no cambia, así que reasignar es un UPDATE."""
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).update(
        {"member_id": member_id, "updated_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", credential_id).eq("org_id", org_id).execute()


def mark_secret_saved(credential_id: str, org_id: str, *, username: str | None = None) -> None:
    """Deja constancia de que la credencial tiene un secreto guardado y cuándo se
    rotó. Vive en la fila de la credencial y no se deduce de un join a la tabla de
    sobres, justamente para que el camino de listado nunca toque esa tabla."""
    now = datetime.now(timezone.utc).isoformat()
    # Guardar una contraseña nueva ES rotar: es lo único que apaga rotation_required.
    # Deliberadamente no hay un "descartar" aparte.
    fields = {"secret_updated_at": now, "updated_at": now, "rotation_required": False}
    if username is not None:
        fields["username"] = username
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).update(fields).eq("id", credential_id).eq(
        "org_id", org_id
    ).execute()


def list_member_credentials(member_id: str, org_id: str) -> list[dict]:
    admin = get_supabase_admin()
    return (
        admin.table(CREDENTIALS_TABLE)
        .select(CREDENTIAL_COLUMNS)
        .eq("member_id", member_id)
        .eq("org_id", org_id)
        .order("service_name")
        .execute()
        .data
    )


def set_rotation_required(credential_ids: list[str], org_id: str) -> None:
    """Marca credenciales cuya contraseña conoce alguien que ya no debería."""
    if not credential_ids:
        return
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).update({"rotation_required": True}).in_(
        "id", credential_ids
    ).eq("org_id", org_id).execute()


def delete_credential(credential_id: str, org_id: str) -> None:
    """Compensación: si una credencial se creó pero no se pudo guardar su secreto, se
    borra en vez de dejar una fila a medias que parece completa."""
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).delete().eq("id", credential_id).eq("org_id", org_id).execute()


def update_credential_status(credential_id: str, status: str) -> None:
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).update(
        {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", credential_id).execute()


def insert_audit_log(
    *,
    org_id: str,
    actor_user_id: str,
    actor_email: str | None,
    member_id: str | None,
    action: str,
    credential_id: str | None = None,
    credential_type: str | None = None,
    vault_item_id: str | None = None,
    target_member_id: str | None = None,
    denied_reason: str | None = None,
) -> dict:
    """Entrada en la cadena de auditoría de la organización (payload jsonb).

    Qué se hashea y qué no:
    - `actor_user_id` va DENTRO del payload: es un UUID seudónimo, y es lo que
      identifica al autor de forma verificable.
    - `actor_email` va FUERA del hash, en su propia columna: es un dato personal en
      texto plano. Si el dueño de la cuenta empresa ejerce su derecho de supresión
      (Ley 21.719) se anula sin romper la cadena — el mismo dilema que ya resolvió
      la ADR de supresión para vault_audit_log.

    member_id es None para una credencial sin asignar (pool). target_member_id solo
    se usa al reasignar: a quién pasa la credencial (member_id es de quién sale).

    denied_reason (HU18): por qué el segundo factor rechazó la operación
    (totp_no_enrolado, totp_invalido, ...). Va en el payload SOLO cuando existe, así el
    payload de todas las demás acciones queda idéntico. Tiene que ser un enum
    ([a-z_]+): nunca algo que pueda ser un código TOTP, y eso se exige acá y no se confía
    en quien llama.

    Ningún valor de este payload es una contraseña, y el test que lo sostiene
    inspecciona exactamente este dict.
    """
    if denied_reason is not None and not _DENIED_REASON_RE.fullmatch(denied_reason):
        raise ValueError("denied_reason debe ser un identificador ([a-z_]+), no un valor libre")

    payload = {
        "org_id": org_id,
        "actor_user_id": actor_user_id,
        "member_id": member_id,
        "target_member_id": target_member_id,
        "credential_id": credential_id,
        "credential_type": credential_type,
        "vault_item_id": vault_item_id,
        "action": action,
    }
    if denied_reason is not None:
        payload["denied_reason"] = denied_reason
    return audit_chain.append_entry_jsonb(
        AUDIT_LOG_TABLE, payload, extra={"actor_email": actor_email}
    )


def detach_supabase_user(user_id: str) -> int:
    """Clear supabase_user_id on any credential or member linked to a deleted
    account (Ley 21.719 erasure), without deleting the dashboard_members
    governance record itself — that row tracks the org's own offboarding
    history (HU16).

    El vínculo del miembro también se corta: desde HU21 es el puente que usa
    la empresa para abrir la bóveda del trabajador, y dejarlo apuntando a un
    usuario borrado haría que ese endpoint use un owner_id muerto como AAD.

    NO se toca `username` (R-HU21-9, decidido): es el identificador de una cuenta de la
    empresa —a menudo una cuenta de rol— y la empresa lo necesita para saber cuál es.
    """
    admin = get_supabase_admin()
    # SparkGate guarda cifrada la contraseña vigente de las cuentas internas. Si la
    # cuenta se borra, conservar ese sobre sería retener la contraseña de una cuenta
    # que ya no existe: dato personal sin finalidad. Se borra ANTES de cortar el
    # vínculo, porque después ya no habría cómo saber a qué credenciales pertenecía.
    linked = (
        admin.table(CREDENTIALS_TABLE)
        .select("id")
        .eq("supabase_user_id", user_id)
        .execute()
        .data
    )
    credential_secret_repo.delete_secrets_for_credentials([row["id"] for row in linked])
    result = (
        admin.table(CREDENTIALS_TABLE)
        .update({"supabase_user_id": None, "updated_at": datetime.now(timezone.utc).isoformat()})
        .eq("supabase_user_id", user_id)
        .execute()
    )
    admin.table(MEMBERS_TABLE).update({"supabase_user_id": None}).eq(
        "supabase_user_id", user_id
    ).execute()
    return len(result.data)


# Proyección explícita: una clave que se agregue al payload más adelante no puede
# aflorar sola en la respuesta de la API (el mismo cuidado que las columnas
# explícitas de credenciales: Pydantic descartando en silencio es un mecanismo
# demasiado frágil para custodiar nada).
_AUDIT_PAYLOAD_KEYS = (
    "actor_user_id",
    "member_id",
    "target_member_id",
    "credential_id",
    "credential_type",
    "vault_item_id",
    "action",
    "denied_reason",
)


def _flatten_audit_row(row: dict) -> dict:
    payload = row.get("payload") or {}
    flat = {k: payload.get(k) for k in _AUDIT_PAYLOAD_KEYS}
    flat["id"] = row["id"]
    flat["actor_email"] = row.get("actor_email")
    flat["created_at"] = row["created_at"]
    return flat


def list_audit_log(org_id: str) -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(AUDIT_LOG_TABLE)
        .select("id, org_id, actor_email, payload, created_at")
        .eq("org_id", org_id)
        .order("created_at", desc=True)
        .execute()
    )
    return [_flatten_audit_row(row) for row in result.data]
