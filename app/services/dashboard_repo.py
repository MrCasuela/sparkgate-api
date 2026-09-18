"""Panel de gobernanza (HU16) con aislamiento por organización (HU21 AC3).

Toda lectura y escritura lleva el org_id del caller. El aislamiento es 100%
application-side, sin RLS: si una función de este módulo pierde su filtro, una
empresa ve las credenciales de otra. El org_id llega siempre resuelto desde la
tabla organizations por require_enterprise, nunca desde un claim del token.
"""

from datetime import datetime, timezone

from app.services.db_client import get_supabase_admin

MEMBERS_TABLE = "dashboard_members"
CREDENTIALS_TABLE = "dashboard_credentials"
AUDIT_LOG_TABLE = "dashboard_audit_log"


def list_members_with_credentials(org_id: str) -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(MEMBERS_TABLE)
        .select(f"*, {CREDENTIALS_TABLE}(*)")
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
        .select("*")
        .eq("id", member_id)
        .eq("org_id", org_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def get_credential(credential_id: str, org_id: str) -> dict | None:
    """La credencial no guarda org_id: la tenencia se resuelve por embed !inner
    sobre dashboard_members, así el filtro lo aplica Postgres en una sola ida y
    vuelta. Una credencial de otra organización devuelve None, y el
    `if credential is None: 404` que ya tienen los handlers cumple AC3 sin una
    rama nueva (mismo criterio anti-enumeración que el vault personal)."""
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .select(f"*, {MEMBERS_TABLE}!inner(org_id)")
        .eq("id", credential_id)
        .eq(f"{MEMBERS_TABLE}.org_id", org_id)
        .maybe_single()
        .execute()
    )
    row = result.data if result else None
    if row is not None:
        row.pop(MEMBERS_TABLE, None)
    return row


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
    member_id: str,
    service_name: str,
    supabase_user_id: str,
) -> dict:
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .insert(
            {
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


def update_credential_status(credential_id: str, status: str) -> None:
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).update(
        {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", credential_id).execute()


def insert_audit_log(
    *,
    org_id: str,
    actor_email: str,
    member_id: str,
    action: str,
    credential_id: str | None = None,
    credential_type: str | None = None,
    vault_item_id: str | None = None,
) -> None:
    # credential_id/credential_type son opcionales desde HU21: un evento de
    # bóveda (consultar_vault_miembro) no tiene credencial de gobernanza
    # asociada, tiene vault_item_id.
    admin = get_supabase_admin()
    admin.table(AUDIT_LOG_TABLE).insert(
        {
            "org_id": org_id,
            "actor_email": actor_email,
            "member_id": member_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "vault_item_id": vault_item_id,
            "action": action,
        }
    ).execute()


def detach_supabase_user(user_id: str) -> int:
    """Clear supabase_user_id on any credential or member linked to a deleted
    account (Ley 21.719 erasure), without deleting the dashboard_members
    governance record itself — that row tracks the org's own offboarding
    history (HU16).

    El vínculo del miembro también se corta: desde HU21 es el puente que usa
    la empresa para abrir la bóveda del trabajador, y dejarlo apuntando a un
    usuario borrado haría que ese endpoint use un owner_id muerto como AAD.
    """
    admin = get_supabase_admin()
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


def list_audit_log(org_id: str) -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(AUDIT_LOG_TABLE)
        .select("*")
        .eq("org_id", org_id)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data
