from datetime import datetime, timezone

from app.services.db_client import get_supabase_admin

MEMBERS_TABLE = "dashboard_members"
CREDENTIALS_TABLE = "dashboard_credentials"
AUDIT_LOG_TABLE = "dashboard_audit_log"


def list_members_with_credentials() -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(MEMBERS_TABLE)
        .select(f"*, {CREDENTIALS_TABLE}(*)")
        .order("full_name")
        .execute()
    )
    members = []
    for row in result.data:
        credentials = row.pop(CREDENTIALS_TABLE, []) or []
        row["credentials"] = credentials
        members.append(row)
    return members


def get_credential(credential_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .select("*")
        .eq("id", credential_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def update_credential_status(credential_id: str, status: str) -> None:
    admin = get_supabase_admin()
    admin.table(CREDENTIALS_TABLE).update(
        {"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}
    ).eq("id", credential_id).execute()


def insert_audit_log(
    *,
    actor_email: str,
    member_id: str,
    credential_id: str,
    credential_type: str,
    action: str,
) -> None:
    admin = get_supabase_admin()
    admin.table(AUDIT_LOG_TABLE).insert(
        {
            "actor_email": actor_email,
            "member_id": member_id,
            "credential_id": credential_id,
            "credential_type": credential_type,
            "action": action,
        }
    ).execute()


def detach_supabase_user(user_id: str) -> int:
    """Clear supabase_user_id on any credential linked to a deleted account
    (Ley 21.719 erasure), without touching the dashboard_members governance
    record itself — that row tracks the org's own offboarding history (HU16)."""
    admin = get_supabase_admin()
    result = (
        admin.table(CREDENTIALS_TABLE)
        .update({"supabase_user_id": None, "updated_at": datetime.now(timezone.utc).isoformat()})
        .eq("supabase_user_id", user_id)
        .execute()
    )
    return len(result.data)


def list_audit_log() -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(AUDIT_LOG_TABLE)
        .select("*")
        .order("created_at", desc=True)
        .execute()
    )
    return result.data
