from app.services import audit_chain
from app.services.db_client import get_supabase_admin

VAULT_ITEMS_TABLE = "vault_items"
VAULT_AUDIT_TABLE = "vault_audit_log"


def insert_item(*, user_id: str, service_name: str, username: str | None, secret: dict) -> dict:
    admin = get_supabase_admin()
    result = (
        admin.table(VAULT_ITEMS_TABLE)
        .insert(
            {
                "user_id": user_id,
                "service_name": service_name,
                "username": username,
                **secret,
            }
        )
        .execute()
    )
    return result.data[0]


def list_items(user_id: str) -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(VAULT_ITEMS_TABLE)
        .select("id, service_name, username, created_at, updated_at")
        .eq("user_id", user_id)
        .order("service_name")
        .execute()
    )
    return result.data


def get_item(item_id: str, user_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(VAULT_ITEMS_TABLE)
        .select("*")
        .eq("id", item_id)
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def delete_item(item_id: str, user_id: str) -> bool:
    admin = get_supabase_admin()
    result = (
        admin.table(VAULT_ITEMS_TABLE)
        .delete()
        .eq("id", item_id)
        .eq("user_id", user_id)
        .execute()
    )
    return bool(result.data)


def delete_all_items(user_id: str) -> int:
    admin = get_supabase_admin()
    result = admin.table(VAULT_ITEMS_TABLE).delete().eq("user_id", user_id).execute()
    return len(result.data)


def insert_audit(
    *,
    user_id: str,
    item_id: str | None = None,
    action: str,
    result: str = "ok",
    deleted_count: int | None = None,
    actor_user_id: str | None = None,
) -> dict:
    # Fixed key set on every entry (even when a value is None) so verify_chain's
    # row-to-payload reconstruction always matches what was hashed at insert time.
    #
    # actor_user_id: None cuando el dueño actúa sobre su propia bóveda; el id de
    # quien consultó cuando la empresa abre la bóveda de un trabajador (HU21
    # AC7). Va siempre en el payload, incluso en None, o la cadena deja de
    # verificar.
    payload = {
        "user_id": user_id,
        "item_id": item_id,
        "action": action,
        "result": result,
        "deleted_count": deleted_count,
        "actor_user_id": actor_user_id,
    }
    return audit_chain.append_entry(VAULT_AUDIT_TABLE, payload)


def list_audit(user_id: str) -> list[dict]:
    admin = get_supabase_admin()
    result = (
        admin.table(VAULT_AUDIT_TABLE)
        .select("*")
        .eq("user_id", user_id)
        .order("created_at", desc=True)
        .execute()
    )
    return result.data
