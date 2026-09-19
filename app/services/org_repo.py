"""Organizaciones (HU21 etapa A).

Fuente de verdad de la tenencia: el org_id con el que se filtra todo el panel
de gobernanza sale siempre de acá, nunca del claim del token. El claim es una
cache para gatear rápido; esta tabla es la que manda.

Mismo patrón que dashboard_repo/vault_repo: funciones sync, get_supabase_admin()
por llamada, sin try/except (el error de PostgREST sube tal cual).
"""

from app.services.db_client import get_supabase_admin

ORGANIZATIONS_TABLE = "organizations"


def create_organization(*, owner_user_id: str, name: str) -> dict:
    admin = get_supabase_admin()
    result = (
        admin.table(ORGANIZATIONS_TABLE)
        .insert({"owner_user_id": owner_user_id, "name": name})
        .execute()
    )
    return result.data[0]


def get_organization_by_owner(owner_user_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(ORGANIZATIONS_TABLE)
        .select("*")
        .eq("owner_user_id", owner_user_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def get_organization(org_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(ORGANIZATIONS_TABLE)
        .select("*")
        .eq("id", org_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None
