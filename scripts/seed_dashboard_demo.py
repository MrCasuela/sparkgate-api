"""Seeds a demo PYME org for the SP-1 offboarding dashboard.

Idempotent: safe to run more than once, matches by email/service_name and
skips rows that already exist. Requires SUPABASE_SERVICE_ROLE_KEY in .env.

Desde HU21 también crea la organización y vincula cada integrante con su cuenta
de Auth. El user_metadata de la cuenta dueña se reescribe en cada corrida (no
solo al crearla): sin eso, una cuenta sembrada antes de HU21 conserva su
is_admin legacy y require_enterprise le responde 403 en todo el panel.

Correr después de scripts/reset_hu21_schema.py.

Usage (from repo root, with venv active):
    python scripts/seed_dashboard_demo.py
"""

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

MEMBERS_TABLE = "dashboard_members"
CREDENTIALS_TABLE = "dashboard_credentials"
ORGANIZATIONS_TABLE = "organizations"

ORG_NAME = "PYME Demo"


def random_password() -> str:
    return secrets.token_urlsafe(12)


def get_or_create_auth_user(admin, email: str, user_metadata: dict) -> tuple[str, str | None]:
    """Returns (user_id, password). password is None if the user already existed
    (we never know or reset an existing user's password here)."""
    existing = admin.auth.admin.list_users()
    users = existing.users if hasattr(existing, "users") else existing
    for u in users:
        if u.email == email:
            return u.id, None

    password = random_password()
    result = admin.auth.admin.create_user(
        {
            "email": email,
            "password": password,
            "email_confirm": True,
            "user_metadata": user_metadata,
        }
    )
    return result.user.id, password


def get_or_create_organization(admin, owner_user_id: str, name: str) -> str:
    existing = (
        admin.table(ORGANIZATIONS_TABLE)
        .select("id")
        .eq("owner_user_id", owner_user_id)
        .execute()
    )
    if existing.data:
        return existing.data[0]["id"]
    inserted = admin.table(ORGANIZATIONS_TABLE).insert(
        {"owner_user_id": owner_user_id, "name": name}
    ).execute()
    return inserted.data[0]["id"]


def get_or_create_member(
    admin,
    org_id: str,
    full_name: str,
    email: str,
    role_title: str,
    supabase_user_id: str | None = None,
) -> str:
    existing = (
        admin.table(MEMBERS_TABLE)
        .select("id")
        .eq("email", email)
        .eq("org_id", org_id)
        .execute()
    )
    if existing.data:
        return existing.data[0]["id"]
    inserted = admin.table(MEMBERS_TABLE).insert(
        {
            "org_id": org_id,
            "full_name": full_name,
            "email": email,
            "role_title": role_title,
            "supabase_user_id": supabase_user_id,
        }
    ).execute()
    return inserted.data[0]["id"]


def ensure_credential(
    admin,
    member_id: str,
    type_: str,
    service_name: str,
    supabase_user_id: str | None = None,
) -> None:
    existing = (
        admin.table(CREDENTIALS_TABLE)
        .select("id")
        .eq("member_id", member_id)
        .eq("service_name", service_name)
        .execute()
    )
    if existing.data:
        return
    admin.table(CREDENTIALS_TABLE).insert(
        {
            "member_id": member_id,
            "type": type_,
            "service_name": service_name,
            "supabase_user_id": supabase_user_id,
            "status": "activa",
        }
    ).execute()


def main() -> None:
    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no está configurada en .env. Abortando.")
        sys.exit(1)

    admin = get_supabase_admin()
    any_password_shown = False

    def report(email: str, password: str | None, role: str) -> None:
        nonlocal any_password_shown
        if password:
            any_password_shown = True
            print(f"  {email} / {password}  ({role})")

    admin_id, admin_password = get_or_create_auth_user(
        admin,
        "admin@pyme-demo.sparkgate.test",
        {"premium": True, "plan": "Gratuito", "type_account": "enterprise"},
    )
    report("admin@pyme-demo.sparkgate.test", admin_password, "dueña de la PYME, cuenta empresa")

    org_id = get_or_create_organization(admin, admin_id, ORG_NAME)

    # get_or_create_auth_user devuelve temprano si el usuario ya existía en Auth,
    # así que el user_metadata de una cuenta sembrada antes de HU21 seguiría
    # diciendo {is_admin: True} y require_enterprise le respondería 403 en todo
    # el panel. Se reescribe siempre, y is_admin queda anulado explícitamente:
    # el flag legacy ya no existe, no alcanza con dejar de leerlo.
    admin.auth.admin.update_user_by_id(
        admin_id,
        {
            "user_metadata": {
                "premium": True,
                "plan": "Gratuito",
                "type_account": "enterprise",
                "org_id": org_id,
                "is_admin": None,
            }
        },
    )

    admin_member_id = get_or_create_member(
        admin, org_id, "Ana Torres", "admin@pyme-demo.sparkgate.test", "Dueña / Admin", admin_id
    )
    ensure_credential(admin, admin_member_id, "interna", "SparkGate (cuenta interna)", admin_id)

    bruno_id, bruno_password = get_or_create_auth_user(
        admin,
        "bruno.diaz@pyme-demo.sparkgate.test",
        {"premium": False, "plan": "Gratuito", "type_account": "personal", "org_id": org_id},
    )
    report("bruno.diaz@pyme-demo.sparkgate.test", bruno_password, "empleado")
    bruno_member_id = get_or_create_member(
        admin, org_id, "Bruno Díaz", "bruno.diaz@pyme-demo.sparkgate.test", "Ventas", bruno_id
    )
    ensure_credential(admin, bruno_member_id, "interna", "SparkGate (cuenta interna)", bruno_id)
    ensure_credential(admin, bruno_member_id, "externa", "Google Workspace")

    carla_id, carla_password = get_or_create_auth_user(
        admin,
        "carla.munoz@pyme-demo.sparkgate.test",
        {"premium": False, "plan": "Gratuito", "type_account": "personal", "org_id": org_id},
    )
    report("carla.munoz@pyme-demo.sparkgate.test", carla_password, "empleada")
    carla_member_id = get_or_create_member(
        admin, org_id, "Carla Muñoz", "carla.munoz@pyme-demo.sparkgate.test", "Contabilidad", carla_id
    )
    ensure_credential(admin, carla_member_id, "interna", "SparkGate (cuenta interna)", carla_id)

    # Diego queda deliberadamente SIN supabase_user_id: es el contratista externo
    # sin cuenta SparkGate, el caso de prueba de HU21 AC5 (la empresa pide su
    # bóveda y recibe 200 con lista vacía, no un error).
    diego_member_id = get_or_create_member(
        admin, org_id, "Diego Ríos", "diego.rios@ejemplo-externo.com",
        "Soporte (contratista externo)",
    )
    ensure_credential(admin, diego_member_id, "externa", "Dropbox Empresarial")

    print(f"\nSeed completo: organización {ORG_NAME} ({org_id}) con 4 miembros "
          "(Ana, Bruno, Carla, Diego).")
    if not any_password_shown:
        print("Los usuarios ya existían — no se generaron nuevas contraseñas nuevas.")


if __name__ == "__main__":
    main()
