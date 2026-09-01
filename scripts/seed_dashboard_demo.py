"""Seeds a demo PYME org for the SP-1 offboarding dashboard.

Idempotent: safe to run more than once, matches by email/service_name and
skips rows that already exist. Requires SUPABASE_SERVICE_ROLE_KEY in .env.

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


def get_or_create_member(admin, full_name: str, email: str, role_title: str) -> str:
    existing = admin.table(MEMBERS_TABLE).select("id").eq("email", email).execute()
    if existing.data:
        return existing.data[0]["id"]
    inserted = admin.table(MEMBERS_TABLE).insert(
        {"full_name": full_name, "email": email, "role_title": role_title}
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
        {"is_admin": True, "premium": True},
    )
    report("admin@pyme-demo.sparkgate.test", admin_password, "dueño de la PYME, is_admin")
    admin_member_id = get_or_create_member(admin, "Ana Torres", "admin@pyme-demo.sparkgate.test", "Dueña / Admin")
    ensure_credential(admin, admin_member_id, "interna", "SparkGate (cuenta interna)", admin_id)

    bruno_id, bruno_password = get_or_create_auth_user(
        admin, "bruno.diaz@pyme-demo.sparkgate.test", {"premium": False}
    )
    report("bruno.diaz@pyme-demo.sparkgate.test", bruno_password, "empleado")
    bruno_member_id = get_or_create_member(
        admin, "Bruno Díaz", "bruno.diaz@pyme-demo.sparkgate.test", "Ventas"
    )
    ensure_credential(admin, bruno_member_id, "interna", "SparkGate (cuenta interna)", bruno_id)
    ensure_credential(admin, bruno_member_id, "externa", "Google Workspace")

    carla_id, carla_password = get_or_create_auth_user(
        admin, "carla.munoz@pyme-demo.sparkgate.test", {"premium": False}
    )
    report("carla.munoz@pyme-demo.sparkgate.test", carla_password, "empleada")
    carla_member_id = get_or_create_member(
        admin, "Carla Muñoz", "carla.munoz@pyme-demo.sparkgate.test", "Contabilidad"
    )
    ensure_credential(admin, carla_member_id, "interna", "SparkGate (cuenta interna)", carla_id)

    diego_member_id = get_or_create_member(
        admin, "Diego Ríos", "diego.rios@ejemplo-externo.com", "Soporte (contratista externo)"
    )
    ensure_credential(admin, diego_member_id, "externa", "Dropbox Empresarial")

    print("\nSeed completo: 4 miembros (Ana, Bruno, Carla, Diego).")
    if not any_password_shown:
        print("Los usuarios ya existían — no se generaron nuevas contraseñas nuevas.")


if __name__ == "__main__":
    main()
