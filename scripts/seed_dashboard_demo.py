"""Seeds a demo PYME org for the SP-1 offboarding dashboard.

Idempotent: safe to run more than once, matches by email/service_name and
skips rows that already exist. Requires SUPABASE_SERVICE_ROLE_KEY in .env.

Desde HU21 también crea la organización y vincula cada integrante con su cuenta
de Auth. El user_metadata de la cuenta dueña se reescribe en cada corrida (no
solo al crearla): sin eso, una cuenta sembrada antes de HU21 conserva su
is_admin legacy y require_enterprise le responde 403 en todo el panel.

Desde la etapa C también siembra credenciales de la organización con contraseña
guardada (cifrada con AAD = org_id), para que el reveal se pueda demostrar de fábrica:
  - Bruno · Google Workspace (externa) CON contraseña
  - Carla · cuenta interna SIN contraseña (el camino "no tiene una guardada")
  - Google Ads (cuenta compartida), SIN asignar: el pool y la reasignación
Requiere VAULT_MASTER_KEY; sin ella las credenciales se crean sin secreto.
Las contraseñas de los usuarios de Auth que ya existían no se conocen (el seed no las
resetea), así que no se guardan sobres para sus cuentas internas.

Correr después de scripts/reset_hu21_schema.py.

Usage (from repo root, with venv active):
    python scripts/seed_dashboard_demo.py
"""

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.services import credential_secret_repo, dashboard_repo, vault_crypto  # noqa: E402
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
    org_id: str,
    member_id: str | None,
    type_: str,
    service_name: str,
    supabase_user_id: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """member_id None = credencial sin asignar (pool). Si viene `password` y la clave
    maestra está disponible, se guarda cifrada con AAD = org_id, igual que en la app."""
    query = (
        admin.table(CREDENTIALS_TABLE)
        .select("id")
        .eq("org_id", org_id)
        .eq("service_name", service_name)
    )
    query = query.is_("member_id", "null") if member_id is None else query.eq("member_id", member_id)
    existing = query.execute()
    if existing.data:
        return

    inserted = admin.table(CREDENTIALS_TABLE).insert(
        {
            "org_id": org_id,
            "member_id": member_id,
            "type": type_,
            "service_name": service_name,
            "username": username,
            "supabase_user_id": supabase_user_id,
            "status": "activa",
        }
    ).execute()
    credential_id = inserted.data[0]["id"]

    if password is None:
        return
    if not vault_crypto.is_available():
        print(f"  (sin VAULT_MASTER_KEY: '{service_name}' queda sin contraseña guardada)")
        return
    envelope = vault_crypto.encrypt_secret({"password": password, "notes": None}, aad=org_id)
    credential_secret_repo.upsert_secret(
        credential_id=credential_id, org_id=org_id, envelope=envelope
    )
    dashboard_repo.mark_secret_saved(credential_id, org_id)


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
    ensure_credential(admin, org_id, admin_member_id, "interna", "SparkGate (cuenta interna)", admin_id)

    bruno_id, bruno_password = get_or_create_auth_user(
        admin,
        "bruno.diaz@pyme-demo.sparkgate.test",
        {"premium": False, "plan": "Gratuito", "type_account": "personal", "org_id": org_id},
    )
    report("bruno.diaz@pyme-demo.sparkgate.test", bruno_password, "empleado")
    bruno_member_id = get_or_create_member(
        admin, org_id, "Bruno Díaz", "bruno.diaz@pyme-demo.sparkgate.test", "Ventas", bruno_id
    )
    ensure_credential(admin, org_id, bruno_member_id, "interna", "SparkGate (cuenta interna)", bruno_id)
    # Con contraseña guardada: es la que la empresa le entregaría al reemplazo de Bruno.
    ensure_credential(
        admin, org_id, bruno_member_id, "externa", "Google Workspace",
        username="bruno.diaz@pyme-demo.sparkgate.test",
        password="Demo-Workspace#2026",
    )

    carla_id, carla_password = get_or_create_auth_user(
        admin,
        "carla.munoz@pyme-demo.sparkgate.test",
        {"premium": False, "plan": "Gratuito", "type_account": "personal", "org_id": org_id},
    )
    report("carla.munoz@pyme-demo.sparkgate.test", carla_password, "empleada")
    carla_member_id = get_or_create_member(
        admin, org_id, "Carla Muñoz", "carla.munoz@pyme-demo.sparkgate.test", "Contabilidad", carla_id
    )
    # Sin contraseña guardada a propósito: demuestra el camino "no tiene una guardada".
    ensure_credential(admin, org_id, carla_member_id, "interna", "SparkGate (cuenta interna)", carla_id)

    # Diego queda deliberadamente SIN supabase_user_id: es el contratista externo
    # sin cuenta SparkGate, el caso de prueba de HU21 AC5 (la empresa pide su
    # bóveda y recibe 200 con lista vacía, no un error).
    diego_member_id = get_or_create_member(
        admin, org_id, "Diego Ríos", "diego.rios@ejemplo-externo.com",
        "Soporte (contratista externo)",
    )
    ensure_credential(admin, org_id, diego_member_id, "externa", "Dropbox Empresarial")

    # Credencial SIN asignar: vive en el pool de la organización, no de un integrante.
    # Demuestra el listado ?assigned=false y la reasignación a un reemplazo.
    ensure_credential(
        admin, org_id, None, "externa", "Google Ads (cuenta compartida)",
        username="ads@pyme-demo.sparkgate.test",
        password="Demo-Ads#2026",
    )

    print(f"\nSeed completo: organización {ORG_NAME} ({org_id}) con 4 miembros "
          "(Ana, Bruno, Carla, Diego) y una credencial sin asignar.")
    if not any_password_shown:
        print("Los usuarios ya existían — no se generaron nuevas contraseñas nuevas.")


if __name__ == "__main__":
    main()
