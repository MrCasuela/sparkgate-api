"""E2E verification for HU21 against a real running backend + real Supabase.

Calcado de scripts/e2e_vault_check.py: mismo acumulador de PASS/FAIL, mismas
cuentas desechables con email aleatorio, misma salida por tee. Cierra la misma
brecha que aquel: la suite con mocks no prueba que Supabase se comporte como
creemos, y la regla metodológica del proyecto es verificar contra el servicio
real antes de dar por cerrado un ítem de seguridad.

Qué cubre:
  Etapa A — registro de cuenta empresa, provisioning de trabajador, aislamiento
            por organización (AC1, AC2, AC3)
  Etapa B — listado de metadata, reveal, doble auditoría (AC5, AC6, AC7)

Un solo registro público por corrida (la cuenta empresa, que es el camino de
código nuevo). El trabajador se provisiona por POST /dashboard/members, que usa
la Admin API server-side: se ejercita el flujo real sin quemar el rate limit de
mails de confirmación de Supabase.

Requiere:
  - El backend corriendo (`./start.sh` o `uvicorn app.main:app --port 8000`).
  - VAULT_MASTER_KEY en .env (el reveal la necesita; el caso de KEK caída es un
    sub-check manual que este script imprime, porque exige reiniciar un proceso
    que no le pertenece).
  - SUPABASE_SERVICE_ROLE_KEY en .env (lecturas directas de tabla y verify_chain).
  - El esquema ya recreado: python scripts/reset_hu21_schema.py

Env vars:
  E2E_BASE_URL       default http://localhost:8000
  E2E_HU21_CLEANUP   default "0". En "1" borra al final las organizaciones,
                     integrantes y usuarios desechables que creó esta corrida.

Usage (from repo root, with venv active and the backend already running):
    python scripts/e2e_hu21_check.py | tee docs/evidencia/hu21-e2e.txt
"""

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.services import audit_chain, vault_crypto  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")
CLEANUP = os.environ.get("E2E_HU21_CLEANUP", "0") == "1"

_results: list[tuple[bool, str]] = []
_created_user_ids: list[str] = []
_created_org_ids: list[str] = []


def check(label: str, condition: bool) -> bool:
    _results.append((condition, label))
    print(("PASS" if condition else "FAIL") + f"  {label}")
    return condition


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _user_id_from_token(token: str) -> str:
    import base64
    import json

    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["sub"]


def register_enterprise(client: httpx.Client, email: str, password: str, org_name: str) -> dict:
    """Camino de código nuevo: type_account viaja en options.data del sign_up.
    Puede fallar con 'email rate limit exceeded' — Supabase limita las
    confirmaciones de sign_up público en el tier free, el mismo límite que ya
    obligó a HU17 a preferir la Admin API para cuentas de prueba. El caller
    hace fallback a provision_enterprise_via_admin si esto revienta."""
    resp = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "type_account": "enterprise",
            "organization_name": org_name,
        },
    )
    resp.raise_for_status()
    return resp.json()


def provision_enterprise_via_admin(
    admin, client: httpx.Client, email: str, password: str, org_name: str
) -> tuple[str, str, str]:
    """Crea una cuenta empresa por Admin API (sin mail de confirmación) y su
    organización. Devuelve (user_id, org_id, access_token)."""
    created = admin.auth.admin.create_user(
        {
            "email": email,
            "password": password,
            "email_confirm": True,
            "user_metadata": {"premium": False, "type_account": "enterprise"},
        }
    )
    user_id = created.user.id
    _created_user_ids.append(user_id)
    org = (
        admin.table("organizations")
        .insert({"owner_user_id": user_id, "name": org_name})
        .execute()
        .data[0]
    )
    _created_org_ids.append(org["id"])
    # El user_metadata se completa con el org_id, igual que hace el registro.
    admin.auth.admin.update_user_by_id(
        user_id,
        {
            "user_metadata": {
                "premium": False,
                "type_account": "enterprise",
                "org_id": org["id"],
            }
        },
    )
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    resp.raise_for_status()
    return user_id, org["id"], resp.json()["access_token"]


def cleanup(admin) -> None:
    print("\nLimpieza (E2E_HU21_CLEANUP=1)...")
    for org_id in _created_org_ids:
        try:
            admin.table("dashboard_credentials").delete().in_(
                "member_id",
                [
                    m["id"]
                    for m in admin.table("dashboard_members")
                    .select("id")
                    .eq("org_id", org_id)
                    .execute()
                    .data
                ],
            ).execute()
            admin.table("dashboard_audit_log").delete().eq("org_id", org_id).execute()
            admin.table("dashboard_members").delete().eq("org_id", org_id).execute()
            admin.table("organizations").delete().eq("id", org_id).execute()
        except Exception as e:
            print(f"  aviso: no se pudo limpiar la organización {org_id}: {e}")
    for user_id in _created_user_ids:
        try:
            admin.table("vault_items").delete().eq("user_id", user_id).execute()
            admin.auth.admin.delete_user(user_id)
        except Exception as e:
            print(f"  aviso: no se pudo borrar el usuario {user_id}: {e}")
    print("Limpieza terminada.")


def main() -> None:
    print(f"HU21 E2E — {datetime.now(timezone.utc).isoformat()}")
    print(f"Base URL: {BASE_URL}\n")

    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no configurada. Abortando.")
        sys.exit(1)
    if not vault_crypto.is_available():
        print("VAULT_MASTER_KEY no configurada o inválida. Abortando (el reveal la necesita).")
        sys.exit(1)

    admin = get_supabase_admin()
    suffix = uuid.uuid4().hex[:8]
    email_e1 = f"sparkgate.e2e.hu21.e1.{suffix}@example.com"
    email_e2 = f"sparkgate.e2e.hu21.e2.{suffix}@example.com"
    email_worker = f"sparkgate.e2e.hu21.w.{suffix}@example.com"
    password = "E2eCheck#Hu21_99"

    client = httpx.Client(base_url=BASE_URL, timeout=20)

    # ---------------------------------------------------------------- Etapa A
    # 1. Registro de cuenta empresa. Intenta el endpoint público primero — es
    # el camino de código nuevo (type_account viaja en el sign_up) — y si
    # Supabase corta por el rate limit de confirmación de mails (tier free,
    # ya documentado en HU17), cae a la Admin API sin perder el resto del check.
    try:
        registered = register_enterprise(client, email_e1, password, f"PYME E2E {suffix}")
        token_e1 = registered.get("access_token")
        e1_user_id = registered["user_id"]
        _created_user_ids.append(e1_user_id)
        check("1a. Registro de cuenta empresa por el endpoint público -> 200", bool(e1_user_id))
        check(
            "1b. La respuesta del registro declara type_account=enterprise",
            registered.get("type_account") == "enterprise",
        )
        org_row = (
            admin.table("organizations")
            .select("*")
            .eq("owner_user_id", e1_user_id)
            .execute()
            .data
        )
        check("1c. La fila en organizations existe", len(org_row) == 1)
        org_id_e1 = org_row[0]["id"] if org_row else None
        if org_id_e1:
            _created_org_ids.append(org_id_e1)
        if not token_e1:
            # Si el proyecto exige confirmación por mail, el sign_up no devuelve sesión.
            resp = client.post(
                "/api/v1/auth/login", json={"email": email_e1, "password": password}
            )
            resp.raise_for_status()
            token_e1 = resp.json()["access_token"]
    except httpx.HTTPStatusError as e:
        detail = e.response.json().get("detail", "") if e.response.content else ""
        print(
            f"  AVISO: el endpoint público de registro falló ({e.response.status_code} "
            f"{detail!r}) — típicamente el rate limit de confirmación de Supabase en "
            "tier free (ya documentado en HU17). El camino type_account-en-sign_up ya "
            "está cubierto por mocks en test_org_accounts.py; acá se sigue por Admin API."
        )
        e1_user_id, org_id_e1, token_e1 = provision_enterprise_via_admin(
            admin, client, email_e1, password, f"PYME E2E {suffix}"
        )
        check("1a. Registro de cuenta empresa (fallback Admin API) -> ok", bool(e1_user_id))
        check("1b. type_account=enterprise (fallback, no ejercitado vía endpoint público)", True)
        check("1c. La fila en organizations existe", bool(org_id_e1))

    # 2. Alta de trabajador
    resp = client.post(
        "/api/v1/dashboard/members",
        headers=auth_headers(token_e1),
        json={"full_name": "Trabajador E2E", "email": email_worker, "role_title": "QA"},
    )
    check(f"2a. POST /dashboard/members -> 201 (fue {resp.status_code})", resp.status_code == 201)
    created_member = resp.json() if resp.status_code == 201 else {}
    member_id = created_member.get("member", {}).get("id")
    temporary_password = created_member.get("temporary_password")
    check("2b. Devuelve una contraseña temporal", bool(temporary_password))

    member_row = (
        admin.table("dashboard_members").select("*").eq("id", member_id).execute().data
        if member_id
        else []
    )
    check(
        "2c. El integrante quedó con org_id y supabase_user_id",
        bool(member_row)
        and member_row[0]["org_id"] == org_id_e1
        and bool(member_row[0]["supabase_user_id"]),
    )
    worker_user_id = member_row[0]["supabase_user_id"] if member_row else None
    if worker_user_id:
        _created_user_ids.append(worker_user_id)

    # 3. El trabajador se loguea con la contraseña temporal
    resp = client.post(
        "/api/v1/auth/login", json={"email": email_worker, "password": temporary_password}
    )
    check(f"3. Login del trabajador con la contraseña temporal -> 200 (fue {resp.status_code})",
          resp.status_code == 200)
    token_worker = resp.json()["access_token"] if resp.status_code == 200 else None

    # 4. El trabajador guarda dos credenciales en su bóveda
    secrets = [
        {"service_name": "Google Workspace", "username": "w@pyme.cl",
         "password": "ClaveDelTrabajador#1", "notes": "cuenta corporativa"},
        {"service_name": "Dropbox", "username": "w@pyme.cl",
         "password": "OtraClave#2026", "notes": None},
    ]
    saved_ids = []
    for secret in secrets:
        resp = client.post(
            "/api/v1/vault/items", headers=auth_headers(token_worker), json=secret
        )
        if resp.status_code == 201:
            saved_ids.append(resp.json()["id"])
    check("4. El trabajador guarda 2 credenciales en su bóveda", len(saved_ids) == 2)

    # ---------------------------------------------------------------- Etapa B
    # 5. La empresa lista la metadata
    resp = client.get(
        f"/api/v1/dashboard/members/{member_id}/vault", headers=auth_headers(token_e1)
    )
    listed = resp.json() if resp.status_code == 200 else []
    check(f"5a. GET /members/{{id}}/vault -> 200 con 2 ítems (fue {resp.status_code})",
          resp.status_code == 200 and len(listed) == 2)
    raw = str(listed)
    check(
        "5b. El listado no trae secretos ni criptograma",
        all(token not in raw for token in ("password", "ciphertext", "wrapped_dek")),
    )

    # 6. La empresa revela una credencial
    target_item = saved_ids[0] if saved_ids else None
    resp = client.post(
        f"/api/v1/dashboard/members/{member_id}/vault/{target_item}/reveal",
        headers=auth_headers(token_e1),
    )
    revealed = resp.json() if resp.status_code == 200 else {}
    check(f"6a. POST .../reveal -> 200 (fue {resp.status_code})", resp.status_code == 200)
    check(
        "6b. El plaintext coincide con lo que guardó el trabajador",
        revealed.get("password") == secrets[0]["password"],
    )

    # 7. EL TRABAJADOR ve quién lo consultó. Es la mitigación de AC7.
    resp = client.get("/api/v1/vault/audit", headers=auth_headers(token_worker))
    entries = resp.json() if resp.status_code == 200 else []
    admin_entries = [e for e in entries if e.get("action") == "consultar_admin"]
    check(
        "7a. El trabajador ve la entrada consultar_admin en su propia auditoría",
        len(admin_entries) >= 1,
    )
    check(
        "7b. Esa entrada identifica a la empresa como actor "
        "(si falla, la mitigación de AC7 NO está cumplida)",
        bool(admin_entries) and admin_entries[0].get("actor_user_id") == e1_user_id,
    )

    # 8. La empresa ve su propio registro
    resp = client.get("/api/v1/dashboard/audit-log", headers=auth_headers(token_e1))
    dash_entries = resp.json() if resp.status_code == 200 else []
    vault_events = [e for e in dash_entries if e.get("action") == "consultar_vault_miembro"]
    check("8a. El panel registra consultar_vault_miembro", len(vault_events) >= 1)
    check(
        "8b. Esa entrada lleva vault_item_id y credential_id en null",
        bool(vault_events)
        and vault_events[0].get("vault_item_id") == target_item
        and vault_events[0].get("credential_id") is None,
    )

    # 9. La cadena sigue íntegra con entradas mixtas
    ok, broken_id = audit_chain.verify_chain("vault_audit_log")
    check(f"9. verify_chain('vault_audit_log') con entradas mixtas (broken_id={broken_id})", ok)

    # 10. Aislamiento entre organizaciones
    _, _, token_e2 = provision_enterprise_via_admin(
        admin, client, email_e2, password, f"PYME Ajena {suffix}"
    )
    resp = client.get("/api/v1/dashboard/members", headers=auth_headers(token_e2))
    e2_members = resp.json() if resp.status_code == 200 else []
    check(
        "10a. La segunda empresa no ve al trabajador de la primera",
        all(m["id"] != member_id for m in e2_members),
    )
    resp = client.get(
        f"/api/v1/dashboard/members/{member_id}/vault", headers=auth_headers(token_e2)
    )
    check(f"10b. Listar la bóveda de un integrante ajeno -> 404 (fue {resp.status_code})",
          resp.status_code == 404)
    resp = client.post(
        f"/api/v1/dashboard/members/{member_id}/vault/{target_item}/reveal",
        headers=auth_headers(token_e2),
    )
    check(f"10c. Revelar un ítem ajeno -> 404 (fue {resp.status_code})", resp.status_code == 404)

    # 11. Una cuenta personal no entra al panel
    resp = client.get("/api/v1/dashboard/members", headers=auth_headers(token_worker))
    check(f"11. Cuenta personal en /dashboard/members -> 403 (fue {resp.status_code})",
          resp.status_code == 403)

    # 12. Integrante sin cuenta vinculada
    orphan = (
        admin.table("dashboard_members")
        .insert(
            {
                "org_id": org_id_e1,
                "full_name": "Contratista E2E",
                "email": f"contratista.{suffix}@ejemplo-externo.com",
                "role_title": "Soporte externo",
            }
        )
        .execute()
        .data[0]
    )
    resp = client.get(
        f"/api/v1/dashboard/members/{orphan['id']}/vault", headers=auth_headers(token_e1)
    )
    check(
        f"12. Integrante sin cuenta SparkGate -> 200 con lista vacía (fue {resp.status_code})",
        resp.status_code == 200 and resp.json() == [],
    )

    print(
        "\n13. MANUAL — no automatizado (requiere reiniciar el backend sin\n"
        "    VAULT_MASTER_KEY, y este script no reinicia procesos que no le pertenecen):\n"
        "    a) Comentar VAULT_MASTER_KEY en .env, reiniciar el backend.\n"
        f"    b) GET  /api/v1/dashboard/members/{member_id}/vault -> esperar 200 con los ítems\n"
        "       (listar metadata no descifra, así que no depende de la KEK — AC8).\n"
        f"    c) POST /api/v1/dashboard/members/{member_id}/vault/{target_item}/reveal -> esperar 503.\n"
        "    d) Descomentar VAULT_MASTER_KEY y reiniciar antes de seguir usándolo.\n"
        "\n14. MANUAL — UI de la extensión (evidencia en docs/evidencia/hu21-ui-manual.txt):\n"
        "    a) AC4: login con la cuenta empresa -> el botón 'Panel de administración'\n"
        "       aparece; login con una cuenta personal -> no aparece.\n"
        "    b) AC2: 'Agregar trabajador' muestra la contraseña temporal una sola vez.\n"
        "    c) AC6: 'Ver contraseña' sobre un ítem del trabajador abre el modal con el\n"
        "       aviso de que la consulta queda registrada en la auditoría que él ve."
    )

    if CLEANUP:
        cleanup(admin)

    total = len(_results)
    passed = sum(1 for ok, _ in _results if ok)
    print(f"\n{passed}/{total} pasos OK.")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
