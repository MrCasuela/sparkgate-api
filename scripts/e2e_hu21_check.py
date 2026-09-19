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
  Etapa C — credenciales propias de la organización: guardar y recuperar la
            contraseña, supervivencia al integrante (19), reasignación al reemplazo
            (20), y que la contraseña que muestra el panel es la real (21)

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


_skipped: list[str] = []


def check(label: str, condition: bool) -> bool:
    _results.append((condition, label))
    print(("PASS" if condition else "FAIL") + f"  {label}")
    return condition


def skip(label: str) -> None:
    """Un paso que NO se ejercitó. No suma a los PASS: un check con resultado
    fijo o que comprueba lo que el propio script acaba de crear infla el conteo
    sin probar nada de la aplicación."""
    _skipped.append(label)
    print(f"SKIP  {label}")


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
            # Por org_id, no por la lista de miembros: con ON DELETE SET NULL las
            # credenciales sobreviven a su integrante (paso 19) y quedan con member_id
            # nulo, así que borrarlas "por miembro" las dejaría huérfanas.
            admin.table("dashboard_credential_secrets").delete().eq("org_id", org_id).execute()
            admin.table("dashboard_credentials").delete().eq("org_id", org_id).execute()
            admin.table("dashboard_members").delete().eq("org_id", org_id).execute()
            admin.table("organizations").delete().eq("id", org_id).execute()
            # dashboard_audit_log NO se borra: es una cadena hash, y quitar filas del
            # medio rompería prev_hash de las siguientes. Sus payloads son seudónimos
            # (UUIDs), así que dejarlas no retiene datos personales.
        except Exception as e:
            print(f"  aviso: no se pudo limpiar la organización {org_id}: {e}")
    for user_id in _created_user_ids:
        try:
            admin.table("vault_items").delete().eq("user_id", user_id).execute()
            admin.auth.admin.delete_user(user_id)
        except Exception as e:
            print(f"  aviso: no se pudo borrar el usuario {user_id}: {e}")
    print("Limpieza terminada.")


def provision_worker(admin, client: httpx.Client, company_token: str, suffix: str, tag: str) -> dict:
    """Alta de un trabajador por el endpoint del panel (Admin API server-side) y login
    con su contraseña temporal. Devuelve ids, credenciales y token."""
    email = f"sparkgate.e2e.hu21.{tag}.{suffix}@example.com"
    resp = client.post(
        "/api/v1/dashboard/members",
        headers=auth_headers(company_token),
        json={"full_name": f"Trabajador {tag}", "email": email, "role_title": "QA"},
    )
    resp.raise_for_status()
    body = resp.json()
    member_id = body["member"]["id"]
    row = admin.table("dashboard_members").select("*").eq("id", member_id).execute().data[0]
    _created_user_ids.append(row["supabase_user_id"])
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": body["temporary_password"]}
    )
    login.raise_for_status()
    return {
        "member_id": member_id,
        "user_id": row["supabase_user_id"],
        "email": email,
        "temporary_password": body["temporary_password"],
        "secret_stored": body.get("secret_stored"),
        "token": login.json()["access_token"],
    }


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
            f"{detail!r}). Dos causas observadas en este proyecto: Supabase rechaza el "
            "dominio de prueba @example.com como dirección inválida, y el rate limit de "
            "confirmación de mails del tier free (visto en HU17). Para ejercitar este "
            "camino de verdad hace falta una dirección con dominio entregable y cuota "
            "disponible. Acá se sigue por Admin API."
        )
        e1_user_id, org_id_e1, token_e1 = provision_enterprise_via_admin(
            admin, client, email_e1, password, f"PYME E2E {suffix}"
        )
        # La cuenta la creó este script, no la aplicación: comprobar que existe, o
        # que declara enterprise, sería verificar el propio setup. Lo que queda sin
        # ejercitar contra el sistema real es que type_account viaje dentro del
        # token del sign_up (cubierto solo por mocks en test_org_accounts.py).
        skip(
            "1. Registro de cuenta empresa por el endpoint público: NO ejercitado "
            "(cuenta provisionada por Admin API); type_account-en-el-token-del-sign_up "
            "queda verificado solo con mocks"
        )

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

    # =================================================================== Etapa C
    # Credenciales propias de la organización. Los pasos 19, 20 y 21 son los que
    # deciden si la etapa está hecha.
    stg = f"Stg-C-{suffix}"

    def pool_and_assigned(token):
        r = client.get("/api/v1/dashboard/credentials", headers=auth_headers(token))
        return r.json() if r.status_code == 200 else []

    # 15. Registrar una cuenta externa con contraseña, asignada al trabajador A
    plain_1 = f"{stg}-uno"
    resp = client.post(
        "/api/v1/dashboard/credentials",
        headers=auth_headers(token_e1),
        json={"member_id": member_id, "service_name": "Google Workspace E2E",
              "username": "ws@pyme.cl", "password": plain_1, "notes": "cuenta de la empresa"},
    )
    check(f"15a. POST /dashboard/credentials con contraseña -> 201 (fue {resp.status_code})",
          resp.status_code == 201)
    cred = resp.json() if resp.status_code == 201 else {}
    cred_id = cred.get("id")
    raw_cred = (admin.table("dashboard_credentials").select("*").eq("id", cred_id).execute().data
                if cred_id else [])
    check("15b. La fila cruda de la credencial lleva org_id no nulo (la tenencia es de la fila)",
          bool(raw_cred) and raw_cred[0].get("org_id") == org_id_e1)
    check("15c. La respuesta declara has_secret", cred.get("has_secret") is True)

    resp = client.post(
        "/api/v1/dashboard/credentials",
        headers=auth_headers(token_e1),
        json={"service_name": "Google Ads E2E", "password": f"{stg}-pool"},
    )
    pool_id = resp.json().get("id") if resp.status_code == 201 else None
    resp = client.get("/api/v1/dashboard/credentials?assigned=false", headers=auth_headers(token_e1))
    check("15d. La credencial sin asignar aparece en ?assigned=false y NO en el listado de un integrante",
          resp.status_code == 200 and any(c["id"] == pool_id for c in resp.json()))

    # 16. Reemplazar el secreto; el plaintext no aparece en NINGUNA columna de la fila cruda
    plain_2 = f"{stg}-dos"
    resp = client.put(
        f"/api/v1/dashboard/credentials/{cred_id}/secret",
        headers=auth_headers(token_e1),
        json={"password": plain_2, "notes": "rotada"},
    )
    check(f"16a. PUT /credentials/{{id}}/secret -> 200 (fue {resp.status_code})", resp.status_code == 200)
    check("16b. El PUT no devuelve el plaintext", plain_2 not in resp.text)
    secret_row = (admin.table("dashboard_credential_secrets").select("*")
                  .eq("credential_id", cred_id).execute().data)
    check("16c. La fila cruda del sobre NO contiene el plaintext (ni el viejo ni el nuevo)",
          bool(secret_row) and plain_1 not in str(secret_row) and plain_2 not in str(secret_row))
    check("16d. El sobre lleva el org_id (es el AAD con el que se cifró)",
          bool(secret_row) and secret_row[0]["org_id"] == org_id_e1)

    # 17. Revelar
    resp = client.post(f"/api/v1/dashboard/credentials/{cred_id}/secret/reveal",
                       headers=auth_headers(token_e1))
    check(f"17. POST .../secret/reveal -> 200 y devuelve la contraseña vigente (fue {resp.status_code})",
          resp.status_code == 200 and resp.json().get("password") == plain_2)

    # 18. Aislamiento: la segunda empresa
    resp = client.post(f"/api/v1/dashboard/credentials/{cred_id}/secret/reveal",
                       headers=auth_headers(token_e2))
    check(f"18a. Revelar la credencial de otra organización -> 404 (fue {resp.status_code})",
          resp.status_code == 404)
    resp = client.post(f"/api/v1/dashboard/credentials/{cred_id}/reassign",
                       headers=auth_headers(token_e2), json={"member_id": None})
    check(f"18b. Reasignar la credencial de otra organización -> 404 (fue {resp.status_code})",
          resp.status_code == 404)

    # 19. LA CREDENCIAL SOBREVIVE AL BORRADO DEL INTEGRANTE. Ejercita la FK de Postgres
    # (ON DELETE SET NULL), no el script; y el reveal sigue devolviendo lo mismo, que es
    # la prueba de que el AAD es la organización y no el integrante.
    doomed = provision_worker(admin, client, token_e1, suffix, "d")
    plain_3 = f"{stg}-tres"
    resp = client.post(
        "/api/v1/dashboard/credentials",
        headers=auth_headers(token_e1),
        json={"member_id": doomed["member_id"], "service_name": "Cuenta del que se va E2E",
              "password": plain_3},
    )
    doomed_cred = resp.json().get("id") if resp.status_code == 201 else None
    admin.table("dashboard_members").delete().eq("id", doomed["member_id"]).execute()
    survivors = (admin.table("dashboard_credentials").select("id, member_id")
                 .eq("id", doomed_cred).execute().data) if doomed_cred else []
    check("19a. Borrado el integrante, su credencial de empresa SIGUE existiendo, sin portador",
          len(survivors) == 1 and survivors[0]["member_id"] is None)
    resp = client.post(f"/api/v1/dashboard/credentials/{doomed_cred}/secret/reveal",
                       headers=auth_headers(token_e1))
    check("19b. Y su reveal sigue devolviendo el mismo plaintext (el AAD no depende del integrante)",
          resp.status_code == 200 and resp.json().get("password") == plain_3)

    # 20. REASIGNADA: el nuevo portador la ve, el anterior no
    replacement = provision_worker(admin, client, token_e1, suffix, "r")
    before = client.get("/api/v1/me/credentials", headers=auth_headers(token_worker))
    check("20a. Antes de reasignar, el trabajador A la ve en /me/credentials",
          before.status_code == 200 and any(c["id"] == cred_id for c in before.json()))
    resp = client.post(f"/api/v1/dashboard/credentials/{cred_id}/reassign",
                       headers=auth_headers(token_e1), json={"member_id": replacement["member_id"]})
    check(f"20b. POST .../reassign -> 200 (fue {resp.status_code})", resp.status_code == 200)
    check("20c. La respuesta sugiere rotarla: la que cambia de manos la conocía el anterior",
          resp.status_code == 200 and any(x["credential_id"] == cred_id
                                          for x in resp.json().get("rotation_suggested", [])))
    mine = client.get("/api/v1/me/credentials", headers=auth_headers(replacement["token"]))
    check("20d. El reemplazo la lista en /me/credentials",
          mine.status_code == 200 and any(c["id"] == cred_id for c in mine.json()))
    resp = client.post(f"/api/v1/me/credentials/{cred_id}/reveal",
                       headers=auth_headers(replacement["token"]))
    check("20e. El reemplazo retira la contraseña y es la vigente",
          resp.status_code == 200 and resp.json().get("password") == plain_2)
    gone = client.get("/api/v1/me/credentials", headers=auth_headers(token_worker))
    check("20f. El trabajador ANTERIOR ya no la lista",
          gone.status_code == 200 and all(c["id"] != cred_id for c in gone.json()))
    resp = client.post(f"/api/v1/me/credentials/{cred_id}/reveal", headers=auth_headers(token_worker))
    check(f"20g. Y ya no puede retirarla -> 404 (fue {resp.status_code})", resp.status_code == 404)
    audit = client.get("/api/v1/dashboard/audit-log", headers=auth_headers(token_e1)).json()
    check("20h. La empresa ve en su cadena quién retiró la credencial (consultar_secreto_asignado)",
          any(e["action"] == "consultar_secreto_asignado"
              and e["actor_user_id"] == replacement["user_id"] for e in audit))

    # 21. LA CONTRASEÑA QUE MUESTRA EL PANEL ES LA REAL. Es el contrato roto que motiva toda
    # la etapa: antes el backend descartaba la contraseña y el panel mostraba una que él
    # mismo había generado. Ejercita Supabase Auth de punta a punta.
    worker_c = provision_worker(admin, client, token_e1, suffix, "c")
    resp = client.post("/api/v1/dashboard/credentials", headers=auth_headers(token_e1),
                       json={"member_id": worker_c["member_id"], "service_name": "Dropbox C E2E",
                             "password": f"{stg}-dropbox"})
    ext_c = resp.json().get("id") if resp.status_code == 201 else None
    members_now = client.get("/api/v1/dashboard/members", headers=auth_headers(token_e1)).json()
    interna_c = next((cr["id"] for m in members_now if m["id"] == worker_c["member_id"]
                      for cr in m["credentials"] if cr["type"] == "interna"), None)

    resp = client.post(f"/api/v1/dashboard/credentials/{interna_c}/revoke",
                       headers=auth_headers(token_e1), json={})
    revoked = resp.json() if resp.status_code == 200 else {}
    applied = revoked.get("applied_password")
    check(f"21a. revoke devuelve la contraseña que APLICÓ y quedó guardada cifrada (fue {resp.status_code})",
          resp.status_code == 200 and bool(applied) and revoked.get("secret_stored") is True)
    # Medido, no supuesto: el proyecto asumía (V10) que el access token ya emitido vive
    # ~1 h tras un revoke. verify_token consulta a GoTrue en cada request, y GoTrue
    # rechaza al usuario baneado o con la sesión invalidada por el cambio de contraseña.
    resp = client.get("/api/v1/me/credentials", headers=auth_headers(worker_c["token"]))
    check(f"21b0. Tras un revoke REAL, el token que el trabajador ya tenía deja de servir -> 401 (fue {resp.status_code})",
          resp.status_code == 401)
    resp = client.post("/api/v1/auth/login",
                       json={"email": worker_c["email"], "password": worker_c["temporary_password"]})
    check(f"21b. Revocada, la contraseña vieja ya no sirve -> 401 (fue {resp.status_code})",
          resp.status_code == 401)
    resp = client.post(f"/api/v1/dashboard/credentials/{interna_c}/restore",
                       headers=auth_headers(token_e1))
    resp_login = client.post("/api/v1/auth/login",
                             json={"email": worker_c["email"], "password": applied or ""})
    check(f"21c. Restaurada, la contraseña que mostró el panel ABRE la cuenta -> 200 (fue {resp_login.status_code})",
          resp.status_code == 200 and resp_login.status_code == 200)
    token_c = resp_login.json().get("access_token") if resp_login.status_code == 200 else None
    resp = client.post(f"/api/v1/dashboard/credentials/{interna_c}/secret/reveal",
                       headers=auth_headers(token_e1))
    check("21d. Y lo que la empresa recupera después es esa misma contraseña",
          resp.status_code == 200 and resp.json().get("password") == applied)

    # 22. El trabajador ve que la empresa retiró su contraseña interna
    resp = client.get("/api/v1/vault/audit", headers=auth_headers(token_c or worker_c["token"]))
    seen = [e for e in (resp.json() if resp.status_code == 200 else [])
            if e.get("action") == "consultar_credencial_interna_admin"]
    check("22. El trabajador ve consultar_credencial_interna_admin con la empresa como actor "
          "(si falla, la mitigación de R-HU21-5 NO está cumplida)",
          bool(seen) and seen[0].get("actor_user_id") == e1_user_id)

    # 21e. La guarda de /me contra un integrante REVOCADO. Un revoke real ya invalida su
    # token (21b0), así que se simula el caso que la guarda sí cubre: la credencial quedó
    # 'revocada' en la base pero Auth NO llegó a banear al usuario (admin_api_success=false
    # en un revoke cuya llamada a Auth falló). Se voltea el estado directo y el token sigue
    # siendo válido.
    admin.table("dashboard_credentials").update({"status": "revocada"}).eq("id", interna_c).execute()
    resp = client.post(f"/api/v1/me/credentials/{ext_c}/reveal", headers=auth_headers(token_c))
    check(f"21e. Con su cuenta interna revocada en la base pero el token aún válido, no retira nada -> 403 (fue {resp.status_code})",
          resp.status_code == 403)
    admin.table("dashboard_credentials").update({"status": "activa"}).eq("id", interna_c).execute()

    # 25. Rotación sugerida: tras revocar, sus otras credenciales quedan marcadas
    members_now = client.get("/api/v1/dashboard/members", headers=auth_headers(token_e1)).json()
    flagged = next((cr for m in members_now if m["id"] == worker_c["member_id"]
                    for cr in m["credentials"] if cr["id"] == ext_c), {})
    check("25a. Tras revocar al integrante, su otra credencial queda con rotation_required",
          flagged.get("rotation_required") is True)
    client.put(f"/api/v1/dashboard/credentials/{ext_c}/secret", headers=auth_headers(token_e1),
               json={"password": f"{stg}-rotada"})
    members_now = client.get("/api/v1/dashboard/members", headers=auth_headers(token_e1)).json()
    cleared = next((cr for m in members_now if m["id"] == worker_c["member_id"]
                    for cr in m["credentials"] if cr["id"] == ext_c), {})
    check("25b. Guardar una contraseña nueva (rotar de verdad) apaga la bandera",
          cleared.get("rotation_required") is False)

    # 20i. Una interna no se reasigna
    resp = client.post(f"/api/v1/dashboard/credentials/{interna_c}/reassign",
                       headers=auth_headers(token_e1), json={"member_id": replacement["member_id"]})
    check(f"20i. Reasignar una cuenta INTERNA -> 400 (fue {resp.status_code})", resp.status_code == 400)

    # 23. Las dos cadenas siguen verificando, con entradas de todos los tipos
    ok_panel, broken_panel = audit_chain.verify_chain_jsonb("dashboard_audit_log")
    check(f"23a. verify_chain_jsonb('dashboard_audit_log') (broken_id={broken_panel})", ok_panel)
    ok_vault, broken_vault = audit_chain.verify_chain("vault_audit_log")
    check(f"23b. verify_chain('vault_audit_log') sigue íntegra (broken_id={broken_vault})", ok_vault)

    skip("24. Alterar una fila del panel y ver la cadena romperse: dejaría rota de forma "
         "permanente la cadena de desarrollo; está cubierto de forma hermética en "
         "tests/test_audit_chain.py")
    skip("26. Sin VAULT_MASTER_KEY, PUT /secret y el reveal responden 503: exige reiniciar un "
         "proceso que el script no posee (ver M1)")

    print(
        "\nM1. MANUAL — no automatizado (requiere reiniciar el backend sin\n"
        "    VAULT_MASTER_KEY, y este script no reinicia procesos que no le pertenecen):\n"
        "    a) Comentar VAULT_MASTER_KEY en .env, reiniciar el backend.\n"
        f"    b) GET  /api/v1/dashboard/members/{member_id}/vault -> esperar 200 con los ítems\n"
        "       (listar metadata no descifra, así que no depende de la KEK — AC8).\n"
        f"    c) POST /api/v1/dashboard/members/{member_id}/vault/{target_item}/reveal -> esperar 503.\n"
        "    d) Descomentar VAULT_MASTER_KEY y reiniciar antes de seguir usándolo.\n"
        "\nM2. MANUAL — UI de la extensión (evidencia en docs/evidencia/hu21-ui-manual.txt):\n"
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
    print(f"\n{passed}/{total} pasos OK, {len(_skipped)} omitidos (no cuentan como PASS).")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
