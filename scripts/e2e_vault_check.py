"""E2E verification for HU17 (Vault) against a real running backend + real Supabase.

Unlike the unit/integration suite (which mocks Supabase and vault_crypto), this hits
the actual HTTP API and reads the actual tables, closing the gap the boveda's own
methodological rule flags: "verificacion real, no solo mocks" (see
_Leccion-singleton-sdk-muta-estado-global — the logout fix was only trusted after a
live login -> 200 -> logout -> 401 sequence, not from mocked tests alone).

Self-contained: creates two throwaway accounts (random emails, via the Admin API —
see create_and_login) rather than asking the operator to prepare real ones, so
there's nothing pre-existing to accidentally delete, and it doesn't burn Supabase's
public-signup confirmation-email rate limit. Requires:
  - The backend running (`./start.sh` or `uvicorn app.main:app --port 8000`).
  - VAULT_MASTER_KEY set in .env (steps 1-7 need it; step 8's KEK-down case is a
    manual sub-check this script prints instructions for, since it requires
    restarting the server without the key — not something a script should do to a
    process it doesn't own).
  - SUPABASE_SERVICE_ROLE_KEY set in .env (for the direct-table and audit_chain checks).

Env vars:
  E2E_BASE_URL              default http://localhost:8000
  E2E_ALLOW_ACCOUNT_DELETE  default "0". Set to "1" to also run step 9 (account
                            deletion), which is irreversible but only ever targets
                            this script's own throwaway account A.

Usage (from repo root, with venv active and the backend already running):
    python scripts/e2e_vault_check.py | tee docs/evidencia/hu17-e2e.txt
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
ALLOW_ACCOUNT_DELETE = os.environ.get("E2E_ALLOW_ACCOUNT_DELETE", "0") == "1"

_results: list[tuple[bool, str]] = []


def check(label: str, condition: bool) -> bool:
    _results.append((condition, label))
    print(("PASS" if condition else "FAIL") + f"  {label}")
    return condition


def create_and_login(client: httpx.Client, admin, email: str, password: str) -> str:
    """Creates the throwaway user via the Admin API (email_confirm=True), exactly
    like scripts/seed_dashboard_demo.py does — this sidesteps Supabase's public
    sign_up confirmation-email rate limit entirely, since /auth/register would send
    a real confirmation email per run and quickly gets throttled on a free project.
    Login still goes through the real public endpoint under test.
    """
    admin.auth.admin.create_user(
        {"email": email, "password": password, "email_confirm": True, "user_metadata": {"premium": False}}
    )
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    resp.raise_for_status()
    return resp.json()["access_token"]


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def main() -> None:
    print(f"HU17 E2E — {datetime.now(timezone.utc).isoformat()}")
    print(f"Base URL: {BASE_URL}\n")

    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no configurada. Abortando.")
        sys.exit(1)
    if not vault_crypto.is_available():
        print("VAULT_MASTER_KEY no configurada o inválida. Abortando (los pasos 1-7 la necesitan).")
        sys.exit(1)

    admin = get_supabase_admin()
    suffix = uuid.uuid4().hex[:8]
    email_a = f"sparkgate.e2e.a.{suffix}@example.com"
    email_b = f"sparkgate.e2e.b.{suffix}@example.com"
    password = "E2eCheck#Vault99"

    client = httpx.Client(base_url=BASE_URL, timeout=15)

    # 1. Login A
    token_a = create_and_login(client, admin, email_a, password)
    check("1. Login usuario A", bool(token_a))

    # 2. Guardar credencial
    secret_password = "MiClaveSecreta#2026"
    secret_notes = "notas privadas de A"
    resp = client.post(
        "/api/v1/vault/items",
        headers=auth_headers(token_a),
        json={"service_name": "E2E Service", "username": "a-user", "password": secret_password, "notes": secret_notes},
    )
    check("2. POST /vault/items -> 201", resp.status_code == 201)
    item_id = resp.json()["id"]

    # 3. Fila cruda sin texto plano
    row = admin.table("vault_items").select("*").eq("id", item_id).single().execute().data
    row_text = str(row)
    check(
        "3. La fila cruda no contiene el password ni las notas en claro",
        secret_password not in row_text and secret_notes not in row_text,
    )

    # 4. Consulta propia
    resp = client.get(f"/api/v1/vault/items/{item_id}", headers=auth_headers(token_a))
    check("4. GET propio -> 200 con el password original", resp.status_code == 200 and resp.json()["password"] == secret_password)

    # 5. Consulta cruzada (B intenta leer el ítem de A)
    token_b = create_and_login(client, admin, email_b, password)
    resp = client.get(f"/api/v1/vault/items/{item_id}", headers=auth_headers(token_b))
    check("5a. GET cruzado (B lee ítem de A) -> 404", resp.status_code == 404)

    last_entries = (
        admin.table("vault_audit_log").select("*").eq("item_id", item_id).order("seq", desc=True).limit(1).execute().data
    )
    check(
        "5b. Última entrada de auditoría del ítem es consultar_denegado",
        bool(last_entries) and last_entries[0]["action"] == "consultar_denegado",
    )

    # 6. Auditoría propia sin secretos
    resp = client.get("/api/v1/vault/audit", headers=auth_headers(token_a))
    audit_text = resp.text
    check(
        "6. GET /vault/audit propio no contiene el password ni las notas",
        resp.status_code == 200 and secret_password not in audit_text and secret_notes not in audit_text,
    )

    # 7. Cadena íntegra
    ok, broken_id = audit_chain.verify_chain("vault_audit_log")
    check(f"7. verify_chain('vault_audit_log') == True (broken_id={broken_id})", ok)

    # 8. KEK ausente — no automatizable sin reiniciar el proceso del servidor.
    print(
        "\n8. MANUAL — no automatizado (requiere reiniciar el backend sin VAULT_MASTER_KEY,\n"
        "   y este script no reinicia procesos que no le pertenecen):\n"
        "   a) Comentar VAULT_MASTER_KEY en .env, reiniciar el backend.\n"
        "   b) POST /api/v1/vault/items -> esperar 503, confirmar que vault_items no creció.\n"
        "   c) DELETE /api/v1/vault/items/{id} de un ítem existente -> esperar 204 igual\n"
        "      (el borrado no depende de la KEK).\n"
        "   d) Descomentar VAULT_MASTER_KEY, reiniciar el backend antes de seguir usándolo.\n"
    )

    # 9. Borrado de cuenta (opcional, irreversible, solo sobre la cuenta A de este script)
    if not ALLOW_ACCOUNT_DELETE:
        print("9. Omitido (E2E_ALLOW_ACCOUNT_DELETE != 1). Cuentas de prueba A/B quedan vivas.")
    else:
        resp = client.request(
            "DELETE",
            "/api/v1/auth/account",
            headers=auth_headers(token_a),
            json={"confirm_email": "correo-incorrecto@example.com", "password": password},
        )
        check("9a. confirm_email incorrecto -> 400", resp.status_code == 400)

        resp = client.request(
            "DELETE",
            "/api/v1/auth/account",
            headers=auth_headers(token_a),
            json={"confirm_email": email_a, "password": "contraseña-incorrecta"},
        )
        check("9b. password incorrecta -> 401", resp.status_code == 401)

        resp = client.request(
            "DELETE",
            "/api/v1/auth/account",
            headers=auth_headers(token_a),
            json={"confirm_email": f"  {email_a.upper()}  ", "password": password},
        )
        check("9c. confirm_email + password correctos -> 204", resp.status_code == 204)

        remaining = admin.table("vault_items").select("id").eq("user_id", _user_id_from_token(token_a)).execute().data
        check("9d. vault_items del usuario borrado queda vacío", remaining == [])

        resp = client.post("/api/v1/auth/login", json={"email": email_a, "password": password})
        check("9e. Login con la cuenta borrada -> ya no funciona", resp.status_code == 401)

        ok, broken_id = audit_chain.verify_chain("vault_audit_log")
        check(f"9f. verify_chain sigue True tras el borrado de cuenta (broken_id={broken_id})", ok)

    total = len(_results)
    passed = sum(1 for ok, _ in _results if ok)
    print(f"\n{passed}/{total} pasos OK.")
    if passed != total:
        sys.exit(1)


def _user_id_from_token(token: str) -> str:
    import base64
    import json

    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["sub"]


if __name__ == "__main__":
    main()
