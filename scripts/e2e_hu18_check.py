"""E2E verification for HU18 against a real running backend + real Supabase.

Calcado de scripts/e2e_hu21_check.py: mismo acumulador de PASS/FAIL/SKIP, mismas cuentas
desechables con email aleatorio, misma salida por tee. Existe por la misma razón: la suite
con mocks no prueba que Supabase se comporte como creemos, y la regla metodológica del
proyecto es verificar contra el servicio real antes de dar por cerrado un ítem de seguridad.

Qué cubre (AC de HU18):
  AC1  el administrador lee una credencial de un integrante CON un código TOTP vigente
  AC2  revocar una cuenta interna exige el código, genera la contraseña nueva y revoca las
       sesiones (Admin API: cambio de contraseña + ban en UNA llamada)
  AC3  sugerir para una cuenta externa exige el código y la deja «pendiente de aplicación
       manual» sin declarar el cambio efectuado
  AC4  un código ausente, inválido, reusado o de una cuenta sin factor DENIEGA, no accede a
       la credencial y deja el intento en la auditoría, con su motivo
  AC5  la revocación bloquea sesiones futuras Y refresh tokens, y el access token ya emitido
       deja de servir. SE MIDE: la afirmación original del AC («puede seguir válido ~1 h») es
       una propiedad de OTRO componente, y se verifica antes de escribirla (ver
       _Leccion-un-texto-de-ui-es-una-afirmacion-que-se-mide).
  Además: TODO lector de un secreto ajeno lo necesita, también el trabajador; un factor sin
  confirmar no habilita nada; anti-replay; bloqueo por fuerza bruta; las cadenas de auditoría
  siguen íntegras; ninguna contraseña, secreto TOTP ni código llega a la auditoría.

Los códigos se generan con pyotp.TOTP(secreto).now() (el constructor por DEFECTO, no el de
totp_service): lo mismo que haría un teléfono. El anti-replay obliga a esperar al próximo
paso de 30 s entre operaciones que consumen un código; el script lo imprime como una línea
explícita para que el tiempo de corrida se lea como propiedad del sistema y no como lentitud.

Requiere:
  - El backend corriendo CON EL CÓDIGO DE HU18 y TOTP_MASTER_KEY en su entorno (reiniciarlo si
    se levantó antes: el script detecta un backend viejo y aborta con un mensaje claro).
  - VAULT_MASTER_KEY y TOTP_MASTER_KEY en .env (el script las lee para comprobar que existen;
    el caso de las dos caídas es un sub-check manual que se imprime al final, porque exige
    reiniciar un proceso que este script no posee).
  - SUPABASE_SERVICE_ROLE_KEY en .env (lecturas directas de tabla y verify_chain).
  - Aplicado: python scripts/apply_mfa_schema.py

Env vars:
  E2E_BASE_URL       default http://localhost:8000
  E2E_HU18_CLEANUP   default "0". En "1" borra al final las organizaciones, integrantes,
                     factores y usuarios desechables que creó esta corrida.

Usage (from repo root, with venv active and the backend already running):
    python scripts/e2e_hu18_check.py | tee docs/evidencia/hu18-e2e.txt
"""

import json
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
import pyotp  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.services import audit_chain, totp_service, vault_crypto  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")
CLEANUP = os.environ.get("E2E_HU18_CLEANUP", "0") == "1"
PERIOD = totp_service.PERIOD
TOTP = "X-SparkGate-TOTP"

PANEL_LOG = "dashboard_audit_log"
VAULT_LOG = "vault_audit_log"

EXT_PASSWORD = "ExtSecret#E2E_18"  # la contraseña de la credencial externa, que la empresa guarda

_results: list[tuple[bool, str]] = []
_skipped: list[str] = []
_created_user_ids: list[str] = []
_created_org_ids: list[str] = []
_secrets_seen: list[str] = []  # contraseñas y secretos: NO pueden aparecer (ni como substring) en la auditoría
_codes_seen: list[str] = []  # códigos de 6 dígitos: se buscan como VALOR completo, no como substring


def check(label: str, condition: bool) -> bool:
    _results.append((condition, label))
    print(("PASS" if condition else "FAIL") + f"  {label}")
    return condition


def skip(label: str) -> None:
    """Un paso que NO se ejercitó. No suma a los PASS: un check con resultado fijo o que
    comprueba lo que el propio script acaba de crear infla el conteo sin probar nada de la
    aplicación (_Leccion-check-tautologico-infla-la-evidencia)."""
    _skipped.append(label)
    print(f"SKIP  {label}")


def auth_headers(token: str, code: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    if code is not None:
        headers[TOTP] = code
    return headers


# --------------------------------------------------------------------------------------
# Códigos TOTP: como los generaría un teléfono
# --------------------------------------------------------------------------------------


def code_now(secret: str) -> str:
    """El código vigente. Constructor por defecto de pyotp (SHA-1, 6 dígitos, 30 s): NO el de
    totp_service, para que el E2E no verifique a la implementación con ella misma."""
    code = pyotp.TOTP(secret).now()
    _codes_seen.append(code)
    return code


def wrong_code(secret: str) -> str:
    """Un código de formato válido que NO es ninguno de los tres de la ventana del servidor.
    Uno al azar colisionaría 3 de cada 10^6 veces: eso no es evidencia."""
    now = int(time.time())
    valid = {pyotp.TOTP(secret).at(now + step * PERIOD) for step in (-1, 0, 1)}
    code = next(c for c in (f"{n:06d}" for n in range(100000, 100200)) if c not in valid)
    _codes_seen.append(code)
    return code


def wait_next_step(why: str) -> None:
    """Espera al próximo paso de 30 s: un código aceptado no se puede reusar (RFC 6238 §5.2)."""
    wait = PERIOD - (time.time() % PERIOD) + 1.0
    print(f"  … esperando {wait:.0f} s ({why}): el anti-replay de RFC 6238 impide reusar un código")
    time.sleep(wait)


# --------------------------------------------------------------------------------------
# Aprovisionamiento (igual que HU21: Admin API, sin quemar el rate limit de mails)
# --------------------------------------------------------------------------------------


def provision_enterprise(admin, client: httpx.Client, email: str, password: str, org_name: str):
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
    org = admin.table("organizations").insert({"owner_user_id": user_id, "name": org_name}).execute().data[0]
    _created_org_ids.append(org["id"])
    admin.auth.admin.update_user_by_id(
        user_id,
        {"user_metadata": {"premium": False, "type_account": "enterprise", "org_id": org["id"]}},
    )
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    resp.raise_for_status()
    return user_id, org["id"], resp.json()["access_token"]


def provision_worker(admin, client: httpx.Client, company_token: str, suffix: str) -> dict:
    email = f"sparkgate.e2e.hu18.w.{suffix}@example.com"
    resp = client.post(
        "/api/v1/dashboard/members",
        headers=auth_headers(company_token),
        json={"full_name": "Trabajador E2E HU18", "email": email, "role_title": "QA"},
    )
    resp.raise_for_status()
    body = resp.json()
    member_id = body["member"]["id"]
    row = admin.table("dashboard_members").select("*").eq("id", member_id).execute().data[0]
    _created_user_ids.append(row["supabase_user_id"])
    _secrets_seen.append(body["temporary_password"])
    return {
        "member_id": member_id,
        "user_id": row["supabase_user_id"],
        "email": email,
        "temporary_password": body["temporary_password"],
    }


def gotrue(path: str, grant: str, payload: dict) -> httpx.Response:
    """Habla directo con Supabase Auth (GoTrue). El login del backend no devuelve el
    refresh_token, y AC5 hay que medirlo con uno."""
    return httpx.post(
        f"{settings.supabase_url}/auth/v1/{path}",
        params={"grant_type": grant},
        headers={"apikey": settings.supabase_key},
        json=payload,
        timeout=20,
    )


def cleanup(admin) -> None:
    print("\nLimpieza (E2E_HU18_CLEANUP=1)...")
    for user_id in _created_user_ids:
        try:
            admin.table("user_totp_factors").delete().eq("user_id", user_id).execute()
        except Exception as e:
            print(f"  aviso: no se pudo borrar el factor de {user_id}: {e}")
    for org_id in _created_org_ids:
        try:
            admin.table("dashboard_credential_secrets").delete().eq("org_id", org_id).execute()
            admin.table("dashboard_credentials").delete().eq("org_id", org_id).execute()
            admin.table("dashboard_members").delete().eq("org_id", org_id).execute()
            admin.table("organizations").delete().eq("id", org_id).execute()
            # dashboard_audit_log NO se borra: es una cadena hash y quitar filas del medio
            # rompería prev_hash de las siguientes. Sus payloads son seudónimos (UUIDs).
        except Exception as e:
            print(f"  aviso: no se pudo limpiar la organización {org_id}: {e}")
    for user_id in _created_user_ids:
        try:
            admin.table("vault_items").delete().eq("user_id", user_id).execute()
            admin.auth.admin.delete_user(user_id)
        except Exception as e:
            print(f"  aviso: no se pudo borrar el usuario {user_id}: {e}")
    print("Limpieza terminada.")


# --------------------------------------------------------------------------------------
# Lecturas directas de la base (service_role): lo que la API responde no alcanza como prueba
# --------------------------------------------------------------------------------------


def panel_rows(admin, org_id: str) -> list[dict]:
    return admin.table(PANEL_LOG).select("seq, action, payload").eq("org_id", org_id).order("seq").execute().data


def rows_of(rows: list[dict], action: str, reason: str | None = None) -> list[dict]:
    return [
        r for r in rows
        if r["action"] == action and (reason is None or r["payload"].get("denied_reason") == reason)
    ]


def _flatten_strings(node):
    """Todos los valores de texto de una estructura anidada (para comparar un código COMPLETO)."""
    if isinstance(node, dict):
        for value in node.values():
            yield from _flatten_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _flatten_strings(value)
    elif isinstance(node, str):
        yield node


def credential_row(admin, credential_id: str) -> dict:
    return admin.table("dashboard_credentials").select("*").eq("id", credential_id).execute().data[0]


def main() -> None:  # noqa: C901 — un script de verificación lineal, numerado a propósito
    print(f"HU18 E2E — {datetime.now(timezone.utc).isoformat()}")
    print(f"Base URL: {BASE_URL}\n")

    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no configurada. Abortando.")
        sys.exit(1)
    if not vault_crypto.is_available():
        print("VAULT_MASTER_KEY no configurada o inválida. Abortando (el reveal la necesita).")
        sys.exit(1)
    if not vault_crypto.is_available(settings.totp_master_key):
        print("TOTP_MASTER_KEY no configurada o inválida. Abortando (sin ella no hay segundo factor).")
        sys.exit(1)

    admin = get_supabase_admin()
    suffix = uuid.uuid4().hex[:8]
    password = "E2eCheck#Hu18_99"
    client = httpx.Client(base_url=BASE_URL, timeout=30)

    # ---------------------------------------------------------------- Preparación
    email_admin = f"sparkgate.e2e.hu18.a.{suffix}@example.com"
    admin_id, org_id, admin_token = provision_enterprise(admin, client, email_admin, password, f"PYME E2E HU18 {suffix}")

    probe = client.get("/api/v1/me/mfa", headers=auth_headers(admin_token))
    if probe.status_code == 404:
        print(
            "El backend en marcha NO tiene los endpoints de HU18 (GET /api/v1/me/mfa -> 404). "
            "Reinicialo con el código actual y con TOTP_MASTER_KEY en el entorno. Abortando."
        )
        sys.exit(1)

    worker = provision_worker(admin, client, admin_token, suffix)
    members = client.get("/api/v1/dashboard/members", headers=auth_headers(admin_token)).json()
    member = next(m for m in members if m["id"] == worker["member_id"])
    internal_id = next(c["id"] for c in member["credentials"] if c["type"] == "interna")
    ext = client.post(
        "/api/v1/dashboard/credentials",
        headers=auth_headers(admin_token),
        json={
            "member_id": worker["member_id"],
            "service_name": "Google Workspace E2E",
            "username": "ws.e2e@pyme.cl",
            "password": EXT_PASSWORD,
        },
    )
    ext.raise_for_status()
    ext_id = ext.json()["id"]
    _secrets_seen.append(EXT_PASSWORD)

    # El trabajador entra directo por GoTrue: así queda un refresh_token que AC5 va a medir.
    session = gotrue("token", "password", {"email": worker["email"], "password": worker["temporary_password"]})
    session.raise_for_status()
    worker_token = session.json()["access_token"]
    worker_refresh = session.json()["refresh_token"]

    reveal_ext = f"/api/v1/dashboard/credentials/{ext_id}/secret/reveal"
    print(f"Preparación: org={org_id[:8]}…  admin={admin_id[:8]}…  trabajador={worker['user_id'][:8]}…\n")

    # ================================================================ A. Sin factor (AC4, D4)
    print("--- A. Sin segundo factor")
    r = client.post(reveal_ext, headers=auth_headers(admin_token))
    body = r.json()
    check(
        f"1. Sin factor, revelar la credencial de un integrante -> 403 con code=totp_no_enrolado (fue {r.status_code} {body.get('code')})",
        r.status_code == 403 and body.get("code") == "totp_no_enrolado",
    )
    rows = panel_rows(admin, org_id)
    denied = rows_of(rows, "consultar_secreto_denegado", "totp_no_enrolado")
    check(
        f"2. Ese intento quedó en dashboard_audit_log (lectura directa) como consultar_secreto_denegado con denied_reason=totp_no_enrolado ({len(denied)} fila)",
        len(denied) == 1,
    )
    check(
        "3. El 403 no trae el plaintext y NO hay ninguna fila consultar_secreto: no accedió a la credencial (AC4)",
        EXT_PASSWORD not in r.text and not rows_of(rows, "consultar_secreto"),
    )
    r = client.get("/api/v1/me/mfa", headers=auth_headers(admin_token))
    check(
        "4. GET /me/mfa sin factor -> enrolled=false, pending=false",
        r.status_code == 200 and r.json()["enrolled"] is False and r.json()["pending"] is False,
    )

    # El trabajador también: la credencial que retira es de la ORGANIZACIÓN (decisión de HU18).
    r = client.post(f"/api/v1/me/credentials/{ext_id}/reveal", headers=auth_headers(worker_token))
    check(
        f"5. El TRABAJADOR sin factor tampoco retira la credencial que le asignaron -> 403 totp_no_enrolado (fue {r.status_code} {r.json().get('code')})",
        r.status_code == 403 and r.json().get("code") == "totp_no_enrolado",
    )

    # ================================================================ B. Enrolamiento
    print("\n--- B. Enrolamiento")
    r = client.post("/api/v1/me/mfa/enroll", headers=auth_headers(admin_token))
    if r.status_code == 503:
        print("El backend respondió 503 al enrolar: le falta TOTP_MASTER_KEY en su entorno. Abortando.")
        sys.exit(1)
    enroll = r.json()
    admin_secret = enroll["secret"]
    _secrets_seen.extend([admin_secret, enroll["otpauth_uri"]])
    uri = urlparse(enroll["otpauth_uri"])
    query = parse_qs(uri.query)
    check(
        f"6. POST /me/mfa/enroll -> 201 con un otpauth:// parseable (issuer=SparkGate, SHA1, 6 dígitos, 30 s) (fue {r.status_code})",
        r.status_code == 201 and uri.scheme == "otpauth" and query.get("issuer") == ["SparkGate"]
        and query.get("digits") == ["6"] and query.get("period") == ["30"] and query.get("algorithm") == ["SHA1"]
        and query.get("secret") == [admin_secret],
    )

    r = client.post(reveal_ext, headers=auth_headers(admin_token, code_now(admin_secret)))
    check(
        f"7. Enrolado pero SIN confirmar, un código VÁLIDO para ese secreto no habilita nada: sigue totp_no_enrolado (no totp_invalido) (fue {r.status_code} {r.json().get('code')})",
        r.status_code == 403 and r.json().get("code") == "totp_no_enrolado",
    )

    r = client.post("/api/v1/me/mfa/confirm", headers=auth_headers(admin_token, code_now(admin_secret)))
    status = client.get("/api/v1/me/mfa", headers=auth_headers(admin_token)).json()
    check(
        f"8. POST /me/mfa/confirm con un código real de pyotp -> 200 y GET /me/mfa dice enrolled=true (fue {r.status_code})",
        r.status_code == 200 and status["enrolled"] is True and status["pending"] is False,
    )
    r = client.post("/api/v1/me/mfa/enroll", headers=auth_headers(admin_token))
    check(
        f"9. Enrolar de nuevo sobre un factor confirmado -> 409 (un JWT robado no puede pisar el factor de la víctima) (fue {r.status_code})",
        r.status_code == 409,
    )
    stored = admin.table("user_totp_factors").select("secret_envelope").eq("user_id", admin_id).execute().data[0]
    check(
        "10. Lo persistido del factor es un sobre cifrado: el secreto TOTP no está en claro en la fila (lectura directa)",
        admin_secret not in json.dumps(stored),
    )

    # El trabajador se enrola por su cuenta.
    r = client.post("/api/v1/me/mfa/enroll", headers=auth_headers(worker_token))
    worker_secret = r.json()["secret"]
    _secrets_seen.extend([worker_secret, r.json()["otpauth_uri"]])
    rc = client.post("/api/v1/me/mfa/confirm", headers=auth_headers(worker_token, code_now(worker_secret)))
    check(
        f"11. El trabajador enrola y confirma su propio factor (require_user, no require_enterprise) (fue {r.status_code}/{rc.status_code})",
        r.status_code == 201 and rc.status_code == 200,
    )

    # ================================================================ C. Lecturas con factor (AC1, AC4)
    print("\n--- C. Lectura con segundo factor")
    wait_next_step("confirmar consumió el paso actual")

    good = code_now(admin_secret)
    r = client.post(reveal_ext, headers=auth_headers(admin_token, good))
    check(
        f"12. Con un código vigente la empresa lee la credencial y el plaintext coincide con lo guardado (AC1) (fue {r.status_code})",
        r.status_code == 200 and r.json().get("password") == EXT_PASSWORD,
    )
    r = client.post(reveal_ext, headers=auth_headers(admin_token, good))
    check(
        f"13. Reusar ese MISMO código -> 403 totp_reutilizado (anti-replay RFC 6238 §5.2) (fue {r.status_code} {r.json().get('code')})",
        r.status_code == 403 and r.json().get("code") == "totp_reutilizado",
    )
    bad = wrong_code(admin_secret)
    r = client.post(reveal_ext, headers=auth_headers(admin_token, bad))
    check(
        f"14. Un código incorrecto -> 403 totp_invalido (fue {r.status_code} {r.json().get('code')})",
        r.status_code == 403 and r.json().get("code") == "totp_invalido",
    )
    check("15. El 403 de un código incorrecto no trae el plaintext (AC4)", EXT_PASSWORD not in r.text)

    rows = panel_rows(admin, org_id)
    check(
        "16. La auditoría (lectura directa) tiene UNA lectura exitosa y las denegaciones con su motivo: no_enrolado ×3 (admin sin factor, trabajador sin factor, admin con factor pendiente), reutilizado ×1, invalido ×1 (AC4)",
        len(rows_of(rows, "consultar_secreto")) == 1
        and len(rows_of(rows, "consultar_secreto_denegado", "totp_no_enrolado")) == 3
        and len(rows_of(rows, "consultar_secreto_denegado", "totp_reutilizado")) == 1
        and len(rows_of(rows, "consultar_secreto_denegado", "totp_invalido")) == 1,
    )

    r = client.post(f"/api/v1/me/credentials/{ext_id}/reveal", headers=auth_headers(worker_token, code_now(worker_secret)))
    check(
        f"17. El trabajador, con SU código, retira la credencial que la empresa le asignó (fue {r.status_code})",
        r.status_code == 200 and r.json().get("password") == EXT_PASSWORD,
    )
    audit_view = client.get("/api/v1/vault/audit", headers=auth_headers(worker_token)).json()
    seen = {a["action"] for a in audit_view}
    check(
        f"18. El trabajador ve el ciclo de vida de su factor en su propia auditoría (mfa_enrolar, mfa_activar): {sorted(seen & {'mfa_enrolar', 'mfa_activar'})}",
        {"mfa_enrolar", "mfa_activar"} <= seen,
    )

    # ================================================================ D. Cuenta interna (AC2, AC5)
    print("\n--- D. Rotación de una cuenta interna (AC2) y revocación de sesiones (AC5)")
    wait_next_step("el código anterior ya se usó")

    r = client.post(f"/api/v1/dashboard/credentials/{internal_id}/revoke", headers=auth_headers(admin_token), json={})
    rows = panel_rows(admin, org_id)
    still_active = credential_row(admin, internal_id)["status"] == "activa"
    still_works = client.get("/api/v1/me/credentials", headers=auth_headers(worker_token)).status_code == 200
    check(
        f"19. Revocar SIN código -> 403 + fila revocar_interna_denegado, y NADA se ejecutó: la credencial sigue activa y el token del trabajador sigue sirviendo (fue {r.status_code})",
        r.status_code == 403 and len(rows_of(rows, "revocar_interna_denegado", "totp_invalido")) == 1
        and still_active and still_works,
    )

    r = client.post(
        f"/api/v1/dashboard/credentials/{internal_id}/revoke",
        headers=auth_headers(admin_token, code_now(admin_secret)),
        json={},
    )
    revoked = r.json() if r.status_code == 200 else {}
    applied = revoked.get("applied_password")
    if applied:
        _secrets_seen.append(applied)
    check(
        f"20. Revocar CON un código vigente -> 200; genera la contraseña nueva, Auth la acepta y queda guardada cifrada (AC2) (fue {r.status_code})",
        r.status_code == 200 and bool(applied) and revoked.get("admin_api_success") is True
        and revoked.get("secret_stored") is True,
    )
    check(
        "21. La credencial quedó `revocada` en la base (lectura directa)",
        credential_row(admin, internal_id)["status"] == "revocada",
    )

    # AC5, medido. Lo que el AC dice («un access_token ya emitido puede seguir válido ~1 h») es
    # una propiedad de OTRO componente: se mide, no se cita.
    r = client.get("/api/v1/me/credentials", headers=auth_headers(worker_token))
    check(
        f"22. AC5 MEDIDO — el access token que el trabajador YA tenía deja de servir en la petición siguiente -> 401 (fue {r.status_code}). verify_token consulta a Auth en CADA request: no valida el JWT localmente",
        r.status_code == 401,
    )
    old_login = gotrue("token", "password", {"email": worker["email"], "password": worker["temporary_password"]})
    new_login = gotrue("token", "password", {"email": worker["email"], "password": applied or ""})
    print(f"      login con la contraseña VIEJA -> {old_login.status_code} {old_login.json().get('error_code') or old_login.json().get('msg', '')}")
    print(f"      login con la contraseña NUEVA -> {new_login.status_code} {new_login.json().get('error_code') or new_login.json().get('msg', '')}")
    check(
        f"23. AC5 MEDIDO — sesiones futuras bloqueadas: ni la contraseña vieja ni la nueva inician sesión (la cuenta está baneada) (fue {old_login.status_code}/{new_login.status_code})",
        old_login.status_code >= 400 and new_login.status_code >= 400,
    )
    refreshed = gotrue("token", "refresh_token", {"refresh_token": worker_refresh})
    print(f"      refresh con el refresh_token previo -> {refreshed.status_code} {refreshed.json().get('error_code') or refreshed.json().get('msg', '')}")
    check(
        f"24. AC5 MEDIDO — el refresh token emitido ANTES de revocar ya no renueva la sesión (fue {refreshed.status_code})",
        refreshed.status_code >= 400,
    )

    # ================================================================ E. Cuenta externa (AC3)
    print("\n--- E. Cuenta externa: sugerida y pendiente de aplicación manual (AC3)")
    r = client.post(f"/api/v1/dashboard/credentials/{ext_id}/suggest", headers=auth_headers(admin_token), json={})
    rows = panel_rows(admin, org_id)
    check(
        f"25. Sugerir SIN código -> 403 + fila sugerir_externa_denegado, y la credencial sigue `activa` (fue {r.status_code})",
        r.status_code == 403 and len(rows_of(rows, "sugerir_externa_denegado", "totp_invalido")) == 1
        and credential_row(admin, ext_id)["status"] == "activa",
    )
    wait_next_step("el código anterior ya se usó")
    r = client.post(
        f"/api/v1/dashboard/credentials/{ext_id}/suggest",
        headers=auth_headers(admin_token, code_now(admin_secret)),
        json={},
    )
    suggested = r.json() if r.status_code == 200 else {}
    if suggested.get("suggested_password"):
        _secrets_seen.append(suggested["suggested_password"])
    check(
        f"26. Sugerir CON código -> 200, contraseña sugerida, estado `pendiente_aplicacion_manual`, y NO declara el cambio efectuado: applied_password es null (AC3) (fue {r.status_code})",
        r.status_code == 200 and bool(suggested.get("suggested_password"))
        and suggested.get("credential", {}).get("status") == "pendiente_aplicacion_manual"
        and suggested.get("applied_password") is None
        and credential_row(admin, ext_id)["status"] == "pendiente_aplicacion_manual",
    )

    # ================================================================ F. Guardar una contraseña
    print("\n--- F. Guardar una contraseña nueva (es rotar)")
    before = credential_row(admin, ext_id)["secret_updated_at"]
    put = f"/api/v1/dashboard/credentials/{ext_id}/secret"
    r = client.put(put, headers=auth_headers(admin_token), json={"password": "Manual#Nueva_18"})
    _secrets_seen.append("Manual#Nueva_18")
    rows = panel_rows(admin, org_id)
    check(
        f"27. PUT /secret SIN código -> 403 + fila guardar_secreto_denegado, y secret_updated_at no cambió (fue {r.status_code})",
        r.status_code == 403 and len(rows_of(rows, "guardar_secreto_denegado", "totp_invalido")) == 1
        and credential_row(admin, ext_id)["secret_updated_at"] == before,
    )
    wait_next_step("el código anterior ya se usó")
    r = client.put(put, headers=auth_headers(admin_token, code_now(admin_secret)), json={"password": "Manual#Nueva_18"})
    check(
        f"28. PUT /secret CON código -> 200 y secret_updated_at avanzó (fue {r.status_code})",
        r.status_code == 200 and credential_row(admin, ext_id)["secret_updated_at"] != before,
    )

    # ================================================================ G. Desactivar
    print("\n--- G. Desactivar el factor")
    r = client.request("DELETE", "/api/v1/me/mfa", headers=auth_headers(admin_token, wrong_code(admin_secret)))
    still = client.get("/api/v1/me/mfa", headers=auth_headers(admin_token)).json()
    check(
        f"29. DELETE /me/mfa con un código incorrecto -> 403 y el factor SIGUE activo (fue {r.status_code}, enrolled={still['enrolled']})",
        r.status_code == 403 and still["enrolled"] is True,
    )
    wait_next_step("el código anterior ya se usó")
    r = client.request("DELETE", "/api/v1/me/mfa", headers=auth_headers(admin_token, code_now(admin_secret)))
    r2 = client.post(reveal_ext, headers=auth_headers(admin_token))
    check(
        f"30. DELETE con un código vigente -> 204, y el siguiente intento vuelve a totp_no_enrolado (fue {r.status_code}/{r2.json().get('code')})",
        r.status_code == 204 and r2.json().get("code") == "totp_no_enrolado",
    )

    # ================================================================ H. Bloqueo por fuerza bruta
    print("\n--- H. Bloqueo por intentos fallidos")
    r = client.post("/api/v1/me/mfa/enroll", headers=auth_headers(admin_token))
    lock_secret = r.json()["secret"]
    _secrets_seen.extend([lock_secret, r.json()["otpauth_uri"]])
    client.post("/api/v1/me/mfa/confirm", headers=auth_headers(admin_token, code_now(lock_secret)))
    codes = []
    for _ in range(totp_service.MAX_FAILED):
        resp = client.post(reveal_ext, headers=auth_headers(admin_token, wrong_code(lock_secret)))
        codes.append(resp.json().get("code"))
    check(
        f"31. {totp_service.MAX_FAILED} códigos incorrectos seguidos -> el último responde totp_bloqueado ({codes})",
        codes[:-1] == ["totp_invalido"] * (totp_service.MAX_FAILED - 1) and codes[-1] == "totp_bloqueado",
    )
    wait_next_step("un código NUEVO y válido, para que no se rechace por reutilizado")
    r = client.post(reveal_ext, headers=auth_headers(admin_token, code_now(lock_secret)))
    check(
        f"32. Bloqueado, ni siquiera un código CORRECTO y fresco pasa: sigue totp_bloqueado (fue {r.status_code} {r.json().get('code')})",
        r.status_code == 403 and r.json().get("code") == "totp_bloqueado",
    )

    # ================================================================ I. Integridad y fugas
    print("\n--- I. Integridad de la auditoría y ausencia de fugas")
    ok_panel, broken_panel = audit_chain.verify_chain_jsonb(PANEL_LOG)
    ok_vault, broken_vault = audit_chain.verify_chain(VAULT_LOG)
    check(
        f"33. Las dos cadenas de auditoría siguen íntegras con todas las entradas de esta corrida (panel={ok_panel}, vault={ok_vault})",
        ok_panel and ok_vault,
    )
    panel_all = panel_rows(admin, org_id)
    # Solo las columnas de contenido: los hashes hexadecimales y los UUID podrían contener por
    # azar seis dígitos seguidos, y un falso positivo aquí sería evidencia rota.
    vault_all = (
        admin.table(VAULT_LOG)
        .select("user_id, item_id, action, result, deleted_count, actor_user_id")
        .in_("user_id", [admin_id, worker["user_id"]])
        .execute()
        .data
    )
    dump = json.dumps({"panel": panel_all, "vault": vault_all}, default=str)
    values = {v for v in _flatten_strings({"panel": panel_all, "vault": vault_all})}
    leaked_secrets = sorted({s for s in _secrets_seen if s and s in dump})
    leaked_codes = sorted({c for c in _codes_seen if c in values})
    check(
        f"34. Ninguna contraseña, secreto TOTP ni URI otpauth:// ({len(set(_secrets_seen))}) aparece en las filas de auditoría de esta corrida, ni ninguno de los {len(set(_codes_seen))} códigos usados como valor (filtrados: {len(leaked_secrets)} + {len(leaked_codes)}); {len(panel_all)} filas del panel y {len(vault_all)} del vault revisadas",
        not leaked_secrets and not leaked_codes,
    )
    reasons = {r["payload"].get("denied_reason") for r in panel_all if r["payload"].get("denied_reason")}
    check(
        f"35. Todo denied_reason en la auditoría es uno de los cuatro enums, nunca un código: {sorted(reasons)}",
        reasons <= {"totp_no_enrolado", "totp_invalido", "totp_reutilizado", "totp_bloqueado"},
    )

    # ================================================================ Lo que NO se ejercitó
    print()
    skip(
        "Revocar con la KEK de la bóveda caída (la razón de tener DOS claves): exige reiniciar el backend sin "
        "VAULT_MASTER_KEY, un proceso que este script no posee. Cubierto con mocks en test_dashboard_credentials.py; "
        "ver M1."
    )
    skip(
        "Fallar cerrado sin TOTP_MASTER_KEY (503): exige reiniciar el backend sin ella. Cubierto con mocks; ver M2."
    )
    skip(
        "Deriva de reloj > 30 s: exige alterar el reloj del sistema o del servidor. Se cubre de forma hermética en "
        "tests/test_totp_service.py con un reloj inyectado."
    )
    skip(
        "Expiración del bloqueo a los 15 min (el paso 31-32 prueba que bloquea, no que se libera): se cubre en "
        "tests/test_totp_service.py con un reloj inyectado."
    )
    skip(
        "PUT /secret con apply_to_account contra Auth real: en este punto la cuenta interna ya está revocada. Se cubre "
        "con mocks (orden: el factor va ANTES de tocar Auth)."
    )
    skip(
        "Ventana de ~1 h de un JWT validado SIN consultar a Auth: no existe ningún validador offline en este sistema "
        "(verify_token consulta a GoTrue en cada request, pasos 22 y 24), así que no hay nada que medir. La limitación "
        "existe para un tercero que valide el JWT por su cuenta, y queda DOCUMENTADA, no oculta, en ARQUITECTURA.md §7."
    )

    print("\nMANUAL (no automatizable):")
    print("  M1. Con el backend reiniciado SIN VAULT_MASTER_KEY: revocar una cuenta interna con un código vigente debe")
    print("      responder 200 (verifica el TOTP, banea y rota) con secret_stored=false; leer un secreto sigue dando 503.")
    print("  M2. Con el backend reiniciado SIN TOTP_MASTER_KEY: cualquier operación sensible debe responder 503 y no")
    print("      hacer nada (falla cerrado, no se omite el segundo factor).")
    print("  M3. Escanear el QR con Google Authenticator / Authy REALES (python scripts/seed_hu18_factor.py) y rotar una")
    print("      credencial con el código que muestra el teléfono: es la única prueba de que SHA1/6/30 es compatible")
    print("      con una app real. pyotp por defecto usa los mismos parámetros, pero no es un teléfono.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        check("La corrida terminó sin una excepción no prevista", False)
    finally:
        if CLEANUP:
            cleanup(get_supabase_admin())

    total = len(_results)
    passed = sum(1 for ok, _ in _results if ok)
    print(f"\n{passed}/{total} pasos OK, {len(_skipped)} omitidos (no cuentan como PASS).")
    if passed != total:
        sys.exit(1)
