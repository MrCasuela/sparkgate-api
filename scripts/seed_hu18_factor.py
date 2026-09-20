"""Enrola el segundo factor TOTP (HU18) de una cuenta ya existente, para la demostración.

Desde HU18, leer o rotar la credencial de un tercero exige un código TOTP vigente. Ninguna
cuenta sembrada antes tiene factor, así que el panel demo responde 403 `totp_no_enrolado`
hasta que la dueña se enrole. Este script lo hace por ella:

    python scripts/seed_hu18_factor.py                      # deja un factor PENDIENTE e imprime el secreto
    python scripts/seed_hu18_factor.py --confirm 123456     # confirma con el primer código de la app
    python scripts/seed_hu18_factor.py --reset              # break-glass: borra el factor (ver abajo)
    python scripts/seed_hu18_factor.py --email otra@cuenta  # otra cuenta (default: la dueña demo)

Flujo normal: correrlo sin argumentos, ingresar el secreto (o el URI otpauth://) en Google
Authenticator / Authy / 1Password, y volver a correrlo con `--confirm <código que muestra la
app>`. Un factor pendiente NO habilita nada: hasta confirmarlo, el panel sigue dando
`totp_no_enrolado`.

Idempotente: si la cuenta ya tiene un factor CONFIRMADO no lo pisa (mismo criterio que
POST /me/mfa/enroll: un factor activo solo se reemplaza desactivándolo con un código válido).

--reset es el break-glass de R-HU18-1. Si alguien pierde el teléfono (o se pierde
TOTP_MASTER_KEY y hay que rehacer los factores), un operador con SUPABASE_SERVICE_ROLE_KEY
borra la fila y la persona se vuelve a enrolar. No recupera ningún secreto: recupera el
acceso al sistema. El siguiente intento de leer algo queda auditado como `totp_no_enrolado`,
así que el borrado deja rastro. NO hay una variable de entorno que apague el segundo factor,
a propósito: el camino de emergencia es administrativo y auditable, no un interruptor global.

Requiere SUPABASE_SERVICE_ROLE_KEY y TOTP_MASTER_KEY en .env, y `python
scripts/apply_mfa_schema.py` aplicado.

Imprime un secreto TOTP en la terminal: correrlo en una máquina de confianza y no pegar la
salida en ningún registro compartido.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.services import totp_repo, totp_service, vault_crypto  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

DEMO_EMAIL = "admin@pyme-demo.sparkgate.test"


def find_user_id(admin, email: str) -> str | None:
    existing = admin.auth.admin.list_users()
    users = existing.users if hasattr(existing, "users") else existing
    for user in users:
        if user.email == email:
            return user.id
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrola el factor TOTP de una cuenta (HU18).")
    parser.add_argument("--email", default=DEMO_EMAIL)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--confirm", metavar="CODIGO", help="confirma el enrolamiento pendiente")
    action.add_argument("--reset", action="store_true", help="break-glass: borra el factor de la cuenta")
    args = parser.parse_args()

    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no está configurada en .env. Abortando.")
        sys.exit(1)
    if not vault_crypto.is_available(settings.totp_master_key):
        print(
            "TOTP_MASTER_KEY no está configurada (o es inválida). Abortando: sin ella el factor no "
            "se puede sellar ni verificar. Generala con:\n"
            '  python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"'
        )
        sys.exit(1)

    admin = get_supabase_admin()
    user_id = find_user_id(admin, args.email)
    if user_id is None:
        print(f"No existe una cuenta de Auth con el correo {args.email}. ¿Corriste seed_dashboard_demo.py?")
        sys.exit(1)

    if args.reset:
        deleted = totp_repo.delete_factor(user_id)
        print(
            f"Factor de {args.email} eliminado." if deleted else f"{args.email} no tenía un factor."
        )
        print("La persona puede volver a enrolarse (POST /api/v1/me/mfa/enroll).")
        return

    if args.confirm:
        try:
            totp_service.confirm_enrollment(user_id, args.confirm)
        except totp_service.TotpDenied as denied:
            print(f"No se confirmó: {denied.code}. Sin un enrolamiento pendiente, corré el script sin argumentos primero.")
            sys.exit(1)
        print(f"Segundo factor de {args.email} ACTIVO. Un código vale una sola vez (anti-replay).")
        return

    if totp_service.is_enrolled(user_id):
        print(f"{args.email} ya tiene un factor ACTIVO: no se toca. Para rehacerlo, --reset y volver a empezar.")
        return

    enrollment = totp_service.start_enrollment(user_id, args.email)
    print(f"Factor PENDIENTE para {args.email} (no habilita nada hasta confirmarlo).\n")
    print(f"  secreto (ingreso manual): {enrollment['secret']}")
    print(f"  URI otpauth://          : {enrollment['otpauth_uri']}")
    print(
        f"\nParámetros: {enrollment['algorithm']} · {enrollment['digits']} dígitos · "
        f"{enrollment['period']} s. Sincronizá el reloj del teléfono.\n"
        "Cuando la app muestre el primer código:\n"
        f"    python scripts/seed_hu18_factor.py --email {args.email} --confirm <código>"
    )


if __name__ == "__main__":
    main()
