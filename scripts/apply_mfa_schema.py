"""Applies sql/mfa_schema.sql (HU18: user_totp_factors + acciones nuevas de auditoría) to
the target Supabase project.

Idempotent: `create table if not exists`, `drop constraint if exists` + `add constraint`.
Additive: no table is recreated, so neither audit chain is invalidated (the CHECKs change,
the column sets don't). scripts/reset_hu21_schema.py is NOT needed.

Two paths, in this order:
1. If SUPABASE_DB_URL is set, connect directly with psycopg and execute the SQL file.
2. Otherwise print the SQL to paste into the Supabase SQL editor and exit 0 (documented
   manual path, not an error).

Either way, verifies at the end that user_totp_factors is queryable via the same PostgREST
client the app uses. That does NOT prove the new audit actions were accepted by the CHECK
constraints (that would need writing to a hash chain); the E2E does, by exercising them.

Usage (from repo root, with venv active):
    python scripts/apply_mfa_schema.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "sql" / "mfa_schema.sql"
TABLES = ["user_totp_factors"]


def apply_via_psycopg(sql: str) -> bool:
    try:
        import psycopg
    except ImportError:
        return False

    if not settings.supabase_db_url:
        return False

    print("Connecting to Postgres via SUPABASE_DB_URL...")
    with psycopg.connect(settings.supabase_db_url, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    print("DDL executed.")
    return True


def print_manual_instructions(sql: str) -> None:
    print(
        "SUPABASE_DB_URL no está configurada (o psycopg no está instalado).\n"
        "Camino manual: pegá este SQL en el SQL editor de tu proyecto Supabase y ejecutalo:\n"
    )
    print("-" * 70)
    print(sql)
    print("-" * 70)


def verify() -> bool:
    admin = get_supabase_admin()
    all_ok = True
    for table in TABLES:
        try:
            admin.table(table).select("user_id").limit(1).execute()
            print(f"  OK   {table} — la API la ve")
        except Exception as e:
            print(f"  FAIL {table} — {e}")
            all_ok = False
    return all_ok


def main() -> None:
    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no está configurada en .env. Abortando.")
        sys.exit(1)

    sql = SCHEMA_FILE.read_text(encoding="utf-8")

    applied = apply_via_psycopg(sql)
    if not applied:
        print_manual_instructions(sql)
        print("\nUna vez aplicado manualmente, volvé a correr este script para verificar.")

    print("\nVerificando contra la API (PostgREST)...")
    ok = verify()

    if not ok:
        print(
            "\nLa tabla no responde todavía. Si acabás de aplicar el SQL a mano, esperá unos "
            "segundos: PostgREST cachea su propio esquema y puede tardar en refrescarlo."
        )
        sys.exit(1)

    print("\nListo: user_totp_factors está operativa.")
    print(
        "Recordatorio: las acciones nuevas de auditoría (mfa_*, *_denegado) solo se "
        "comprueban al escribirlas; las ejercita scripts/e2e_hu18_check.py."
    )


if __name__ == "__main__":
    main()
