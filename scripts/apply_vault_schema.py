"""Applies sql/vault_schema.sql (HU17: vault_items, vault_audit_log) to the target
Supabase project.

Idempotent: the DDL uses `create table if not exists` / `create index if not exists`,
so running this more than once is safe.

Two paths, in this order:
1. If SUPABASE_DB_URL is set (Supabase dashboard -> Project Settings -> Database ->
   Connection string -> URI), connect directly with psycopg and execute the SQL file.
2. Otherwise, don't fail silently: print the SQL to paste into the Supabase SQL editor
   and exit 0 (this is the documented manual path, not an error).

Either way, verifies at the end that vault_items / vault_audit_log are queryable via
the same PostgREST client the app uses (get_supabase_admin()) — that's the real proof
the API can see them, since PostgREST caches its schema separately from Postgres itself.

Usage (from repo root, with venv active):
    python scripts/apply_vault_schema.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "sql" / "vault_schema.sql"
TABLES = ["vault_items", "vault_audit_log"]


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
            admin.table(table).select("*").limit(1).execute()
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
        print(
            "\nUna vez aplicado manualmente, volvé a correr este script para verificar."
        )

    print("\nVerificando contra la API (PostgREST)...")
    ok = verify()

    if not ok:
        print(
            "\nLas tablas no responden todavía. Si acabás de aplicar el SQL a mano, "
            "esperá unos segundos: PostgREST cachea su propio esquema y puede tardar "
            "en refrescarlo."
        )
        sys.exit(1)

    print("\nListo: vault_items y vault_audit_log están operativas.")


if __name__ == "__main__":
    main()
