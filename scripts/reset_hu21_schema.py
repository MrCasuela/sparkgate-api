"""DESTRUCTIVO — solo para entornos de desarrollo.

Recrea las tablas que HU21 cambia de forma:
  organizations, dashboard_members, dashboard_credentials,
  dashboard_credential_secrets (nueva), dashboard_audit_log, vault_audit_log

Las DROPEA y las vuelve a crear desde sql/dashboard_schema.sql y
sql/vault_schema.sql. **Se pierden todos sus datos.**

Por qué recrear y no migrar:
- vault_audit_log es una cadena hash y audit_chain.verify_chain reconstruye el payload
  de cada fila como "todas sus columnas salvo id/seq/prev_hash/entry_hash/created_at".
  Agregarle la columna actor_user_id hace que toda fila anterior se recomponga con una
  clave que no estaba presente al hashearla, así que la cadena entera deja de verificar.
- dashboard_audit_log pasa a ser una cadena hash (payload jsonb) y las filas existentes
  no tienen prev_hash: no hay nada que retroajustar.
- dashboard_credentials cambia de forma (org_id, member_id anulable con SET NULL,
  columnas nuevas) y es la tabla de la que cuelga el sobre cifrado.
Con datos reales habría que migrar con cuidado; en desarrollo, recrear deja además los
archivos .sql como única fuente de verdad, idénticos para un proyecto nuevo.

vault_items NO se toca: su esquema no cambia y los ítems cifrados guardados siguen
siendo válidos.

Después de correr esto hay que correr scripts/seed_dashboard_demo.py, que reconstruye
la organización, los integrantes y las credenciales de la demo. Los usuarios de
Supabase Auth no se tocan (viven en otro schema), así que el seed los reencuentra por
email y simplemente no imprime contraseñas nuevas.

Usage (from repo root, with venv active):
    python scripts/reset_hu21_schema.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import settings  # noqa: E402
from app.services.db_client import get_supabase_admin  # noqa: E402

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"
SCHEMA_FILES = [SQL_DIR / "dashboard_schema.sql", SQL_DIR / "vault_schema.sql"]

# El orden no importa con `cascade`, pero se listan de dependiente a dependencia
# para que se lea igual que el grafo de FKs.
# El orden no importa con `cascade`, pero se listan de dependiente a dependencia para
# que se lea igual que el grafo de FKs: los sobres cuelgan de las credenciales.
DROP_SQL = """
drop table if exists dashboard_credential_secrets cascade;
drop table if exists dashboard_credentials cascade;
drop table if exists dashboard_audit_log cascade;
drop table if exists dashboard_members cascade;
drop table if exists organizations cascade;
drop table if exists vault_audit_log cascade;
"""

# Tabla -> columna que se usa para contar filas. dashboard_credential_secrets no tiene
# id y se cuenta por su PK, para no leer el criptograma solo para contar.
RECREATED_TABLES = {
    "organizations": "id",
    "dashboard_members": "id",
    "dashboard_credentials": "id",
    "dashboard_credential_secrets": "credential_id",
    "dashboard_audit_log": "id",
    "vault_audit_log": "id",
}

# Lo que se verifica al final contra PostgREST: las recreadas y la que NO se toca.
# (Antes se usaba TABLES[:-1] para excluir vault_items por ser la última de la lista;
# agregar una tabla hacía que el slice excluyera la equivocada y reportara vault_items
# como "a destruir".)
VERIFIED_TABLES = [*RECREATED_TABLES, "vault_items"]


def build_sql() -> str:
    parts = [DROP_SQL]
    for schema_file in SCHEMA_FILES:
        parts.append(f"\n-- {schema_file.name}\n")
        parts.append(schema_file.read_text(encoding="utf-8"))
    return "\n".join(parts)


def report_current_rows() -> None:
    """Muestra qué se está por destruir. No bloquea: en desarrollo perder estos
    datos es el comportamiento buscado."""
    admin = get_supabase_admin()
    print("Filas actuales en las tablas que se van a recrear:")
    for table, count_column in RECREATED_TABLES.items():
        try:
            result = admin.table(table).select(count_column, count="exact").limit(1).execute()
            print(f"  {table}: {result.count}")
        except Exception:
            print(f"  {table}: (no existe todavía)")


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
    for table in VERIFIED_TABLES:
        try:
            admin.table(table).select(RECREATED_TABLES.get(table, "id")).limit(1).execute()
            print(f"  OK   {table} — la API la ve")
        except Exception as e:
            print(f"  FAIL {table} — {e}")
            all_ok = False
    return all_ok


def main() -> None:
    if not settings.supabase_service_role_key:
        print("SUPABASE_SERVICE_ROLE_KEY no está configurada en .env. Abortando.")
        sys.exit(1)

    print("=" * 70)
    print("RESET DE ESQUEMA HU21 — DESTRUCTIVO, SOLO DESARROLLO")
    print("=" * 70)
    report_current_rows()
    print()

    sql = build_sql()

    applied = apply_via_psycopg(sql)
    if not applied:
        print_manual_instructions(sql)
        print("\nUna vez aplicado manualmente, volvé a correr este script para verificar.")

    print("\nVerificando contra la API (PostgREST)...")
    ok = verify()

    if not ok:
        print(
            "\nLas tablas no responden todavía. Si acabás de aplicar el SQL a mano, "
            "esperá unos segundos: PostgREST cachea su propio esquema y puede tardar "
            "en refrescarlo."
        )
        sys.exit(1)

    print("\nListo. Siguiente paso obligatorio:")
    print("    python scripts/seed_dashboard_demo.py")


if __name__ == "__main__":
    main()
