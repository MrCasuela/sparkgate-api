"""Sobres cifrados de las credenciales de la organización.

Este es el ÚNICO módulo (junto con vault_repo/vault_crypto para la bóveda personal)
que nombra las columnas del criptograma. dashboard_credentials no las tiene: viven
en una tabla aparte precisamente para que ningún listado del panel pueda arrastrarlas
al proceso. Un test escanea app/ y falla si `ciphertext` o `wrapped_dek` aparecen en
otro archivo.

El sobre es de la ORGANIZACIÓN, no del integrante: la fila lleva su propio org_id y
ese es el AAD con el que se cifró. Por eso reasignar una credencial no toca este
módulo (es un UPDATE de member_id), y por eso el borrado de cuenta de un trabajador
(Ley 21.719) no puede destruir un secreto que es de la empresa.

Mismo patrón que dashboard_repo/vault_repo: funciones sync, get_supabase_admin() por
llamada, sin try/except.
"""

from datetime import datetime, timezone

from app.services.db_client import get_supabase_admin

SECRETS_TABLE = "dashboard_credential_secrets"

ENVELOPE_COLUMNS = (
    "credential_id, org_id, ciphertext, nonce, wrapped_dek, dek_nonce, kek_version, updated_at"
)


def upsert_secret(*, credential_id: str, org_id: str, envelope: dict) -> None:
    """Guarda o reemplaza el sobre de una credencial. Un secreto vigente por
    credencial: no hay historial (fuera de alcance)."""
    admin = get_supabase_admin()
    admin.table(SECRETS_TABLE).upsert(
        {
            "credential_id": credential_id,
            "org_id": org_id,
            **envelope,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        on_conflict="credential_id",
    ).execute()


def get_envelope(credential_id: str, org_id: str) -> dict | None:
    admin = get_supabase_admin()
    result = (
        admin.table(SECRETS_TABLE)
        .select(ENVELOPE_COLUMNS)
        .eq("credential_id", credential_id)
        .eq("org_id", org_id)
        .maybe_single()
        .execute()
    )
    return result.data if result else None


def delete_secret(credential_id: str) -> bool:
    admin = get_supabase_admin()
    result = admin.table(SECRETS_TABLE).delete().eq("credential_id", credential_id).execute()
    return bool(result.data)


def delete_secrets_for_credentials(credential_ids: list[str]) -> int:
    if not credential_ids:
        return 0
    admin = get_supabase_admin()
    result = admin.table(SECRETS_TABLE).delete().in_("credential_id", credential_ids).execute()
    return len(result.data)
