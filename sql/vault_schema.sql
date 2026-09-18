-- HU17 vault schema (SP-2).
-- Run once in the Supabase SQL editor of the target project.
-- No RLS: these tables are only ever accessed by the backend via the
-- service_role key (see app/services/db_client.py:get_supabase_admin),
-- gated application-side by the authenticated user's own id (require_user).

create extension if not exists pgcrypto;

create table if not exists vault_items (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  service_name text not null,
  username text,
  ciphertext text not null,
  nonce text not null,
  wrapped_dek text not null,
  dek_nonce text not null,
  kek_version int not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Registro encadenado (HU19). Payload seudónimo a propósito: solo UUIDs y
-- enums, nunca service_name, secretos ni email, para que la supresión de
-- datos (Ley 21.719) nunca obligue a romper la cadena.
create table if not exists vault_audit_log (
  seq bigserial unique not null,
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  item_id uuid,
  action text not null check (action in (
    'guardar', 'listar', 'consultar', 'consultar_denegado',
    'eliminar', 'eliminar_denegado', 'eliminar_todo', 'eliminar_cuenta',
    -- HU21: la empresa consultando la bóveda de un trabajador.
    'listar_admin', 'consultar_admin', 'consultar_admin_denegado'
  )),
  result text not null default 'ok' check (result in ('ok', 'denegado', 'error')),
  deleted_count int,
  -- Quién consultó, cuando no fue el dueño (HU21 AC7). El trabajador lo ve en
  -- su propio GET /api/v1/vault/audit: es la mitigación de privacidad de esa
  -- historia. Sigue siendo seudónimo (un UUID), acorde al criterio del payload.
  actor_user_id uuid,
  prev_hash text not null unique,
  entry_hash text not null,
  created_at timestamptz not null default now()
);

create index if not exists vault_items_user_id_idx on vault_items(user_id);
create index if not exists vault_audit_log_user_id_idx on vault_audit_log(user_id);
