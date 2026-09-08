-- SP-1 offboarding dashboard schema.
-- Run once in the Supabase SQL editor of the target project.
-- No RLS: these tables are only ever accessed by the backend via the
-- service_role key (see app/services/db_client.py:get_supabase_admin),
-- gated application-side by the is_admin user_metadata flag.

create extension if not exists pgcrypto;

create table if not exists dashboard_members (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  email text not null,
  role_title text,
  created_at timestamptz not null default now()
);

create table if not exists dashboard_credentials (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references dashboard_members(id) on delete cascade,
  type text not null check (type in ('interna', 'externa')),
  service_name text not null,
  supabase_user_id uuid,
  status text not null default 'activa'
    check (status in ('activa', 'revocada', 'pendiente_aplicacion_manual')),
  updated_at timestamptz not null default now()
);

create table if not exists dashboard_audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_email text not null,
  member_id uuid not null,
  credential_id uuid not null,
  credential_type text not null,
  action text not null,
  created_at timestamptz not null default now()
);

create index if not exists dashboard_credentials_member_id_idx
  on dashboard_credentials(member_id);
create index if not exists dashboard_audit_log_created_at_idx
  on dashboard_audit_log(created_at desc);
