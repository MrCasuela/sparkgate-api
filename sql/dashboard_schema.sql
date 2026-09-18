-- SP-1 offboarding dashboard schema + organizaciones (HU21 etapa A).
-- Run once in the Supabase SQL editor of the target project.
-- RLS activado SIN policies (deny-all, ver el final del archivo). Estas tablas
-- solo las toca el backend con la clave service_role
-- (app/services/db_client.py:get_supabase_admin), que ignora RLS. El aislamiento
-- entre organizaciones sigue siendo application-side: require_enterprise resuelve
-- la organización del caller contra la tabla organizations (nunca contra el claim
-- del token) y cada consulta de dashboard_repo.py filtra por org_id.
-- RLS cierra el OTRO camino: la clave anon de Supabase es pública por diseño y
-- PostgREST expone el schema public, así que sin RLS cualquiera con esa clave
-- lee y ESCRIBE estas tablas directo, saltándose el backend por completo.

create extension if not exists pgcrypto;

-- Fuente de verdad de la tenencia. El org_id con el que se filtra todo el panel
-- sale de acá; el claim homónimo en user_metadata es solo cache de gateo.
-- owner_user_id es unique: una cuenta de empresa administra una organización.
create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null unique,
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists dashboard_members (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id),
  full_name text not null,
  email text not null,
  role_title text,
  -- Puente con la cuenta SparkGate del integrante. Es lo que la empresa usa
  -- para abrir su bóveda (HU21 etapa B), y lo que se anula -sin borrar la fila-
  -- cuando el integrante ejerce su derecho de supresión.
  supabase_user_id uuid,
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
  org_id uuid not null,
  actor_email text not null,
  member_id uuid not null,
  -- Nullables desde HU21: un evento de bóveda (consultar_vault_miembro) no
  -- tiene credencial de gobernanza asociada, tiene vault_item_id.
  credential_id uuid,
  credential_type text,
  vault_item_id uuid,
  action text not null,
  created_at timestamptz not null default now()
);

create index if not exists dashboard_members_org_id_idx
  on dashboard_members(org_id);
create index if not exists dashboard_credentials_member_id_idx
  on dashboard_credentials(member_id);
create index if not exists dashboard_audit_log_org_id_idx
  on dashboard_audit_log(org_id);
create index if not exists dashboard_audit_log_created_at_idx
  on dashboard_audit_log(created_at desc);

-- Deny-all para anon y authenticated: RLS sin policies no deja ver ni tocar
-- ninguna fila. Idempotente. service_role (el backend) ignora RLS y no se ve
-- afectado. No hay policies por usuario a propósito: ningún cliente se conecta
-- a estas tablas con un JWT de usuario, así que serían código muerto que sugiere
-- una protección que el camino real (backend) no usa.
alter table organizations enable row level security;
alter table dashboard_members enable row level security;
alter table dashboard_credentials enable row level security;
alter table dashboard_audit_log enable row level security;
