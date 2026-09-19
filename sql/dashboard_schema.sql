-- SP-1 offboarding dashboard schema + organizaciones (HU21 etapas A y C).
-- Run once in the Supabase SQL editor of the target project.
--
-- RLS activado SIN policies (deny-all, ver el final del archivo). Estas tablas
-- solo las toca el backend con la clave service_role
-- (app/services/db_client.py:get_supabase_admin), que ignora RLS. El aislamiento
-- entre organizaciones sigue siendo application-side: require_enterprise resuelve
-- la organización del caller contra la tabla organizations (nunca contra el claim
-- del token) y cada consulta de dashboard_repo.py filtra por org_id.
-- RLS cierra el OTRO camino: la clave anon de Supabase es pública por diseño y
-- PostgREST expone el schema public, así que sin RLS cualquiera con esa clave
-- lee y ESCRIBE estas tablas directo, saltándose el backend por completo.
-- Toda tabla nueva de public nace con privilegios para anon: el enable row level
-- security va en este mismo archivo, no en otro commit.

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

-- La credencial es de la ORGANIZACIÓN; el integrante es solo su portador actual.
create table if not exists dashboard_credentials (
  id uuid primary key default gen_random_uuid(),

  -- Tenencia REAL en la fila, no derivada de un join a dashboard_members. Es el
  -- valor con el que se cifra el secreto (el AAD): tiene que salir de la misma fila
  -- que el criptograma, o el binding criptográfico no afirma nada verificable.
  org_id uuid not null references organizations(id),

  -- Nullable y ON DELETE SET NULL (antes: not null + ON DELETE CASCADE). Borrar a la
  -- persona no puede borrar el secreto de la empresa, y reasignar a un reemplazo es
  -- un UPDATE de esta columna, sin re-cifrar nada. member_id null = credencial en el
  -- pool sin asignar, un estado de primera clase.
  member_id uuid references dashboard_members(id) on delete set null,

  type text not null check (type in ('interna', 'externa')),
  service_name text not null,
  -- "Saber cuál es para dárselo al empleado" necesita el usuario, no solo el servicio.
  username text,
  supabase_user_id uuid,
  status text not null default 'activa'
    check (status in ('activa', 'revocada', 'pendiente_aplicacion_manual')),

  -- Marca de "hay un secreto guardado" y de cuándo se rotó. Vive acá y no se deduce de
  -- un join a la tabla de sobres, justamente para que el camino de listado nunca toque
  -- la tabla del criptograma.
  secret_updated_at timestamptz,
  -- Se enciende al bloquear a alguien o reasignar la credencial (quien la tenía ya
  -- conoce su contraseña); solo se apaga guardando una contraseña nueva.
  rotation_required boolean not null default false,

  updated_at timestamptz not null default now()
);

-- ÚNICA tabla con criptograma de la organización. Un secreto vigente por credencial:
-- no hay historial. Separada de dashboard_credentials a propósito: el listado del
-- panel hace un embed de credenciales por cada integrante, y con el sobre en la misma
-- tabla cada carga traería el criptograma de toda la organización al proceso.
create table if not exists dashboard_credential_secrets (
  credential_id uuid primary key
    references dashboard_credentials(id) on delete cascade,
  -- Redundante con dashboard_credentials.org_id A PROPÓSITO: el AAD con el que se
  -- descifra sale de ESTA fila, no de otra consulta. Si alguien moviera el criptograma
  -- bajo otra organización sin mover este valor, el tag GCM falla.
  org_id uuid not null references organizations(id),
  ciphertext text not null,
  nonce text not null,
  wrapped_dek text not null,
  dek_nonce text not null,
  kek_version int not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Cadena hash. Lo que se hashea es la columna `payload`, NO la forma de la tabla: es la
-- salida que recomienda _Leccion-cadena-hash-vs-evolucion-de-esquema. Con el key set
-- congelado en el origen, un ADD COLUMN posterior ya no puede invalidar la historia.
create table if not exists dashboard_audit_log (
  seq bigserial unique not null,
  id uuid primary key default gen_random_uuid(),

  -- Proyecciones GENERADAS del payload: se derivan, no se insertan, así que no pueden
  -- desincronizarse de lo hasheado (el riesgo de duplicar un valor dentro y fuera).
  org_id uuid generated always as ((payload->>'org_id')::uuid) stored,
  action text generated always as (payload->>'action') stored,

  payload jsonb not null,

  -- FUERA del payload y del hash a propósito: es un dato personal en texto plano. Si el
  -- dueño de la cuenta empresa ejerce su derecho de supresión (Ley 21.719) se anula sin
  -- romper la cadena. La identidad hasheada es payload->>'actor_user_id', un UUID
  -- seudónimo: el mismo criterio que vault_audit_log.
  actor_email text,

  prev_hash text not null unique,
  entry_hash text not null,
  created_at timestamptz not null default now(),

  constraint dashboard_audit_log_action_check check (action in (
    'crear_trabajador',
    'revocar_interna', 'sugerir_externa', 'restaurar_interna', 'restaurar_externa',
    'listar_vault_miembro', 'consultar_vault_miembro', 'consultar_vault_miembro_denegado',
    -- HU21 etapa C: credenciales propias de la organización.
    'crear_credencial_externa', 'reasignar_credencial',
    'guardar_secreto', 'guardar_secreto_fallido',
    'consultar_secreto', 'consultar_secreto_denegado', 'consultar_secreto_asignado'
  ))
);

create index if not exists dashboard_members_org_id_idx
  on dashboard_members(org_id);
create index if not exists dashboard_credentials_org_id_idx
  on dashboard_credentials(org_id);
create index if not exists dashboard_credentials_member_id_idx
  on dashboard_credentials(member_id);
create index if not exists dashboard_credential_secrets_org_id_idx
  on dashboard_credential_secrets(org_id);
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
alter table dashboard_credential_secrets enable row level security;
alter table dashboard_audit_log enable row level security;
