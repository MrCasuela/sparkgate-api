-- HU18: segundo factor TOTP (RFC 6238) para toda lectura o rotación de un secreto ajeno.
--
-- ADITIVO: no recrea ninguna tabla, así que no hace falta scripts/reset_hu21_schema.py.
-- Las dos cadenas de auditoría sobreviven: dashboard_audit_log hashea la columna `payload`
-- y vault_audit_log hashea el conjunto de COLUMNAS, y acá solo se cambian CHECKs, no
-- columnas (ver _Leccion-cadena-hash-vs-evolucion-de-esquema).
--
-- Aplicar con: python scripts/apply_mfa_schema.py
-- Idempotente. Para un entorno NUEVO los mismos CHECKs ya están en línea en
-- dashboard_schema.sql y vault_schema.sql; este archivo existe para el entorno ya aplicado.

create table if not exists user_totp_factors (
  -- Un factor por persona. Sin multi-dispositivo en esta iteración: dos filas por usuario
  -- obligarían a decidir cuál gana el anti-replay, y no hay caso de uso.
  -- Sin FK a auth.users a propósito: vive en otro schema y ninguna tabla del proyecto la
  -- referencia (dashboard_members.supabase_user_id tampoco).
  user_id uuid primary key,

  -- Sobre AES-256-GCM de vault_crypto ENTERO en una columna jsonb, no en columnas sueltas:
  -- así ningún módulo fuera de vault_crypto vuelve a nombrar `ciphertext` ni `wrapped_dek`
  -- y el test hermético de tests/test_secret_access.py sigue valiendo tal cual está.
  -- Cifrado con TOTP_MASTER_KEY (no con la KEK de la bóveda) y AAD = este mismo user_id.
  secret_envelope jsonb not null,

  created_at timestamptz not null default now(),
  -- NULL = enrolamiento a medias. NO habilita nada: verify() exige confirmed_at not null.
  -- Si contara como enrolado, abandonar el enrolamiento dejaría a la persona fuera de todo
  -- secreto sin forma de volver a entrar.
  confirmed_at timestamptz,

  -- Anti-replay (RFC 6238 §5.2): contador de 30 s del último código ACEPTADO. Un código del
  -- mismo paso o de uno anterior se rechaza aunque siga vigente.
  last_time_step bigint,
  last_used_at timestamptz,

  -- Freno de fuerza bruta: 6 dígitos son 10^6 y la ventana ±1 acepta 3 pasos, así que una
  -- sesión con JWT válido tendría 3/10^6 por intento y tiempo infinito.
  failed_attempts int not null default 0,
  locked_until timestamptz,

  updated_at timestamptz not null default now()
);

-- Deny-all, igual que las otras seis tablas: la clave anon es pública y PostgREST expone
-- `public`; sin esto cualquiera leería el sobre del factor de todo el mundo. service_role
-- (el backend) ignora RLS.
alter table user_totp_factors enable row level security;

-- --------------------------------------------------------------------------
-- Acciones nuevas. DROP + ADD porque un CHECK no se "extiende" en el lugar. El ADD valida
-- contra las filas existentes: todas llevan acciones de la lista vieja, que es subconjunto
-- de la nueva, así que pasa.
-- --------------------------------------------------------------------------

alter table dashboard_audit_log drop constraint if exists dashboard_audit_log_action_check;
alter table dashboard_audit_log add constraint dashboard_audit_log_action_check check (action in (
  'crear_trabajador',
  'revocar_interna', 'sugerir_externa', 'restaurar_interna', 'restaurar_externa',
  'listar_vault_miembro', 'consultar_vault_miembro', 'consultar_vault_miembro_denegado',
  'crear_credencial_externa', 'reasignar_credencial',
  'guardar_secreto', 'guardar_secreto_fallido',
  'consultar_secreto', 'consultar_secreto_denegado', 'consultar_secreto_asignado',
  'revocar_interna_denegado', 'sugerir_externa_denegado', 'guardar_secreto_denegado'
));

-- El CHECK de vault_audit_log es en línea sobre la columna, así que Postgres lo nombró
-- <tabla>_<columna>_check. Verificarlo con \d+ vault_audit_log si el DROP no encuentra nada.
alter table vault_audit_log drop constraint if exists vault_audit_log_action_check;
alter table vault_audit_log add constraint vault_audit_log_action_check check (action in (
  'guardar', 'listar', 'consultar', 'consultar_denegado',
  'eliminar', 'eliminar_denegado', 'eliminar_todo', 'eliminar_cuenta',
  'listar_admin', 'consultar_admin', 'consultar_admin_denegado',
  'consultar_credencial_interna_admin',
  'mfa_enrolar', 'mfa_activar', 'mfa_desactivar', 'mfa_denegado'
));
