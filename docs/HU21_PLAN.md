# HU21 — Cuentas personal vs. empresa + acceso de la empresa a la bóveda del trabajador

> **Estado**: planificada, **no implementada**. Diseño acordado el 2026-09-16.
> Depende de HU17 (bóveda personal), que sí está implementada.
> Numeración: HU21 porque HU18 ya existe en el backlog (consulta/rotación admin con segundo factor).

---

## 1. Problema

Dos pedidos que resultaron ser el mismo problema de fondo.

**Separar experiencias.** Hoy el popup muestra el botón "Panel de administración"
(`sparkgate-extension/src/components/Navigator.tsx:38-46`) a **todos** los usuarios. Un
empleado ve una puerta que el backend le responde con 403. Hay que separar lo que ve una
cuenta personal de lo que ve una cuenta de empresa.

**Vincular bóveda y gobernanza.** La empresa quiere ver la contraseña real que guardó cada
trabajador, para decidir si la renueva o no.

Ninguno de los dos se resuelve con el flag actual. `is_admin` es un booleano global en
`user_metadata`: no distingue *tipo* de cuenta, no modela que una empresa tenga varias
cuentas de trabajadores vinculadas, y —lo más grave— no aísla nada. `dashboard_members` es
una tabla plana sin dueño, así que **cualquier** `is_admin` ve a **todos** los miembros de
**todas** las empresas. Eso viola la regla R9 (filtro de tenencia) del propio
`SECURITY_AGENT_INSTRUCTIONS.md` del proyecto.

## 2. Decisiones

| Tema | Decisión |
|---|---|
| Tipo de cuenta | `type_account` enum: `personal` \| `enterprise` |
| Dónde vive | Tabla `organizations` (fuente de verdad) + claim en `user_metadata` (gateo rápido) |
| Provisioning | La empresa crea la cuenta del trabajador vía Admin API; queda vinculada al instante |
| Aislamiento | Sí: todas las queries del dashboard filtradas por `org_id` |
| Visibilidad de la bóveda | La empresa ve el valor real descifrado de los ítems del trabajador |
| Segundo factor (TOTP) | **Diferido** a una iteración posterior. Riesgo documentado en §7 |
| Entrega | Dos etapas: A (cuentas) y B (bóveda del trabajador). B depende de A |

## 3. Etapa A — Modelo de cuentas, provisioning y aislamiento

### 3.1 Esquema

`sql/organizations_schema.sql` (nuevo). Mismo criterio que el resto: sin RLS, acceso
exclusivo del backend con `service_role`.

```sql
create table if not exists organizations (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null unique,
  name text not null,
  created_at timestamptz not null default now()
);
```

ALTERs sobre tablas **ya aplicadas y con datos** (van en el mismo archivo):

```sql
alter table dashboard_members    add column if not exists org_id uuid references organizations(id);
alter table dashboard_members    add column if not exists supabase_user_id uuid;
alter table dashboard_audit_log  add column if not exists org_id uuid;
```

`dashboard_members.supabase_user_id` es el puente que la etapa B necesita para saber qué
usuario de Auth corresponde a cada miembro.

**Backfill obligatorio antes de poner `not null`:**

```sql
-- 1. Organización de la demo actual, con el admin sembrado como dueño.
insert into organizations (owner_user_id, name)
select supabase_user_id, 'PYME Demo'
from dashboard_credentials
where type = 'interna' and supabase_user_id is not null
limit 1
on conflict (owner_user_id) do nothing;

-- 2. Todos los miembros y entradas de auditoría existentes quedan en esa organización.
update dashboard_members   set org_id = (select id from organizations limit 1) where org_id is null;
update dashboard_audit_log set org_id = (select id from organizations limit 1) where org_id is null;

-- 3. Puente miembro → usuario auth, desde las credenciales internas que ya lo tienen.
update dashboard_members m
set supabase_user_id = c.supabase_user_id
from dashboard_credentials c
where c.member_id = m.id and c.type = 'interna' and c.supabase_user_id is not null;
```

En `user_metadata` de cada usuario se guardan `type_account` y `org_id`. Es **cache para
gatear sin tocar la base**; la fuente de verdad es la tabla `organizations`.

### 3.2 Backend

| Archivo | Cambio |
|---|---|
| `app/api/dependencies.py` | `verify_token` aplana `type_account` y `org_id` igual que ya aplana `premium` (líneas 22-23). Nuevo `require_enterprise`: exige `type_account == "enterprise"`, **con fallback legacy a `is_admin: True`** para no romper la cuenta ya sembrada. Devuelve el user con `org_id` garantizado |
| `app/schemas/auth.py` | `RegisterRequest` suma `type_account: str = "personal"` (validado con `@field_validator`, igual que el de email en la línea 12) y `organization_name: str \| None` |
| `app/api/routes/auth.py` | `register`: si `type_account == "enterprise"`, tras el `sign_up` crea la fila en `organizations` y actualiza el `user_metadata` con `type_account`/`org_id` vía Admin API |
| `app/services/org_repo.py` | **Nuevo**. `create_organization(owner_user_id, name)`, `get_organization_by_owner(user_id)`, `get_organization(org_id)`. Mismo patrón que `dashboard_repo.py`: funciones sync, `get_supabase_admin()` por llamada, sin try/except |
| `app/services/dashboard_repo.py` | **Todas** las funciones reciben `org_id` y filtran: `list_members_with_credentials(org_id)`, `get_credential(credential_id, org_id)` (valida que la credencial pertenezca a un miembro de esa org), `list_audit_log(org_id)`, `insert_audit_log(..., org_id=...)`. Nuevo `create_member(...)` |
| `app/api/routes/dashboard.py` | Guard pasa a `require_enterprise`; cada llamada al repo recibe `caller["org_id"]`. Nuevo endpoint `POST /members` |
| `app/schemas/dashboard.py` | `CreateMemberRequest` (full_name, email, role_title?), `CreateMemberResponse` (member + `temporary_password`) |
| `scripts/seed_dashboard_demo.py` | Crea la organización demo, setea `type_account`/`org_id` en el `user_metadata` de cada usuario y `org_id`/`supabase_user_id` en cada miembro |

#### `POST /api/v1/dashboard/members` — alta de trabajador

Guard: `require_enterprise`.

1. Genera contraseña temporal con `random_generator.generate(...)` — el mismo servicio que
   ya usa `dashboard.py:25-27`.
2. `auth.admin.create_user({email, password, email_confirm: True, user_metadata: {type_account: "personal", org_id: <org del caller>, premium: False}})`.
3. `dashboard_repo.create_member(org_id=..., supabase_user_id=<nuevo id>, ...)` más la
   credencial `interna` asociada (replica lo que hace el seed en las líneas 106/115/125).
4. Entrada de auditoría con acción `crear_trabajador`.
5. Devuelve la contraseña temporal **una sola vez**, sin persistirla — mismo contrato que ya
   comunica el modal de revoke ("esta contraseña no se guarda en ningún lado",
   `DashboardApp.tsx:554-556`).

### 3.3 Extensión

| Archivo | Cambio |
|---|---|
| `src/utils/jwt.ts` | `getJwtAccountType(jwt)` sobre el `decodeJwtPayload` ya existente: lee `user_metadata.type_account`, con fallback al `is_admin` legacy |
| `src/hooks/useAuth.ts` | Expone `isEnterprise: boolean`, resuelto en `checkAuth()` junto al `exp`. `register` acepta `typeAccount` y `organizationName` |
| `src/components/AuthScreen.tsx` | En el tab de registro, selector "Cuenta personal" / "Cuenta empresa" + campo de nombre de empresa cuando corresponde |
| `src/components/Navigator.tsx` | El bloque del botón "Panel de administración" (38-46) se renderiza **solo con `isEnterprise`**. Las tres tabs (Generar/Detectar/Bóveda) quedan para todos, incluida la cuenta empresa |
| `src/dashboard/DashboardApp.tsx` | Sección "Agregar trabajador": formulario (nombre, email, cargo) → muestra la contraseña temporal una vez, con botón de copiar y el aviso de que no se vuelve a mostrar |
| `src/api/dashboard.ts`, `src/types/dashboard.ts` | `createMember(...)` y sus tipos |

Recordatorio del `CLAUDE.md` de la extensión: `useAuth()` se llama **una sola vez por raíz
de página** (`App.tsx` para el popup, `DashboardApp.tsx` para el panel). `isEnterprise` baja
por props, no por un `useAuth()` extra.

### 3.4 Tests de la etapa A

- `tests/test_org_accounts.py`: registro `enterprise` crea la organización y setea el
  `user_metadata`; registro `personal` no crea organización; `require_enterprise` rechaza
  una cuenta personal con 403 y acepta el `is_admin` legacy.
- `tests/test_dashboard.py` (existente): las llamadas al repo pasan a verificar que reciben
  el `org_id` del caller. **Test de aislamiento nuevo**: una credencial de otra organización
  responde 404, no 200.
- `tests/test_dashboard_members.py`: el alta crea usuario + miembro + credencial, devuelve la
  contraseña temporal y **no la escribe en la auditoría** (bucle de aserción negativa, igual
  que `test_dashboard.py:172`).
- Extensión: `Navigator` no renderiza el botón del panel sin `isEnterprise`.

## 4. Etapa B — La empresa ve y rota la bóveda del trabajador

### 4.1 Esquema

`sql/vault_schema.sql` — **conviene editarlo antes de aplicarlo**, así no hace falta
migración:

- `vault_audit_log` suma `actor_user_id uuid` (null = el propio dueño; no-null = quién de la
  empresa consultó).
- Acciones nuevas en el `check`: `consultar_admin`, `consultar_admin_denegado`.

> Si el esquema ya fue aplicado: `alter table vault_audit_log add column actor_user_id uuid;`
> más recrear el `check` de `action`. **Ojo**: eso cambia el key set del payload, así que las
> entradas anteriores dejan de cuadrar en `verify_chain`. Con la tabla vacía no hay nada que
> romper.

`dashboard_audit_log` (ya aplicada, con datos): `credential_id` y `credential_type` pasan a
nullable y suma `vault_item_id uuid` — un evento de bóveda no tiene credencial de gobernanza
asociada.

### 4.2 Backend

| Archivo | Cambio |
|---|---|
| `app/services/vault_repo.py` | `insert_audit(...)` suma `actor_user_id: str \| None = None`, **siempre presente en el payload**. La regla del key set fijo ya está comentada en el archivo: si un kwarg falta, `verify_chain` deja de cuadrar |
| `app/api/routes/dashboard.py` | Los dos endpoints de abajo |

| Método | Ruta | Comportamiento |
|---|---|---|
| GET | `/members/{member_id}/vault` | Valida que el miembro sea de la organización del caller. Sin `supabase_user_id` → 200 con `[]` (contratista sin cuenta SparkGate, como Diego Ríos en el seed). Devuelve metadata, **no descifra** |
| POST | `/members/{member_id}/vault/{item_id}/reveal` | Descifra y devuelve el secreto. **POST y no GET a propósito**: escribe auditoría, no debe quedar en el historial del navegador ni ser precargable por el browser |

Flujo de `reveal`:

1. `require_enterprise`.
2. `vault_crypto.is_available()` → si no, 503 (el mismo `ServiceUnavailableError` de HU17 AC5).
3. El miembro pertenece a mi organización → si no, 404.
4. `owner_id = member["supabase_user_id"]` → si es `None`, 404.
5. `vault_repo.get_item(item_id, owner_id)` → si es `None`, auditoría
   `consultar_admin_denegado` + 404 (mismo criterio anti-enumeración que el vault personal:
   inexistente y ajeno responden igual).
6. `vault_crypto.decrypt_secret(item, aad=owner_id)`.
7. Doble auditoría (§4.3).
8. `logger.info` con `item_id`/`member_id`, **nunca** el secreto.

> **El punto sutil de toda la HU**: el AAD del descifrado sigue siendo el `user_id` del
> **dueño**, no el del caller. El AAD identifica *de quién es* el dato, no *quién pregunta*.
> Por eso el acceso de la empresa funciona **sin tocar `vault_crypto.py`** y sin debilitar el
> cifrado: mover una fila a otro `user_id` sigue rompiendo el tag GCM.

### 4.3 Doble auditoría

Cada `reveal` escribe en los dos registros:

| Registro | Entrada | Para quién |
|---|---|---|
| `vault_audit_log` | `action="consultar_admin"`, `user_id=<dueño>`, `actor_user_id=<caller>` | **El trabajador**, en su propio `GET /api/v1/vault/audit` |
| `dashboard_audit_log` | `action="consultar_vault_miembro"`, `vault_item_id`, `org_id` | La empresa, en el panel y en el CSV exportable |

La primera es deliberada: es la mitigación de privacidad. El trabajador puede ver quién y
cuándo abrió sus credenciales. Es un adelanto parcial de HU20 (notificación al integrante).

### 4.4 Extensión

`DashboardApp.tsx`: por cada miembro, un bloque "Bóveda personal" bajo sus credenciales, con
lazy-load al expandir. Cada ítem con botón "Ver contraseña" → modal con el valor, botón de
copiar y un aviso fijo: es dato personal del trabajador y **la consulta queda registrada en
la auditoría que él mismo ve**. `ACTION_LABEL` (líneas 24-29) suma las acciones nuevas.

`SPEC.md` de la extensión: V9 y V13 corregidas (el secreto ya no es solo del dueño), V15
(panel solo para cuentas `enterprise`), V16 (toda lectura de bóveda ajena queda en los dos
logs), V17 (aislamiento por `org_id`), más las interfaces y tareas nuevas.

### 4.5 Tests de la etapa B

`tests/test_dashboard_vault.py`, con el patrón de `test_dashboard.py` (`override_auth` sobre
`verify_token` para que el guard corra de verdad, `monkeypatch.setattr` sobre los módulos de
servicio, sin `respx`):

- Cuenta personal → 403 en ambos endpoints.
- Miembro de otra organización → 404.
- Miembro sin `supabase_user_id` → `[]` en el listado, 404 en `reveal`.
- `reveal` feliz: devuelve el plaintext y **el `aad` que recibió `decrypt_secret` es el del
  dueño**, no el del caller (aserción explícita sobre el argumento capturado).
- `reveal` escribe **las dos** entradas, con el `actor_user_id` correcto.
- Ningún payload de auditoría contiene `password` ni `notes`.
- `reveal` sin KEK → 503 y `get_item` **no** fue llamado.

`tests/test_audit_chain.py`: una cadena con entradas mixtas (con y sin `actor_user_id`) sigue
verificando en `True`.

## 5. Documentación a actualizar

- `docs/ARQUITECTURA.md`: `organizations` y `org_id` en el diagrama ER; la fila del
  invariante "el secreto nunca sale en claro salvo al dueño" pasa a "al dueño, o a su empresa
  con doble registro de auditoría"; fila nueva de aislamiento por organización; endpoints en §9.
- `docs/PRUEBAS.md`: filas HU21 (etapas A y B) en la matriz de trazabilidad.
- `README.md` y `CLAUDE.md`: endpoints nuevos, modelo de cuentas, y el punto del AAD del dueño.
- Bóveda Obsidian, dos ADRs: modelo de cuentas (por qué tabla + claim, por qué la empresa
  provisiona) y acceso a la bóveda del trabajador (por qué se invierte el AC3 de HU17, riesgo
  aceptado, mitigaciones).

## 6. Verificación

**Etapa A**

1. Aplicar `sql/organizations_schema.sql` con sus backfills. Correr `python scripts/seed_dashboard_demo.py`.
2. `pytest --cov=. -k "not ollama and not performance"` verde (CI exige ≥70%). `pnpm test` y `pnpm run build` en la extensión.
3. Registrar una cuenta **empresa** → el popup muestra el botón del panel. Registrar una
   **personal** → no lo muestra.
4. Desde la empresa nueva, agregar un trabajador → devuelve contraseña temporal; loguearse
   con ella funciona.
5. **Aislamiento**: el panel de la empresa nueva muestra solo a su trabajador, no a los del
   seed. Intentar revocar por ID una credencial de la otra organización → 404.

**Etapa B**

6. Aplicar `sql/vault_schema.sql` corregido y los ALTERs de `dashboard_schema.sql`.
7. Como trabajador: guardar dos credenciales en la Bóveda.
8. Como su empresa: expandir al trabajador → aparecen los dos ítems; "Ver contraseña"
   coincide con lo guardado.
9. `select * from dashboard_audit_log order by created_at desc limit 1` → acción
   `consultar_vault_miembro` con `vault_item_id` y `org_id`.
10. Volver como el trabajador → `GET /api/v1/vault/audit` muestra `consultar_admin` con el
    `actor_user_id` de la empresa. **Si esto no aparece, la mitigación no está cumplida.**
11. `select * from vault_audit_log order by seq` → cadena continua; `verify_chain` en `True`
    con entradas mixtas.
12. Con `VAULT_MASTER_KEY` comentada: `reveal` → 503; el listado de metadata **sigue
    funcionando**.

## 7. Riesgos aceptados

Se dejan escritos porque son decisiones tomadas a conciencia, no descuidos.

**R-HU21-1 — Sin segundo factor.** El informe exige TOTP para que un administrador acceda a
la credencial de un tercero (CU08, RNF1: "ninguna credencial de terceros sin 2FO"). Se
difiere. Mientras tanto, una cuenta de empresa comprometida lee **todas** las credenciales de
sus trabajadores con solo presentar su JWT, sin fricción adicional. Mitigación parcial: el
doble registro de auditoría deja rastro de cada lectura, y el trabajador lo ve.

**R-HU21-2 — Se expone la bóveda personal, no una bóveda laboral.** El trabajador guarda en
su bóveda lo que quiere, incluidas cuentas privadas sin relación con su trabajo. La empresa
las ve todas. Bajo la Ley 21.719 esto tensiona el principio de minimización de datos. La
alternativa evaluada y descartada fue un store separado de "credenciales de empresa", que
habría dejado lo personal fuera del alcance del empleador. Mitigación incluida: el trabajador
ve cada acceso en su propia auditoría. Mitigación pendiente, si se quisiera cerrar del todo:
marcar los ítems como laborales o personales y exponer solo los primeros.

**R-HU21-3 — `type_account` en `user_metadata` es cache.** Si la tabla `organizations` y el
claim se desincronizan, el gateo del guard puede quedar desactualizado hasta que el usuario
renueve el token. La fuente de verdad es la tabla; cualquier operación sensible debe
resolver contra ella, no contra el claim.
