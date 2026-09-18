# Arquitectura de SparkGate API

> Documento vivo de arquitectura del backend. Refleja el estado actual del código
> en `app/`. Cualquier cambio de capas, contratos o modelo de datos debe reflejarse
> aquí (ver `AGENTS.md`).

SparkGate API es el backend REST que alimenta a la extensión de Chrome SparkGate.
Genera y evalúa contraseñas combinando tres dimensiones — complejidad matemática
(entropía), análisis semántico (LLM) y filtraciones conocidas (HIBP) — y expone un
panel de offboarding (SP-1) para que una PYME administre las credenciales de su
personal.

## 1. Visión general y stack

| Componente | Tecnología | Rol |
|------------|------------|-----|
| Lenguaje | Python 3.12+ | Runtime |
| Framework | FastAPI + Uvicorn | API REST, routers, OpenAPI en `/docs` |
| Validación | Pydantic v2 (`pydantic-settings`) | Schemas request/response + configuración |
| HTTP async | `httpx` | Clientes a Ollama, OpenRouter y HIBP |
| Auth + BD | Supabase (`supabase` py client) | Auth gestionada (`auth.users`) + PostgreSQL para el dashboard |
| LLM local | Llama 3.2 3B vía Ollama | Análisis/generación semántica (`AI_BACKEND=ollama`) |
| LLM cloud | OpenRouter API (`meta-llama/llama-3.1-8b-instruct`) | Alternativa al local (`AI_BACKEND=openrouter`) |
| Filtraciones | HIBP `api.pwnedpasswords.com` | Verificación k-anonymity |

El backend se configura por variables de entorno vía `.env` → `app/core/config.py`
(singleton `settings`). Ejemplo en `.env.example`.

## 2. Diagrama de contexto

```mermaid
flowchart LR
    U[Usuario] -->|usa| EXT[Extensión Chrome<br/>repo separado]
    EXT -->|HTTPS /api/v1/*| API[SparkGate API<br/>FastAPI en Vercel]
    API -->|Auth: sign_up / sign_in / sign_out| SA[Supabase Auth<br/>auth.users]
    API -->|CRUD service_role| PGB[(Supabase PostgreSQL<br/>dashboard_*)]
    API -->|/api/generate o chat/completions| LLM{Ollama local o OpenRouter}
    API -->|/range/{sha1-prefix} k-anonymity| HIBP[Have I Been Pwned]
```

## 3. Arquitectura por capas

Regla de dependencia **obligatoria**: las rutas (`api/routes/`) coordinan y llaman a
los servicios (`services/`); los servicios nunca importan rutas. `core/` (config +
excepciones) y `schemas/` son transversales y no dependen de capas superiores.

```mermaid
flowchart TB
    subgraph coord[api/  — coordinación + guardas de auth]
        DEP[api/dependencies.py<br/>verify_token / require_premium / require_enterprise]
        ROUTES[api/routes/*  — auth, passwords, dashboard, health]
    end

    subgraph serv[services/  — todo el I/O]
        AI[ai_engine.py]
        HIBP[hibp_client.py]
        ENT[entropy.py]
        RG[random_generator.py]
        REPO[dashboard_repo.py]
        DBC[db_client.py]
    end

    subgraph ext[Servicios externos]
        SUP[(Supabase)]
        OL[(Ollama)]
        GR[(OpenRouter)]
        HB[(HIBP)]
    end

    subgraph base[Transversal]
        CORE[core/config.py + core/exceptions.py]
        SCH[schemas/*.py]
        MAIN[main.py — ensambla app]
    end

    ROUTES --> DEP
    ROUTES --> serv
    DEP --> DBC
    AI --> OL
    AI --> GR
    HIBP --> HB
    DBC --> SUP
    REPO --> DBC
    REPO --> RG
    ENT -.usada por rutas y ai_engine.-> ROUTES

    MAIN --> ROUTES
    CORE -.importado por servicios y rutas.-> serv
    SCH -.response_model / bodies.-> ROUTES
```

`app/main.py` es la composición raíz: registra los 4 routers, configura CORS (los
orígenes pueden incluir wildcards `chrome-extension://*` → se traducen a regex) y
conecta los handlers de `core/exceptions.py`.

## 4. Diagrama de componentes

```mermaid
flowchart TB
    subgraph app[app/]
        subgraph routes[api/routes]
            R1[auth.py<br/>/api/v1/auth]
            R2[passwords.py<br/>/api/v1/passwords]
            R3[dashboard.py<br/>/api/v1/dashboard]
            R4[health.py<br/>/api/v1/health]
        end
        subgraph services[services]
            S1[ai_engine]
            S2[hibp_client]
            S3[entropy]
            S4[random_generator]
            S5[dashboard_repo]
            S6[db_client<br/>anon + service_role]
            S7[cache<br/>TTL in-memory]
        end
        subgraph schemas[schemas]
            SC1[auth / common / passwords / dashboard]
        end
        subgraph core[core]
            C1[config.py<br/>Settings]
            C2[exceptions.py<br/>502 / 503 handlers]
        end
        MAIN[main.py]
    end

    MAIN --> routes
    R2 --> S1
    R2 --> S2
    R2 --> S3
    R2 --> S4
    R2 --> S7
    S2 --> S7
    R3 --> S5
    R3 --> S4
    R3 --> S6
    R1 --> S6
    R4 --> S6
    routes --> schemas
    routes --> core
    services --> core
    services --> schemas
```

### 4.1 Mapa módulo → responsabilidad

| Módulo | Archivo | Responsabilidad |
|--------|---------|-----------------|
| `main` | `app/main.py` | Instancia FastAPI, CORS, routers, handlers de excepción |
| Dependencias | `app/api/dependencies.py` | `verify_token` (JWT→dict o `None`), `require_premium`, `require_enterprise` |
| Auth | `app/api/routes/auth.py` | Proxy a Supabase Auth: register / login / logout |
| Passwords | `app/api/routes/passwords.py` | Evaluar (3 dimensiones) y generar (AI/random) |
| Dashboard | `app/api/routes/dashboard.py` | Offboarding SP-1: members, audit-log, revoke/suggest/restore |
| Vault | `app/api/routes/vault.py` | HU17: guardar/listar/consultar/eliminar credencial propia cifrada |
| Health | `app/api/routes/health.py` | Estado de Ollama (raíz) + sesión Supabase |
| `ai_engine` | `app/services/ai_engine.py` | Prompts + llamada LLM + parseo JSON (Ollama/OpenRouter) |
| `hibp_client` | `app/services/hibp_client.py` | SHA-1 truncado + consulta `/range/{prefix}` (caché por prefijo, TTL 24h) |
| `cache` | `app/services/cache.py` | `TTLCache` thread-safe sin dependencias; caches evaluate (TTL 1h) y HIBP |
| `entropy` | `app/services/entropy.py` | `H = L × log₂(R)`, umbral 60 bits |
| `random_generator` | `app/services/random_generator.py` | Generación criptográfica (`secrets`) |
| `dashboard_repo` | `app/services/dashboard_repo.py` | CRUD sobre tablas del dashboard |
| `vault_repo` | `app/services/vault_repo.py` | CRUD sobre `vault_items` / `vault_audit_log`, siempre filtrado por `user_id` |
| `vault_crypto` | `app/services/vault_crypto.py` | Envelope encryption AES-256-GCM (DEK por ítem, KEK en `.env`), AAD=`user_id` |
| `audit_chain` | `app/services/audit_chain.py` | Registro encadenado por hash SHA-256 (base de HU19) |
| `db_client` | `app/services/db_client.py` | Clientes Supabase perezosos: anon y service_role |
| Config | `app/core/config.py` | `Settings` desde `.env` |
| Excepciones | `app/core/exceptions.py` | Tipos 502/503 + handlers JSON |

### 4.2 Contrato de error

Todas las respuestas de error usan `{"detail": string}` (compatible con el esquema
`ErrorResponse` en `app/schemas/common.py`). Códigos usados en rutas: `400` (bad
request / credencial ya revocada / confirmación de correo incorrecta al borrar
cuenta), `401` (sin token, inválido, o contraseña incorrecta al re-autenticar),
`403` (premium / admin requeridos), `404` (credencial inexistente o ajena),
`409` (email ya registrado), `502` (servicio AI fuera de servicio / entropía
insuficiente tras reintentos / falla al borrar el usuario tras purgar sus
datos), `503` (módulo Vault sin clave maestra configurada, HU17 AC5).

## 5. Modelo de datos

La base vive en Supabase (PostgreSQL). Se distinguen dos zonas:

- **`auth.users`** — gestionada por Supabase Auth. SparkGate no la lee ni escribe
  directo: la manipula vía API (`sign_up`, `sign_in_with_password`,
  `auth.admin.update_user_by_id`, `auth.admin.sign_out`). Los flags de negocio se
  guardan en `raw_user_meta_data` → `premium`, `type_account` y `org_id`. Los dos
  últimos son **cache de gateo**: la fuente de verdad de la organización es la tabla
  `organizations` (ver §7).
- **Tablas `organizations` y `dashboard_*`** — creadas por `sql/dashboard_schema.sql`,
  accesibles solo desde el backend con la clave `service_role` (sin RLS; el gateo es
  aplicación-side con `require_enterprise`, y el aislamiento entre empresas es un
  `.eq("org_id", ...)` en cada consulta de `dashboard_repo.py`).
- **Tablas `vault_*`** — creadas por `sql/vault_schema.sql`, mismo modelo de acceso
  (`service_role`, sin RLS), pero gateado por `require_user` y un `.eq("user_id", ...)`
  aplicado en cada consulta de `vault_repo.py`, no por rol.

```mermaid
erDiagram
    auth_users ||..o| organizations : "owner_user_id (lógica, sin FK)"
    organizations ||--o{ dashboard_members : "org_id FK"
    auth_users ||..o| dashboard_credentials : "supabase_user_id (lógica, sin FK)"
    auth_users ||..o| dashboard_members : "supabase_user_id (lógica, sin FK)"
    dashboard_members ||--o{ dashboard_credentials : "member_id FK, on delete cascade"
    dashboard_members ||..o{ dashboard_audit_log : "member_id (lógica, sin FK)"
    dashboard_credentials ||..o{ dashboard_audit_log : "credential_id (lógica, sin FK)"

    auth_users {
        uuid id PK "Supabase Auth"
        text email
        jsonb raw_user_meta_data "premium, type_account, org_id"
        text encrypted_password
    }

    organizations {
        uuid id PK "gen_random_uuid()"
        uuid owner_user_id UK "la cuenta empresa dueña"
        text name "not null"
        timestamptz created_at "default now()"
    }

    dashboard_members {
        uuid id PK "gen_random_uuid()"
        uuid org_id FK "not null, aislamiento"
        text full_name "not null"
        text email "not null"
        text role_title "nullable"
        uuid supabase_user_id "puente con su cuenta SparkGate, nullable"
        timestamptz created_at "default now()"
    }

    dashboard_credentials {
        uuid id PK "gen_random_uuid()"
        uuid member_id FK "on delete cascade"
        text type "check in (interna, externa)"
        text service_name "not null"
        uuid supabase_user_id "solo interna"
        text status "activa | revocada | pendiente_aplicacion_manual"
        timestamptz updated_at "default now()"
    }

    dashboard_audit_log {
        uuid id PK "gen_random_uuid()"
        uuid org_id "not null, aislamiento"
        text actor_email "quien ejecuta"
        uuid member_id
        uuid credential_id "nullable: los eventos de bóveda no tienen"
        text credential_type "nullable"
        uuid vault_item_id "solo eventos de bóveda"
        text action
        timestamptz created_at "default now()"
    }

    auth_users ||..o{ vault_items : "user_id (lógica, sin FK)"
    auth_users ||..o{ vault_audit_log : "user_id (lógica, sin FK)"

    vault_items {
        uuid id PK "gen_random_uuid()"
        uuid user_id "dueño, sin FK a auth.users"
        text service_name "not null"
        text username "nullable"
        text ciphertext "AES-256-GCM, base64"
        text nonce "base64"
        text wrapped_dek "DEK envuelta con la KEK, base64"
        text dek_nonce "base64"
        int kek_version "default 1"
        timestamptz created_at "default now()"
        timestamptz updated_at "default now()"
    }

    vault_audit_log {
        bigserial seq "orden de la cadena"
        uuid id PK "gen_random_uuid()"
        uuid user_id "seudónimo tras borrar la cuenta"
        uuid item_id "nullable"
        text action "guardar|listar|consultar|consultar_denegado|eliminar|eliminar_denegado|eliminar_todo|eliminar_cuenta|listar_admin|consultar_admin|consultar_admin_denegado"
        text result "ok|denegado|error"
        int deleted_count "solo eliminar_todo/eliminar_cuenta"
        uuid actor_user_id "null = el dueño; si no, quién consultó (HU21)"
        text prev_hash UK "hash de la entrada anterior"
        text entry_hash "sha256(prev_hash + payload)"
        timestamptz created_at "default now()"
    }
```

**Observaciones de diseño** (decisiones explícitas, no omisiones):

- Las credenciales *internas* referencian a `auth.users` mediante `supabase_user_id`.
  No hay FK real porque `auth.users` pertenece al esquema `auth` de Supabase.
- Desde HU21 la correspondencia miembro ↔ usuario auth es explícita:
  `dashboard_members.supabase_user_id`. Es el puente que la empresa usa para abrir
  la bóveda del trabajador, y lo único que se anula (sin borrar la fila) cuando el
  integrante ejerce su derecho de supresión. Sigue sin haber FK real a `auth.users`,
  que pertenece a otro esquema.
- `dashboard_audit_log` **nunca** almacena contraseñas (AC4): guarda actor, miembro,
  credencial y acción, no valores.
- Índices: `dashboard_members(org_id)`, `dashboard_credentials(member_id)`,
  `dashboard_audit_log(org_id)` y `dashboard_audit_log(created_at desc)`.
- Sin RLS: acceso exclusivo vía `service_role` (cliente `get_supabase_admin()`),
  nunca expuesto a callers no-admin.
- `vault_items` nunca guarda el secreto en claro: solo el sobre cifrado
  (`ciphertext`/`nonce`/`wrapped_dek`/`dek_nonce`). El AAD del cifrado es el
  `user_id`, así que mover una fila a otro dueño rompe el tag GCM aunque se
  conozca la KEK (HU17 AC2/AC3).
- `vault_audit_log` es una cadena hash (HU19): cada `entry_hash` cubre
  `prev_hash` + el payload. El payload es **seudónimo a propósito** (solo
  UUIDs y enums, nunca `service_name` ni secretos) para que borrar una cuenta
  (Ley 21.719) nunca obligue a romper la cadena — el `user_id` simplemente
  deja de mapear a una persona real. `prev_hash` es `unique`: dos escrituras
  concurrentes sobre la misma cola fallan la segunda en vez de bifurcar la
  cadena en silencio.
- Índices: `vault_items(user_id)` y `vault_audit_log(user_id)`.

## 6. Flujos clave

### 6.1 Evaluar contraseña — `POST /api/v1/passwords/evaluate`

```mermaid
sequenceDiagram
    participant U as Usuario
    participant E as Extensión Chrome
    participant R as passwords.py
    participant H as hibp_client
    participant A as ai_engine
    participant LLM as Ollama/OpenRouter

    U->>E: ingresa contraseña
    E->>R: POST /passwords/evaluate (Bearer)
    Note over R: verify_token → dict | None
    R->>R: entropy = L × log₂(R) (local)
    R->>H: check_password(pwd)
    H-->>R: (is_compromised, pwned_count)
    Note over R: HIBP falla → warn y continúa
    R->>A: evaluate_security(pwd, is_pwned)
    A->>LLM: prompt system estricto (JSON)
    LLM-->>A: JSON raw
    A-->>R: ai_score / feedback / suggestions
    Note over R: parse inválido → fallback por entropía
    R-->>E: 200 (entropy + HIBP + AI)
    Note over R: AI no responde → 502
```

Tolerancia a fallos: la dimensión de entropía siempre se entrega; HIBP caído se
degrada a "no comprometida" con log; IA caída responde `502` informando que el
análisis matemático sí se completó.

### 6.2 Generar contraseña — `POST /api/v1/passwords/generate`

```mermaid
sequenceDiagram
    participant U as Usuario
    participant R as passwords.py
    participant A as ai_engine
    participant LLM as Ollama/OpenRouter
    participant S as random_generator

    U->>R: POST /passwords/generate
    alt mode = random
        R->>S: generate(length, charset toggles)
        S-->>R: password (secrets)
    else mode = ai (default)
        loop hasta 3 intentos
            R->>A: generate_password(params)
            A->>LLM: prompt con style/word_count/theme/personal_words
            LLM-->>A: JSON
            A-->>R: password + explanation
            Note over R: entropía ≥ 60 bits? sí → break
        end
        Note over R: tras 3 intentos <60 → 502
    end
    R-->>U: 200 (password + entropy_bits + explanation)
```

### 6.3 Offboarding — revocar credencial interna (SP-1)

```mermaid
sequenceDiagram
    participant Admin as Admin (extensión/dashboard)
    participant R as dashboard.py
    participant G as get_supabase_admin
    participant DB as dashboard_repo
    participant AU as Supabase Admin API

    Admin->>R: POST /dashboard/credentials/{id}/revoke
    Note over R: require_enterprise → type_account (claim) + organizations (tabla)
    R->>DB: get_credential(id)
    Note over R: guardas: existe / tipo interna / no es tu propia cuenta / no ya revocada
    R->>R: _resolve_password → random 16 o override new_password
    R->>G: auth.admin.update_user_by_id(id, password + ban_duration=87600h)
    Note over R: bloquea logins/refrescos futuros (token vivo expira, AC6)
    R->>DB: update_credential_status(revocada)
    R->>DB: insert_audit_log(revocar_interna)
    Note over R: password NUNCA al audit_log (AC4)
    R-->>Admin: 200 (credential + admin_api_success)
```

Variantes: **suggest** solo aplica a credenciales *externas* (estado →
`pendiente_aplicacion_manual`); **restore** desbanea (`ban_duration: "none"`) y
vuelve a `activa` en interna o externa.

### 6.4 Sesión — registro / login / logout

```mermaid
sequenceDiagram
    participant U as Usuario
    participant R as auth.py
    participant SA as Supabase Auth

    U->>R: POST /auth/register
    R->>SA: sign_up(data: premium=false, plan=Gratuito)
    SA-->>R: user (+session opcional)
    R-->>U: user_id + access_token

    U->>R: POST /auth/login
    R->>SA: sign_in_with_password
    SA-->>R: session + metadata
    R-->>U: access_token + premium

    U->>R: POST /auth/logout (Bearer propio)
    R->>SA: auth.admin.sign_out(jwt, scope=global)
    SA-->>R: ok
    R-->>U: 200 {"message": "Logged out"}
```

Logout revoca la sesión del **propio** token presentado (scope global). No es
posible revocar la sesión de otro usuario desde aquí: el offboarding de quien se va
se hace por el panel (ban + rotación de contraseña).

## 7. Invariantes de seguridad (aplicados en código)

| Invariante | Dónde | Evidencia |
|------------|-------|-----------|
| HIBP nunca recibe la contraseña | `hibp_client.py` | SHA-1 local; solo prefijo de 5 hex a `/range/{prefix}` |
| Cabecera anti-seguimiento HIBP | `hibp_client.py` | `Add-Padding: true` |
| Contraseñas ≥ 60 bits de entropía | `entropy.py`, `passwords.py` | Umbral `MIN_ENTROPY_BITS = 60`; AI reintenta hasta 3× |
| Generación criptográfica | `random_generator.py` | `secrets` + `SystemRandom().shuffle` |
| LLM responde JSON estructurado | `ai_engine.py` | `format: "json"` (Ollama) / `response_format` (OpenRouter) |
| Parse defensivo de IA | `ai_engine.py` | cadena directo → regex → reparo → fallback entropía |
| Tokens de servicio nunca al cliente | `db_client.py`, `dependencies.py` | `get_supabase_admin()` solo en paths admin |
| Guardas de offboarding | `dashboard.py` | no revocar propia cuenta admin; solo interna |
| Sin contraseñas en el audit log | `dashboard.py`, `dashboard_repo.py` | AC4 — solo actor/acción |
| CORS por orígenes exactos + regex | `main.py` | wildcards traducidos a regex |
| Envelope encryption (DEK/KEK) | `vault_crypto.py` | AES-256-GCM, KEK en `.env`, nunca en DB ni logs (HU17 AC2) |
| Ciphertext ligado al dueño | `vault_crypto.py` | AAD=`user_id` del **dueño** (no del caller); `InvalidTag` si se descifra bajo otro dueño |
| Fallo de integridad visible, no silencioso | `vault.py`, `dashboard.py` | `InvalidTag` → 503 + auditoría `result="error"`; nunca 404 (escondería la adulteración) ni 500 |
| Aislamiento entre organizaciones | `dashboard_repo.py`, `dependencies.py` | `.eq("org_id", ...)` en cada consulta; el `org_id` lo resuelve `require_enterprise` contra la tabla `organizations`, nunca desde el claim del token (HU21 AC3) |
| El claim de tenencia solo puede negar | `dependencies.py` | `user_metadata.org_id` se aplana como `claimed_org_id`; la clave `org_id` que leen los handlers la escribe únicamente el guard tras consultar la tabla |
| Recurso de otra organización → 404 | `dashboard.py` | integrante y credencial ajenos responden igual que los inexistentes, nunca 403 |
| Toda lectura de bóveda ajena queda doblemente registrada | `dashboard.py` | `vault_audit_log` con `actor_user_id` (lo ve **el trabajador**) + `dashboard_audit_log` (lo ve la empresa) — HU21 AC7 |
| Vault rechaza sin KEK, sin persistir en claro | `vault.py` | `is_available()` chequeado antes de cualquier escritura (AC5) |
| Ownership explícito, sin RLS | `vault_repo.py` | `.eq("user_id", ...)` en cada lectura/borrado del vault |
| Enumeración de IDs ajenos evitada | `vault.py` | ítem inexistente y ajeno responden ambos 404, nunca 403 |
| Auditoría del vault sin secretos ni service_name | `vault.py`, `audit_chain.py` | payload seudónimo: solo UUIDs y enums (AC4, HU19) |
| Cadena de auditoría detecta alteración | `audit_chain.py` | `entry_hash = sha256(prev_hash + payload)`, `verify_chain` recalcula todo |
| Borrado nunca depende de la KEK | `vault.py` | DELETE de ítem/purga funciona con `is_available() == False` (Ley 21.719) |
| Borrado de cuenta con doble confirmación | `auth.py` | correo exacto (400) + contraseña re-autenticada (401) antes de borrar nada |
| Borrado de cuenta no deja datos huérfanos | `auth.py` | orden: purgar vault → registrar auditoría → desasociar dashboard → `delete_user` al final |

## 8. Vista de despliegue

```mermaid
flowchart LR
    GIT[(GitHub)] -->|push develop/main<br/>integración nativa| VER[Vercel<br/>serverless @vercel/python]
    GIT -->|Actions: test + coverage| CI[GitHub Actions<br/>ci-cd.yml]
    EXT[Extensión Chrome] -->|HTTPS| VER
    VER -->|HTTPS| SA[Supabase gestionado<br/>Auth + PostgreSQL]
    VER -->|HTTPS k-anonymity| HIBP[HIBP]
    VER -->|HTTPS| OR[OpenRouter API<br/>AI_BACKEND=openrouter]
```

- Arranque local: `./start.sh` (venv → deps → chequeo Ollama → uvicorn `:8000`);
  `./stop.sh` lo detiene. Doc interactivo en `http://localhost:8000/docs`.
- Config de despliegue Vercel en `vercel.json` (`@vercel/python`, fuerza
  `AI_BACKEND=openrouter` vía `env` — serverless no puede correr Ollama local).
  Deploy automático por la integración nativa de GitHub de Vercel (preview por
  push/PR, producción en `main`); `.github/workflows/ci-cd.yml` solo corre
  tests + coverage, no dispara el deploy.
- Local sigue usando Ollama por default (`AI_BACKEND=ollama`, alcance
  académico); en Vercel es exclusivamente OpenRouter porque no hay proceso
  local persistente donde correr el LLM. Migrar de un backend a otro es solo
  cambiar `AI_BACKEND`/`OPENROUTER_API_KEY` en `.env`, sin tocar código
  (routing en `ai_engine._call_ai`).
- Inferencia local: GPU NVIDIA (CUDA) con `num_ctx` coherente (1024) entre
  peticiones — Ollama recompila si cambia el contexto (~5s). Latencia con
  GPU+tuning+caché: evaluate cold ~2.8s / cached ~1ms / generate ~1.6s
  (detalle en `docs/evidencia/comparativa-rendimiento.md`).
- Caché evaluate: key incluye `AI_EVALUATE_VERSION` (`ai_engine.py`) para
  invalidar al cambiar prompts; `generate` nunca se cachea (riesgo de reuso).
- Seed del panel SP-1: `python scripts/seed_dashboard_demo.py` (idempotente,
  requiere `SUPABASE_SERVICE_ROLE_KEY`).
- Esquema del vault (HU17): `python scripts/apply_vault_schema.py` — aplica
  `sql/vault_schema.sql` vía `SUPABASE_DB_URL` si está configurada (conexión
  directa con `psycopg`), o imprime el SQL para pegar a mano en el editor de
  Supabase si no. Idempotente, verifica al final contra la API real.
- Verificación E2E del vault (HU17): `python scripts/e2e_vault_check.py`
  contra el backend levantado y Supabase real (no mocks) — crea dos cuentas
  descartables vía Admin API, guarda/consulta/audita/borra, y comprueba
  `verify_chain`. `E2E_ALLOW_ACCOUNT_DELETE=1` suma el flujo de borrado de
  cuenta. Evidencia en `docs/evidencia/hu17-e2e.txt`.

## 9. Catálogo de endpoints (mapeo real)

| Método | Ruta | Guarda | Capa servicio | Notas |
|--------|------|--------|---------------|-------|
| GET | `/api/v1/health` | — | `db_client.check_connection` + GET Ollama raíz | estado `ok`/`degraded` |
| POST | `/api/v1/auth/register` | — | Supabase `sign_up` + `org_repo` | `type_account` viaja en el `sign_up`; si es `enterprise`, crea la organización |
| POST | `/api/v1/auth/login` | — | Supabase `sign_in_with_password` | devuelve `access_token` |
| POST | `/api/v1/auth/logout` | Bearer propio | `admin.sign_out(scope=global)` | solo propia sesión |
| POST | `/api/v1/passwords/evaluate` | auth | `entropy` + `hibp_client` + `ai_engine` (con caché `cache.py`, TTL 1h) | 3 dimensiones |
| POST | `/api/v1/passwords/generate` | auth | `random_generator` / `ai_engine` | `mode: ai\|random` |
| GET | `/api/v1/dashboard/members` | empresa | `dashboard_repo` | miembros + credenciales de **su** organización |
| POST | `/api/v1/dashboard/members` | empresa | `dashboard_repo` + Admin API | alta de trabajador; devuelve la contraseña temporal una sola vez (HU21 AC2) |
| GET | `/api/v1/dashboard/audit-log` | empresa | `dashboard_repo` | `created_at desc`, filtrado por `org_id` |
| POST | `/api/v1/dashboard/credentials/{id}/revoke` | empresa | `dashboard_repo` + Admin API | interna |
| POST | `/api/v1/dashboard/credentials/{id}/suggest` | empresa | `dashboard_repo` | externa |
| POST | `/api/v1/dashboard/credentials/{id}/restore` | empresa | `dashboard_repo` + Admin API | interna/externa |
| GET | `/api/v1/dashboard/members/{id}/vault` | empresa | `dashboard_repo` + `vault_repo` | metadata del trabajador, no descifra; sin cuenta vinculada → `[]` (HU21 AC5) |
| POST | `/api/v1/dashboard/members/{id}/vault/{item}/reveal` | empresa | `vault_repo` + `vault_crypto` | descifra con el AAD del **dueño**; doble auditoría (HU21 AC6/AC7) |
| POST | `/api/v1/vault/items` | usuario | `vault_crypto` + `vault_repo` | 503 si falta la KEK (AC5) |
| GET | `/api/v1/vault/items` | usuario | `vault_repo` | metadatos, nunca descifra |
| GET | `/api/v1/vault/items/{id}` | usuario | `vault_repo` + `vault_crypto` | 404 si no es del dueño (AC3) |
| DELETE | `/api/v1/vault/items/{id}` | usuario | `vault_repo` | no exige KEK (Ley 21.719) |
| DELETE | `/api/v1/vault/items` | usuario | `vault_repo` | purga total, `deleted_count` |
| GET | `/api/v1/vault/audit` | usuario | `vault_repo` | propio, base de HU19 |
| DELETE | `/api/v1/auth/account` | usuario | `vault_repo` + `dashboard_repo` + Admin API | irreversible, confirma correo + password |

## 10. Estructura de directorios

```
app/
├── main.py                 # Ensamblado FastAPI: CORS, routers, exception handlers
├── api/
│   ├── dependencies.py     # verify_token / require_user / require_premium / require_enterprise
│   └── routes/             # Coordinadores (auth, passwords, dashboard, vault, health)
├── core/                   # config.py (Settings) + exceptions.py (handlers 502/503)
├── schemas/                # Pydantic: auth, common, passwords, dashboard, vault
└── services/               # Todo I/O: ai_engine, hibp_client, entropy, cache,
                            #   random_generator, dashboard_repo, vault_repo,
                            #   vault_crypto, audit_chain, db_client
sql/dashboard_schema.sql    # DDL del panel de offboarding
sql/vault_schema.sql        # DDL del vault (HU17) + auditoría encadenada (HU19)
scripts/seed_dashboard_demo.py
scripts/apply_vault_schema.py   # aplica sql/vault_schema.sql (psycopg o instrucciones manuales)
scripts/e2e_vault_check.py      # verificación E2E del vault contra backend + Supabase reales
tests/                      # Ver suite en AGENTS.md
```
