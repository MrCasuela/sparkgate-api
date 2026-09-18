# Pruebas y Evidencia — SparkGate API

> Documento vivo de pruebas del backend. Resultados de ejecución real de la suite
> automatizada y de las pruebas manuales ejecutables, matriz de trazabilidad con
> las historias de usuario (HU) del backlog y estado honesto de las pruebas que
> quedan pendientes. Artefactos en `docs/evidencia/`.

Fecha de última ejecución: 2026-09-07 (backend activo: Ollama `llama3.2:3b` corriendo en `:11434`).

## 1. Resumen ejecutivo

| Métrica | Resultado |
|---|---|
| Suite automatizada (unitarias + integración + tolerancia a fallos) | **119 passed, 0 failed, 2 skipped (E2E manual), 12 deselected** |
| Cobertura de sentencias (`pytest --cov`) | **91%** (643 stmts, 58 sin cubrir, solo `app/`) |
| Objetivo de cobertura declarado (informe, Tabla métricas / monitoreo) | ≥ 70% → **superado** |
| PT06 — Ollama real (llama3.2:3b) | ✅ 3/3 passed (GPU + tuning; 7.69s total) |
| PT10 — Rendimiento (latencia promedio 10 req) | ✅ evaluate avg 2.76s (<5s), generate avg 1.57s (<3s) |
| PT07 — E2E Sistema (Selenium, requiere extensión) | **Pendiente** (requiere Chrome + extensión) |
| PT09 — UX comprensibilidad (≥10 usuarios, Google Forms) | **Pendiente** (sesión con usuarios) |

Conclusión: la cobertura de **código de backend** es alta y los **umbrales de
rendimiento con inferencia local** quedan cumplidos tras activar la GPU de la
máquina de desarrollo con tuning y caché (ver `docs/evidencia/comparativa-rendimiento.md`).
Las pruebas de **aceptación / experiencia de usuario / sistema end-to-end** siguen
sin ejecutarse; existe plantilla de acta (`docs/ACTA_ACEPTACION_TEMPLATE.md`) y
skeleton E2E (`tests/test_e2e_extension.py`), pero ninguna acta está firmada
todavía (ver §4).

## 2. Resultados de ejecución — pruebas automatizadas

Comando reproducido:

```bash
source .venv/bin/activate
pytest --cov=. --cov-report=term-missing --cov-report=xml:docs/evidencia/coverage.xml \
       --junitxml=docs/evidencia/junit-api.xml -k "not ollama and not performance"
```

Resultado: **119 passed, 2 skipped, 12 deselected** (cambios de esta pasada: test
de login HU02 antes inexistente, test de contrato HU12 para detección de info
personal, migración Groq→OpenRouter, skeleton E2E PT07; ver §5). Cobertura por
módulo en `docs/evidencia/coverage.xml` y resumen completo en
`docs/evidencia/resumen.txt`.

### 2.1 Cobertura por módulo (backend `app/`)

| Módulo | Cobertura | Módulo | Cobertura |
|---|---|---|---|
| `app/api/routes/passwords.py` | 95% | `app/api/routes/dashboard.py` | 90% |
| `app/api/routes/auth.py` | 97% | `app/api/routes/health.py` | 89% |
| `app/api/dependencies.py` | 63% | `app/services/ai_engine.py` | 96% |
| `app/services/entropy.py` | 100% | `app/services/hibp_client.py` | 91% |
| `app/services/cache.py` | 93% | `app/services/random_generator.py` | 100% |
| `app/services/dashboard_repo.py` | 36% | `app/services/db_client.py` | 74% |
| `app/core/config.py` | 100% | `app/core/exceptions.py` | 100% |
| `app/main.py` | 100% | `app/schemas/*` | 100% |

Huecos conocidos (documentados en `AGENTS.md`): `verify_token` con Supabase real,
`dashboard_repo` sin Supabase service_role en CI, ramas de error de `health.py` y
parseo fallback de `ai_engine.py:143-146`.

### 2.2 Mapeo plan de pruebas (informe, Tabla 18) → resultado

| ID | Tipo | Componente | Resultado |
|----|------|-----------|-----------|
| PT01 | Unitaria | `entropy.py` (H = L × log₂(R)) | ✅ Pasa (`test_entropy`) |
| PT02 | Unitaria | Generación con H ≥ 60 bits | ✅ Pasa (`test_generator`, `test_random_generator`, `test_passwords_advanced`) |
| PT03 | Unitaria | `hibp_client.py` k-anonymity (prefijo 5 hex) | ✅ Pasa (`test_hibp_client`) |
| PT04 | Integración | `POST /passwords/generate` | ✅ Pasa (`test_api_generate`) |
| PT05 | Integración | `POST /passwords/evaluate` (3 dimensiones) | ✅ Pasa (`test_api_evaluate`) |
| PT06 | Integración real | Ollama / llama3.2:3b | ✅ 3/3 pasa (GPU + tuning de producción) |
| PT07 | Sistema/E2E | Flujo completo desde extensión (Selenium/manual) | ⏳ Pendiente (requiere frontend) |
| PT08 | Tolerancia a fallos | HIBP/Ollama caídos | ✅ Pasa (`test_fault_tolerance`) |
| PT09 | Comprensibilidad UX | ≥10 usuarios, Google Forms | ⏳ Pendiente (sesión con usuarios) |
| PT10 | Rendimiento | Latencia avg evaluate <5s, generate <3s | ✅ Cumple (medido §3.2) |

## 3. Pruebas manuales ejecutadas

Ejecutadas con `SPARKGATE_RUN_MANUAL=1` (los tests saltan por defecto; ver `tests/test_ollama.py` y `tests/test_performance.py`). Logs: `docs/evidencia/pt06-manual.txt`, `docs/evidencia/pt10-manual.txt`.

### 3.1 PT06 — Ollama real (llama3.2:3b)

Ejecutado con la GPU de la máquina activa (GTX 1650 Ti, 100% offload) y las mismas
opciones de inferencia que la API de producción (`num_ctx` 1024, `num_predict`
acotado).

| Prueba | Resultado | Detalle |
|---|---|---|
| `test_ollama_connection` | ✅ | `GET :11434` → 200 |
| `test_ollama_evaluate_semantic` | ✅ | JSON semántico parseado (200 tok max) |
| `test_ollama_response_time` | ✅ | 3.2s por generación (umbral <5s) |

Interpretación: la latencia pasó de ~16s (CPU) a ~3.2s (GPU + `num_ctx` acotado,
~59 tok/s). Detalle: **mantener `num_ctx` coherente entre peticiones** — Ollama
recompila la gráfica al cambiar el contexto entre llamadas (~5s extra). Los tests
manuales usan las mismas opciones que la app para no medir ese golpe.

### 3.2 PT10 — Rendimiento (10 solicitudes, backend real, auth simulado)

Se usó `app.dependency_overrides[verify_token]` para medir el backend de IA real
sin depender de Supabase Auth (ver `tests/test_performance.py`).

Medición propia adicional (cold = HIBP + Ollama reales, sin caché; ver
`docs/evidencia/comparativa-rendimiento.md`):

| Prueba | Umbral | Medido | Resultado |
|---|---|---|---|
| `test_evaluate_latency` (avg 10 req) | avg < 5.0s | 2.76s cold (caché: ~1ms) | ✅ |
| `test_generate_latency` (avg 10 req) | avg < 3.0s | 1.57s | ✅ |

Interpretación: el cuello de botella anterior era la inferencia local de Llama en
CPU. Con la GPU de desarrollo, `num_ctx` 1024 y `num_predict` acotado por
propósito, los umbrales se cumplen sin cambiar de modelo ni de prompts (calidad
semántica preservada: `ai_score` real, generación `attempts=1`). La caché de
evaluate convierte entradas repetidas en ~1ms.

## 4. Aceptación (pendiente de ejecución)

**No existen actas de aceptación firmadas** (ni de HU individuales ni de usuario).
Ya existen los artefactos para producirlas, pero falta ejecutar:

- **Plantilla de acta**: `docs/ACTA_ACEPTACION_TEMPLATE.md` — una por HU (o por
  sprint), a llenar y archivar en `docs/actas/` tras validar cada historia.
- **PT09**: requiere sesión de validación con ≥10 usuarios distintos del Focus
  Group original (formulario Likert 4-5 → ≥80% comprensibilidad). Sin contenido
  de formulario armado todavía.
- **PT07**: skeleton en `tests/test_e2e_extension.py` (Selenium + extensión sin
  empaquetar). El primer test (popup carga + backend real) debería correr; el
  segundo (flujo generar→copiar) queda `@pytest.mark.skip` hasta mapear los
  selectores reales del popup React. Ejecutar con
  `SPARKGATE_RUN_E2E=1 pytest tests/test_e2e_extension.py -v` (requiere
  `pip install selenium`, no está en `requirements.txt` por ser manual-only).

Una vez ejecutadas, deben documentarse los resultados aquí y adjuntarse las actas
de aceptación correspondientes.

## 5. Problemas encontrados y resueltos en esta pasada

- `test_generate_ai_retry_exhaustion_returns_502` fallaba porque fijaba un mock de
  **Groq** mientras que `.env` tenía `AI_BACKEND=ollama` (test acoplado a entorno).
  Corregido `tests/test_passwords_advanced.py` para forzar y restaurar
  `settings.ai_backend = "groq"` dentro del test → determinista en ambos modos.
  (Nota posterior: Groq eliminó sus modelos gratuitos; el backend cloud se
  migró a OpenRouter — ver bullet más abajo. Esta entrada queda como registro
  histórico de esa pasada.)
- `test_ollama_response_time` medía ~15.9s en CPU. Tras GPU + tuning, el límite
  `num_predict=80` truncaba el JSON de evaluate (caía al fallback de entropía);
  subido a 200 → JSON completo y `ai_score` semántico real. El límite de 160 en
  generate es suficiente (`attempts=1`).
- Los tests manuales usan ahora las **mismas opciones de inferencia** que la app
  (`num_ctx`/`num_predict`); con `num_ctx` heterogéneo Ollama recompila la gráfica
  por petición (~5s extra) y el test de respuesta fallaba en 7.6s pese a que el
  mismo request directo tardaba 3.2s.
- Se detectó una cobertura inicial de `cache.py` de 77% → añadidos 8 unit tests
  (`tests/test_cache.py`) + integración de hit de caché en `test_api_evaluate` →
  93% y comportamiento bloqueado (TTL, evicción LRU, clear).
- **Backend cloud migrado de Groq a OpenRouter** (Groq eliminó sus modelos
  gratuitos): `app/core/config.py` y `app/services/ai_engine.py` renombrados
  (`openrouter_api_key`/`openrouter_model`), modelo default
  `meta-llama/llama-3.1-8b-instruct` (pagado, ~$0.000004/call — se probó contra
  la API real). Se agregó `reasoning: {exclude: true}` al request porque varios
  modelos gratuitos de OpenRouter son "reasoning" y agotan el budget de tokens
  pensando en vez de devolver JSON. 9 tests de `test_ai_engine.py` renombrados
  (`groq_backend`→`openrouter_backend`), más `test_fault_tolerance.py` y
  `test_passwords_advanced.py`.
- **HU02 (login) no tenía ningún test**, ni mockeado — la matriz de §6 decía
  "parcial" mal etiquetado. Agregado `tests/test_auth_login.py` (4 tests:
  éxito, `premium` default, credenciales inválidas, campos faltantes) →
  `auth.py` sube de 78% a 97%.
- **HU12 (detección de info personal) sin prueba dedicada.** Agregado
  `test_evaluate_surfaces_personal_info_detection` en `test_api_evaluate.py`:
  fija contrato de que lo que el LLM reporte sobre nombre/fecha llega intacto
  al response. No valida calidad semántica del modelo (eso es PT09).
- Agregada plantilla de acta de aceptación (`docs/ACTA_ACEPTACION_TEMPLATE.md`)
  y skeleton E2E para PT07 (`tests/test_e2e_extension.py`, gateado por
  `SPARKGATE_RUN_E2E=1`, selenium no instalado por defecto).

## 6. Matriz de trazabilidad HU ↔ pruebas

Backlog: 15 HU (`Informe` §Product Backlog). Cobertura evaluada contra **este repo
(backend)**; HU de UI/instalación corresponden al repo de la extensión Chrome.

| HU | Épica | Historia | Prueba backend (archivo/caso) | Resultado | Estado |
|----|-------|----------|------------------------------|-----------|--------|
| HU01 | Autenticación | Crear cuenta | `test_auth_register` | ✅ | Cubierta |
| HU02 | Autenticación | Iniciar sesión | `test_auth_login` | ✅ | Cubierta |
| HU03 | Autenticación | Suscribirse a Premium | `require_premium` en `test_api_*` (403 sin premium) | ✅ | Cubierta (gateo) |
| HU04 | Autenticación | Cerrar sesión | `test_auth_logout` | ✅ | Cubierta |
| HU05 | Generador | Generar con un clic | `test_api_generate` (modo ai/random) | ✅ | Cubierta |
| HU06 | Generador | Ver qué tan segura es | `test_generator` (entropy ≥60), `test_api_generate` | ✅ | Cubierta |
| HU07 | Generador | Fácil de recordar | `ai_engine` (estilos/personalización) `test_passwords_advanced` | ✅ | Cubierta |
| HU08 | Generador | Copiar con un clic | — (UI extensión) | — | Frontend (repo extensión) |
| HU09 | Detector | Evaluar existente | `test_api_evaluate` | ✅ | Cubierta |
| HU10 | Detector | Explicación por qué es débil | `test_api_evaluate` (ai_feedback fallback) | ✅ | Cubierta |
| HU11 | Detector | Saber si está en filtración | `test_hibp_client` + `test_api_evaluate` | ✅ | Cubierta |
| HU12 | Detector | Detectar info personal (nombre/fecha) | `test_evaluate_surfaces_personal_info_detection` | ✅ | Cubierta (contrato; calidad semántica depende del LLM, ver nota) |
| HU13 | Extensión | Instalar con un clic | — | — | Frontend (no aplica backend) |
| HU14 | Extensión | Detectar campos de contraseña | — | — | Frontend (no aplica backend) |
| HU15 | Extensión | Interfaz simple/clara | — | — | Frontend (no aplica backend) |
| HU16 | Dashboard | Panel de gobernanza de credenciales (interna vs externa) | `test_dashboard` | ✅ | Cubierta (agregada al backlog en Jira SCRUM-25 después de este documento) |
| HU17 | Vault | Resguardar y consultar credencial propia (CU07) | `test_vault_crypto`, `test_audit_chain`, `test_api_vault`, `test_auth_account_delete` + E2E real (`scripts/e2e_vault_check.py`, evidencia en `docs/evidencia/hu17-e2e.txt`, 14/14 pasos OK) | ✅ | Cubierta (AC1-AC5; agregada en SP-2 después de este documento). Paso AC5 con KEK caída queda como sub-check manual documentado en el propio script — reinicia el proceso del backend, algo que un script no debe hacerle a un proceso que no le pertenece |
| HU21-A | Gobernanza | Cuentas personal vs. empresa, provisioning y aislamiento (AC1-AC4) | `test_org_accounts`, `test_dashboard_members`, `test_dashboard` (aislamiento) | ✅ | Cubierta. AC4 (gating del botón en el popup) es frontend: repo extensión, `Navigator.test.tsx` |
| HU21-B | Gobernanza | La empresa consulta la bóveda de un trabajador (AC5-AC8) | `test_dashboard_vault`, `test_audit_chain` (cadena mixta) + E2E real (`scripts/e2e_hu21_check.py`, evidencia en `docs/evidencia/hu21-e2e.txt`) | ✅ | Cubierta. El caso de AC8 con la clave maestra caída queda como sub-check manual impreso por el script, igual que en HU17 |

Resumen de cobertura de HU (backend):

| Universo | Cantidad |
|---|---|
| HU del backlog original (informe) | 15 |
| HU agregada después en Jira | 3 (HU16 SCRUM-25, HU17 SP-2, HU21 SP-2) |
| HU frontend (repo extensión, no aplica aquí) | 4 (HU08, HU13, HU14, HU15) |
| HU backend aplicables | 14 (11 del backlog original + HU16 + HU17 + HU21) |
| HU backend cubiertas (✅) | 14 |
| HU backend parciales (⚠️) | 0 |
| **% cobertura backend** | **14/14 = 100%** |

Nota metodológica: la cobertura de *líneas* (90%) y la cobertura de *HU* (100%
backend) son métricas distintas; se reportan ambas, no se mezclan. HU12 se
cubre como **contrato** (la API propaga correctamente lo que el LLM reporta),
no como validación de la calidad semántica del modelo — eso requeriría
evaluación humana tipo PT09, fuera del alcance de un test automatizado.

## 7. Cómo reproducir

```bash
# Suite automatizada con evidencia
pytest --cov=. --cov-report=term-missing --cov-report=xml:docs/evidencia/coverage.xml \
       --junitxml=docs/evidencia/junit-api.xml -k "not ollama and not performance"

# Pruebas manuales (requieren Ollama corriendo con llama3.2:3b y GPU activa)
SPARKGATE_RUN_MANUAL=1 pytest tests/test_ollama.py -v      # PT06
SPARKGATE_RUN_MANUAL=1 pytest tests/test_performance.py -v # PT10
```

Comparativa CPU↔GPU y detalle de mediciones: `docs/evidencia/comparativa-rendimiento.md`.