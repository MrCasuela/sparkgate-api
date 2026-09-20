# HU18 — Acceso administrativo con verificación TOTP

> **Estado:** implementada en el backend y verificada contra Supabase real (35/35 pasos sustantivos, 6 omitidos, ver §6 y `docs/evidencia/hu18-e2e.txt`). La UI de la extensión se hizo después (ver el anexo §9); pendientes: verla en un Chrome real y tres pasos manuales.
> **Fecha de diseño:** 2026-09-19. **Política:** las correcciones que impuso el código NO se funden en el diseño; van en el §8, con lo que decía el plan y lo que dijo el código.
> **Referencia:** CU08 — Consultar o rotar credencial de un integrante (Informe, Casos de Uso). Cierra R-HU21-1 y R-HU21-7.

---

## 1. Problema

HU21 dejó un hueco documentado y deliberado: **sin segundo factor**, una cuenta empresa comprometida lee todas las credenciales de sus trabajadores y de la organización presentando solo su JWT. El Informe lo prohíbe (CU08, RNF1: «ninguna credencial de terceros sin 2FO»).

HU21 dejó el cimiento a propósito, y eso define el tamaño real de esta HU:

| Pieza | Dónde | Estado antes de HU18 |
|---|---|---|
| Punto de paso único | `secret_access._verify_step_up` | existía, un no-op de ocho líneas |
| Excepción 403 | `StepUpRequired` | existía, sin usar |
| Header | `optional_step_up_code` (`X-SparkGate-TOTP`) | existía, cableado en tres rutas |
| Auditoría del intento fallido (AC4) | `on_denied` en las tres rutas de lectura | ya escribía el denegado |
| AC3 «pendiente de aplicación manual» | estado `pendiente_aplicacion_manual` + `suggest` | existía |
| AC2 «rota y revoca sesiones» | `revoke`: `update_user_by_id(password + ban_duration)` | existía |

Lo que faltaba era el **verificador**: no había librería TOTP, ni tabla de factores, ni enrolamiento, y las rutas de **escritura** (rotar, sugerir, aplicar una contraseña) no pasaban por el punto de paso, que era solo de lectura.

## 2. Decisiones

| # | Tema | Decisión |
|---|---|---|
| D1 | Dónde vive el factor | Tabla propia `user_totp_factors` + `pyotp`. **No** Supabase MFA: verificar AAL2 exige validar el JWT localmente (hoy `verify_token` consulta a Auth en cada request), y enrolar/verificar necesita una sesión del usuario en el backend, contra la regla de no hacer `sign_in` en el cliente compartido |
| D2 | A quién se le exige | A **todo** lector de un secreto ajeno, incluido el trabajador que retira la credencial que le asignaron: esa credencial es de la ORGANIZACIÓN, no suya. El enrolamiento va bajo `require_user` |
| D3 | Endpoints | **Ninguno nuevo de rotación.** Se blindan `revoke` (AC2), `suggest` (AC3) y `PUT /secret`. `_resolve_password` usa `generate_password_core` («vía /passwords/generate») |
| D4 | Dos 403 distinguibles | `totp_no_enrolado` (la UI lleva a enrolarse) y `totp_invalido`/`reutilizado`/`bloqueado` (la UI pide el código de nuevo), en el campo `code` de primer nivel |
| D5 | AC5 | Se documenta **medido**, no citado (ver §6) |
| D6 | Claves | **`TOTP_MASTER_KEY` propia**, distinta de `VAULT_MASTER_KEY` |
| D7 | Códigos de recuperación | **Fuera de alcance.** Son un almacén aparte (un solo uso, invalidación en bloque): una HU, no un apéndice. El sustituto es el break-glass administrativo (R-HU18-1) |

**Por qué D6.** `_try_store_secret` afirma que «revocar a alguien que se va no puede depender de que la clave maestra esté arriba». Con el factor bajo la KEK, sin KEK no se podría *verificar* el TOTP y revocar dejaría de funcionar: la decisión D1 chocaba de frente con una propiedad ya escrita. Con una clave propia esa propiedad sigue siendo cierta y no hay que desdecir ningún texto; los dos fallos quedan descorrelacionados en vez de sumados.

## 3. Esquema

`sql/mfa_schema.sql`, **aditivo puro**: no recrea ninguna tabla, así que `reset_hu21_schema.py` no se toca. Los dos `ALTER ... CHECK` cambian restricciones, no columnas: `dashboard_audit_log` hashea la columna `payload`, y `vault_audit_log` hashea el **conjunto de columnas**, que no cambia (`_Leccion-cadena-hash-vs-evolucion-de-esquema`). Los mismos CHECKs van en línea en los dos `.sql` originales para un entorno nuevo.

`user_totp_factors`: `user_id` (PK), `secret_envelope` **jsonb** (el sobre entero en una columna: ningún módulo nuevo nombra las columnas del criptograma de la bóveda y el test hermético sigue valiendo), `confirmed_at` (nulo = a medias, **no habilita nada**), `last_time_step` (anti-replay), `failed_attempts`/`locked_until`. RLS deny-all como las demás.

| Log | Acciones nuevas |
|---|---|
| `dashboard_audit_log` | `revocar_interna_denegado`, `sugerir_externa_denegado`, `guardar_secreto_denegado` |
| `vault_audit_log` | `mfa_enrolar`, `mfa_activar`, `mfa_desactivar`, `mfa_denegado` |

El ciclo de vida del factor va a `vault_audit_log` y no al del panel: es de la persona, una cuenta personal no tiene `org_id` y `dashboard_audit_log.org_id` es columna generada del payload. Además el propio usuario lo ve en `GET /vault/audit`. Las **lecturas** no necesitan acciones nuevas: `consultar_secreto_denegado` y `consultar_vault_miembro_denegado` ya existían.

`denied_reason` viaja en el payload jsonb. **Tres lugares o desaparece en silencio** (el fallo G8 de HU21): el payload, `_AUDIT_PAYLOAD_KEYS` y `AuditLogEntryOut`.

## 4. Backend

| Archivo | Cambio |
|---|---|
| `app/services/totp_service.py` (nuevo) | enrolar / confirmar / verificar / desactivar. Ventana ±1 paso, anti-replay, bloqueo. Nunca imprime el secreto, el código ni el URI |
| `app/services/totp_repo.py` (nuevo) | persistencia. `mark_used` y `confirm_factor` son UPDATE **condicionales** |
| `app/services/vault_crypto.py` | `key_b64` opcional en `encrypt/decrypt/is_available`: una sola implementación de GCM/AAD/sobre, la segunda clave es un parámetro |
| `app/services/secret_access.py` | `_verify_step_up` real; `require_step_up` para las escrituras; `read_foreign_secret` pasa por él; `DENIED_STEP_UP` desaparece en favor de los cuatro motivos concretos |
| `app/core/exceptions.py` | `StepUpRequired` (con `code`) + handler; se re-exporta desde `secret_access` |
| `app/services/password_factory.py` (nuevo) | `generate_password_core`, bajada desde la ruta de contraseñas |
| `app/api/routes/mfa.py`, `app/schemas/mfa.py` (nuevos) | enrolamiento |
| `app/api/routes/dashboard.py`, `me.py` | `require_step_up` en revoke/suggest/PUT; `denied_reason` en las denegaciones de lectura |

| Método | Ruta | Comportamiento |
|---|---|---|
| GET | `/api/v1/me/mfa` | estado (`enrolled`, `pending`, …); nunca el secreto |
| POST | `/api/v1/me/mfa/enroll` | 201; devuelve secreto + `otpauth://` **una sola vez**; 409 si ya hay uno confirmado; 503 sin `TOTP_MASTER_KEY` |
| POST | `/api/v1/me/mfa/confirm` | el primer código correcto activa el factor |
| DELETE | `/api/v1/me/mfa` | exige un código vigente: un JWT robado no puede apagar el factor |
| POST | `/dashboard/credentials/{id}/revoke` | **AC2**: rota la contraseña y banea en una llamada |
| POST | `/dashboard/credentials/{id}/suggest` | **AC3**: `pendiente_aplicacion_manual`, sin afirmar el cambio |
| PUT | `/dashboard/credentials/{id}/secret` | guardar una contraseña ES rotar |

**Sobre `sign_out` (AC2).** `auth.admin.sign_out(jwt, scope)` revoca una sesión **por su propio JWT**, que el admin no tiene. `ban_duration` (junto con el cambio de contraseña) es el único mecanismo de la Admin API tecleado por `user_id`. El enunciado ofrece las dos y el código ya había elegido la única viable.

**Orden dentro de cada escritura:** después de las guardas (404, tipo, estado) y **antes de cualquier efecto**. Un 400 no quema un código (uno cada 30 s) y un rechazo no puede dejar la cuenta de Auth con la contraseña nueva y la operación denegada.

## 5. Documentación a actualizar

`README.md` (filas de `/me/mfa*`, columna **TOTP**, sección «Second factor») · `docs/ARQUITECTURA.md` (§4.1, §5, §6.5 nuevo, §7 invariantes, §9) · `docs/PRUEBAS.md` (fila HU18) · `CLAUDE.md` · `.env.example` · bóveda Obsidian (ADRs, lecciones, journal).

## 6. Verificación

**Suite:** 381 passed, 3 skipped, cobertura de `app/` 90 %. Los cuerpos reales de `totp_repo` (34 %) solo corren contra un Supabase de verdad: los cubre el E2E.

**E2E real** (`python scripts/e2e_hu18_check.py`, evidencia en `docs/evidencia/hu18-e2e.txt`): 35/35 pasos sustantivos, 6 omitidos.

| Pasos | Prueba |
|---|---|
| 1-5 | Sin factor: 403 `totp_no_enrolado`, denegado auditado con su motivo, no accede a la credencial; también el trabajador |
| 6-11 | Enrolar; un factor **pendiente** no habilita nada aunque el código sea válido; confirmar; 409; el sobre no está en claro en la base |
| 12-18 | Leer con código; **reuso → `totp_reutilizado`**; código malo → `totp_invalido`; el trabajador con su propio factor |
| 19-21 | Revocar sin código: 403 y **nada se ejecutó**; con código: 200, contraseña nueva aplicada y guardada |
| **22-24** | **AC5 medido** |
| 25-28 | Sugerir y guardar, con y sin código |
| 29-32 | Desactivar; 5 fallos → `totp_bloqueado`, y ni un código correcto y fresco pasa |
| 33-35 | Cadenas íntegras; ninguna contraseña, secreto TOTP ni código en la auditoría |

**AC5, lo medido.** El enunciado dice que un `access_token` ya emitido «puede seguir siendo válido hasta su expiración natural (~1 h)». Contra este Supabase, en las rutas de SparkGate: el access token del trabajador responde **401 en la petición siguiente** (paso 22); ni la contraseña vieja ni la nueva inician sesión, ambas dan `user_banned` (23); y el refresh token emitido antes de revocar da `refresh_token_not_found` (24): GoTrue elimina la sesión al cambiar la contraseña y banear, así que no es «bloqueado por el ban» sino «ya no existe». La causa es que `verify_token` **consulta a Auth en cada request** y no valida el JWT localmente. La limitación de JWT sigue existiendo para un tercero que valide el JWT por su cuenta, y está **documentada, no oculta**, en `ARQUITECTURA.md` §7 — con la dependencia nombrada: si alguien pasa a validación local, esa fila deja de ser cierta y hay que rehacer la medición.

**No ejercitado contra el sistema real (SKIP, no suman):** KEK caída, `TOTP_MASTER_KEY` caída y deriva de reloj (exigen reiniciar un proceso o alterar el reloj); expiración del bloqueo; `PUT` con `apply_to_account` (en ese punto la cuenta ya está revocada); la ventana de ~1 h de un JWT validado offline (no existe ningún validador offline en este sistema). **Manuales pendientes:** M1 (revocar con la KEK caída debe seguir funcionando), M2 (sin `TOTP_MASTER_KEY` debe dar 503) y M3 (escanear el QR con una app de autenticación **real**: es la única prueba de que SHA1/6/30 es compatible con un teléfono).

## 7. Riesgos aceptados

**R-HU18-1 — Perder `TOTP_MASTER_KEY` deja a todos fuera de todo secreto ajeno.** Mitigación exigida en esta iteración: break-glass administrativo (`python scripts/seed_hu18_factor.py --reset`): un operador con `service_role` borra la fila y la persona se re-enrola. No recupera ningún secreto; recupera el acceso al sistema. Queda visible: el siguiente intento audita `totp_no_enrolado`. Seguimiento: códigos de recuperación.

**R-HU18-2 — Bloqueo de las cuentas existentes al desplegar.** Nadie tiene factor. Mitigado por el orden de commits (el enrolamiento se despliega **antes** que la exigencia), el 403 distinguible y el seed. **Explícitamente NO hay variable de entorno de bypass:** un interruptor global para apagar el único control de HU18 es el mecanismo clásico por el que un control muere en silencio, y sería lo primero que un incidente activa. La salida es administrativa y auditable.

**R-HU18-3 — Dos claves que custodiar.** Coste aceptado de D6. La rotación futura de claves tiene que cubrir las dos (`kek_version` ya existe).

**R-HU18-4 — Replay de ±30 s reducido, no eliminado.** `valid_window=1` acepta tres pasos; quien capture un código y lo use **antes** que el usuario legítimo gana la carrera. Inherente a TOTP; mitigan HTTPS y que el código viaje en un header y no en una URL.

**R-HU18-5 — Deriva de reloj.** Más de 30 s de desfase producen códigos rechazados sin que la persona sepa por qué. El detalle del 403 dice «o ya expiró». **No** se amplía la ventana: agrandarla agranda el replay para todos.

**R-HU18-6 — Un factor por persona, sin multi-dispositivo.** Cambiar de teléfono exige desactivar con el viejo aún funcionando; perderlo lleva a R-HU18-1.

**R-HU18-7 — Una operación sensible cada 30 s** (consecuencia del anti-replay, no un defecto). Seguimiento: una sesión de step-up corta, que es un mecanismo aparte.

**R-HU18-8 — El bloqueo es por usuario, no por IP.** No hay rate limiting en el proyecto. Cinco intentos cada 15 min sobre 10⁶ combinaciones es suficiente. `mark_failure` es read-modify-write: bajo una ráfaga concurrente puede regalar un par de intentos antes de que el bloqueo entre.

**R-HU18-9 — Quien tenga el JWT de la víctima puede bloquearla.** Cinco códigos incorrectos bloquean al dueño legítimo durante 15 min: es una denegación de servicio barata para quien ya tiene su JWT. Se acepta: no da acceso a nada y queda auditado; la alternativa (no bloquear) deja la fuerza bruta abierta.

**R-HU18-10 — Operaciones sensibles que HU18 NO gatea.** `POST /dashboard/credentials/{id}/restore` (desbanea a un ex-empleado), `POST .../reassign` (entrega una credencial externa a otra persona), `POST /dashboard/members` (devuelve una contraseña temporal) y `POST /dashboard/credentials` con contraseña. No leen ni rotan un secreto ajeno, que es el alcance de los cinco AC, pero **conceden acceso**. Candidatas naturales para una HU de seguimiento.

**Lo que HU18 NO cierra** (la mitad de la honestidad del entregable):
- **No cierra R-HU21-5 (suplantación).** El factor encarece *retirar* la contraseña, no *usarla*: la sesión resultante sigue siendo indistinguible de la del trabajador.
- **No cierra R-HU21-2 (minimización).** La empresa sigue viendo la bóveda personal completa.
- **No protege contra un backend comprometido.** Las dos claves y el verificador viven en el mismo proceso: sube el costo de un JWT robado, no el de un servidor tomado.
- **No hay MFA en el login.** Una cuenta comprometida sigue entrando al panel y viendo metadata; solo no puede leer ni rotar secretos.
- **No cubre la extensión.** Sin la UI de enrolamiento, el trabajador no tiene por dónde enrolarse: es trabajo del otro repo, y el orden de despliegue lo exige (enrolamiento antes que exigencia).

---

## 8. Correcciones al diseño (anexo del 2026-09-19)

Lo que decía el plan aprobado, lo que dijo el código y cómo se resolvió.

| # | Lo que decía el plan | Lo que dijo el código | Resolución |
|---|---|---|---|
| C1 | `confirm` y `DELETE /me/mfa` reciben el código en el **body** (`MfaCodeRequest`) | Todas las demás operaciones lo reciben en `X-SparkGate-TOTP`, y algunos proxies descartan el body de un `DELETE` | El código va **siempre** en el header: un solo helper en el cliente. No existe `MfaCodeRequest` |
| C2 | `mark_used` lee `last_time_step` y compara en Python | Dos peticiones simultáneas con el mismo código leerían el mismo valor viejo y pasarían las dos | UPDATE **condicional** (`last_time_step is null or < paso`) que devuelve si tocó fila; perder la carrera es `totp_reutilizado`. Son **dos capas** de anti-replay |
| C3 | `_resolve_password` degrada al generador local si `generate_password_core` falla | `mode="random"` **ya es** ese generador y no puede fallar como lo hace la IA: el `except` sería código para un caso que no ocurre | No se agregó. Lo que sí importa: con `mode="ai"` y Ollama caído, el `try/except` de `revoke` se traga el 502 y **la cuenta no se banea** (validado inyectando esa mutación) |
| C4 | `denied_reason` siempre en el payload | Habría cambiado el payload de todas las acciones y roto el test de igualdad exacta | Solo cuando existe. El repositorio exige que sea un enum (`[a-z_]{1,40}`): aunque una ruta le pasara un código TOTP por error, no llega a la auditoría |
| C5 | El bloqueo cuenta los fallos | Un código **ausente o mal formado** no es una adivinanza; si sumara, sondear «¿esto pide segundo factor?» quemaría el bloqueo. Y tras bloquear, con el contador en 5 el primer error volvería a bloquear | Ausente/mal formado → `totp_invalido` **sin** sumar. Al bloquear el contador vuelve a 0. El bloqueo se chequea **antes** de comparar: un código correcto durante el bloqueo tampoco pasa |
| C6 | Tests: solo `test_secret_access` y los tres de ruta necesitan anular el verificador | También `tests/test_dashboard.py` ejercita revoke/suggest | Mismo fixture `sin_segundo_factor`. Para que anular el verificador no deje a las rutas sin prueba, hay un test **por ruta** con la cadena real (ruta → verificador → servicio → repo en memoria) |
| C7 | Test hermético: `secret_envelope` solo lo nombran `totp_repo` y `totp_service` | El primer borrador de `totp_repo` **nombraba en su docstring** las columnas que decía no nombrar, y el test hermético lo detectó | Docstring reescrito sin los tokens. El guard funciona |
| C8 | Los tests de anti-replay cubren el «reuso» | Una mutación `<=` → `==` **se escapó**: la segunda capa (el UPDATE) tapaba a la primera | Un neutralizador que deja activa una sola capa por test; cada capa tiene el suyo |
| C9 | El E2E espera 31 s entre operaciones que consumen código | Un `sleep` fijo desperdicia hasta 30 s | Espera hasta el borde del próximo paso (+1 s), impresa como línea explícita |
| C10 | AC5: «bloquea sesiones futuras y refresh tokens» | El refresh token no da `user_banned` sino `refresh_token_not_found` | Cierto en el efecto, distinto en el mecanismo: GoTrue elimina la sesión. Se documenta como se midió |
| C11 | `admin_api_success` en `suggest` | Vale `true` para una externa donde **no se llama a Auth** | No se renombra (rompería la extensión); el docstring y `ARQUITECTURA.md` §9 lo dicen |

**Un primer intento de E2E** cayó por un bug del propio script (una lista de módulo tratada como variable local) antes de tocar nada. No cuenta como corrida.

---

## 9. Actualización 2026-09-20 — la extensión (nota de trazabilidad; el texto de arriba no se reescribe)

La UI se hizo en el repo `sparkgate-extension` (7 commits sobre `develop`, rama `SCRUM-28-hu18-...`, sin push). El bullet
«No cubre la extensión» del §7 describía el estado del backend solo; ya no es cierto para el conjunto.

- Las seis operaciones piden el código y muestran el motivo; el enrolamiento (QR, activar, desactivar) está en el panel y
  en la bóveda del trabajador; la auditoría etiqueta los intentos rechazados. **El código es un parámetro obligatorio de
  la firma de cada función de la API**: si el backend gatea otra operación, TypeScript marca cada llamador.
- **Contrato verificado contra este backend real desde el cliente real de la extensión: 13/13** (`sparkgate-extension/docs/evidencia/hu18-contrato-real.txt`),
  con la comprobación demostrada capaz de fallar. Confirma AC5 desde el cliente: tras revocar, el access token del
  trabajador responde 401.
- Decisiones de esta capa: `sparkgate-extension/SPEC.md` (I.step-up, V23-V29) y la bóveda (ADR 2026-09-20).
- **Sigue sin verse** la interfaz en un Chrome real, ni que una app de autenticación real lea el QR (M3). Los tests de la
  extensión son de jsdom: prueban comportamiento, no aspecto.
- Corrige una predicción del SPEC de la extensión (V19: «un header a tres llamadas y nada más cambia»): eran seis
  llamadas y hicieron falta pantallas nuevas.

