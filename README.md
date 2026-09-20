# SparkGate API

Backend REST API for AI-assisted password generation and evaluation.

## Stack

- Python 3.12+ / FastAPI
- Supabase (Auth + DB)
- Llama 3.2 via Ollama (local LLM), OpenRouter API (cloud fallback, `AI_BACKEND=openrouter`)
- Have I Been Pwned (HIBP) API

## Quick Start

```bash
# 1. Clonar y configurar credenciales
cp .env.example .env   # ← llenar SUPABASE_URL y SUPABASE_KEY

# 2. Iniciar todo (Ollama + backend)
./start.sh
```

Abrir http://localhost:8000/docs

```bash
# Apagar todo cuando termines
./stop.sh
```

## Manual Step-by-Step

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3.2:3b
ollama serve &
uvicorn app.main:app --reload --port 8000
```

## Test

```bash
pytest --cov=. --cov-report=term-missing
```

Resultados, matriz de trazabilidad HU↔prueba y evidencia en
[`docs/PRUEBAS.md`](docs/PRUEBAS.md) (artefactos en `docs/evidencia/`).
Pruebas manuales (Ollama real, rendimiento) se corren con
`SPARKGATE_RUN_MANUAL=1 pytest tests/test_ollama.py` / `tests/test_performance.py`.
E2E con la extensión Chrome (Selenium, requiere `pip install selenium`) con
`SPARKGATE_RUN_E2E=1 pytest tests/test_e2e_extension.py`.

## CI/CD

GitHub Actions (`.github/workflows/ci-cd.yml`) corre la suite con coverage
(`--cov-fail-under=70`) en cada push/PR a `develop` y `main`. El deploy a
[Vercel](https://vercel.com) es automático vía su integración nativa de GitHub
(preview por push/PR, producción en `main`) — no hay job de deploy separado en
Actions. Config de build en `vercel.json`.

## Arquitectura

Backend por capas: `api/routes/` coordina y protege, `services/` concentra todo el
I/O (LLM, HIBP, Supabase), `schemas/` valida contratos y `core/` agrupa
configuración y excepciones. Rutas importan servicios; servicios nunca importan
rutas. Documentación completa con diagramas de capas, componentes, modelo de
datos y flujos en [`docs/ARQUITECTURA.md`](docs/ARQUITECTURA.md).

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/health | Health check |
| POST | /api/v1/auth/register | Register user |
| POST | /api/v1/auth/login | Login user |
| POST | /api/v1/auth/logout | Logout user |
| DELETE | /api/v1/auth/account | Delete own account + all vault data (irreversible, Ley 21.719) |
| POST | /api/v1/passwords/evaluate | Evaluate password |
| POST | /api/v1/passwords/generate | Generate password |
| GET | /api/v1/dashboard/members | List members + credentials of the caller's org (enterprise) |
| POST | /api/v1/dashboard/members | Provision a worker account, returns a one-time temporary password (enterprise) |
| GET | /api/v1/dashboard/audit-log | Audit log of the caller's org (enterprise) |
| POST | /api/v1/dashboard/credentials/{id}/revoke | Rotate an internal account's password and ban it: blocks logins and refresh tokens at once (enterprise, **TOTP**) |
| POST | /api/v1/dashboard/credentials/{id}/suggest | Suggest an external credential password, left "pending manual application" — never claims the provider changed (enterprise, **TOTP**) |
| POST | /api/v1/dashboard/credentials/{id}/restore | Restore credential (enterprise) |
| GET | /api/v1/dashboard/members/{id}/vault | Worker's vault metadata, never decrypts (enterprise) |
| POST | /api/v1/dashboard/members/{id}/vault/{item}/reveal | Decrypt a worker's credential; writes to both audit logs (enterprise, **TOTP**) |
| GET/POST | /api/v1/dashboard/credentials | List (`?assigned=false` = unassigned pool) / register an external account (enterprise) |
| PUT | /api/v1/dashboard/credentials/{id}/secret | Store or replace the organization's password for an account; never echoes it (enterprise, **TOTP**) |
| POST | /api/v1/dashboard/credentials/{id}/secret/reveal | Decrypt an organization credential (enterprise, **TOTP**) |
| POST | /api/v1/dashboard/credentials/{id}/reassign | Hand an external account to the replacement, or back to the pool (enterprise) |
| GET | /api/v1/me/credentials | What the organization assigned to the logged-in worker (any user) |
| POST | /api/v1/me/credentials/{id}/reveal | The worker retrieves an assigned credential (any user, **TOTP**) |
| GET | /api/v1/me/mfa | Second-factor status; never the secret (any user) |
| POST | /api/v1/me/mfa/enroll | Start TOTP enrollment: returns the secret + `otpauth://` URI once; pending until confirmed (any user) |
| POST | /api/v1/me/mfa/confirm | Activate the factor with the first code, in `X-SparkGate-TOTP` (any user) |
| DELETE | /api/v1/me/mfa | Deactivate the factor; needs a valid code in `X-SparkGate-TOTP` (any user) |
| POST | /api/v1/vault/items | Save an encrypted credential (HU17 AC1/AC2) |
| GET | /api/v1/vault/items | List own credentials (metadata only, never decrypted) |
| GET | /api/v1/vault/items/{id} | Decrypt and return own credential (HU17 AC3) |
| DELETE | /api/v1/vault/items/{id} | Delete one credential (Ley 21.719, works without the master key) |
| DELETE | /api/v1/vault/items | Purge all own credentials (Ley 21.719) |
| GET | /api/v1/vault/audit | Own vault audit trail (HU19 hash chain) |

### Second factor (HU18)

Reading or rotating a secret that is **not yours** needs a valid TOTP code (RFC 6238: the same
6-digit code Google Authenticator / Authy shows), sent in the `X-SparkGate-TOTP` header. The rows
marked **TOTP** above are the six operations that require it. That includes the worker retrieving
a credential the organization assigned to them: that secret belongs to the organization.

A rejected request never touches the credential, changes nothing, and is written to the audit log
with its reason. The `403` carries a top-level `code` so a client can tell "enroll first" from
"ask for the code again":

| `code` | Meaning |
|---|---|
| `totp_no_enrolado` | The account has no active factor (a factor still pending confirmation counts as none) |
| `totp_invalido` | Code missing, malformed, wrong or expired |
| `totp_reutilizado` | A valid code that was already used (anti-replay: one operation per 30 s step) |
| `totp_bloqueado` | 5 wrong codes in a row: locked for 15 minutes, even for a correct code |

If the second factor cannot be verified (`TOTP_MASTER_KEY` missing) the answer is `503`, never a
pass. `TOTP_MASTER_KEY` is a key of its own, separate from `VAULT_MASTER_KEY` on purpose: revoking a
departed member must keep working with the vault key down. See `.env.example`.

Enroll the demo owner with `python scripts/seed_hu18_factor.py`; apply the schema with
`python scripts/apply_mfa_schema.py`. Real end-to-end evidence: `docs/evidencia/hu18-e2e.txt`.

### Generate modes

| mode | Description |
|------|-------------|
| `ai` | AI-generated (Llama 3.2, memorable, Spanish vocab). Default. |
| `random` | Cryptographically random (secrets module). Traditional generator. |
