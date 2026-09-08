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
| POST | /api/v1/passwords/evaluate | Evaluate password |
| POST | /api/v1/passwords/generate | Generate password |
| GET | /api/v1/dashboard/members | List members + credentials (admin) |
| GET | /api/v1/dashboard/audit-log | Audit log (admin) |
| POST | /api/v1/dashboard/credentials/{id}/revoke | Revoke internal credential (admin) |
| POST | /api/v1/dashboard/credentials/{id}/suggest | Suggest external credential password (admin) |
| POST | /api/v1/dashboard/credentials/{id}/restore | Restore credential (admin) |

### Generate modes

| mode | Description |
|------|-------------|
| `ai` | AI-generated (Llama 3.2, memorable, Spanish vocab). Default. |
| `random` | Cryptographically random (secrets module). Traditional generator. |
