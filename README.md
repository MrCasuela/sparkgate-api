# SparkGate API

Backend REST API for AI-assisted password generation and evaluation.

## Stack

- Python 3.12+ / FastAPI
- Supabase (Auth + DB)
- Llama 3.2 via Ollama (local LLM)
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

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v1/health | Health check |
| POST | /api/v1/auth/register | Register user |
| POST | /api/v1/auth/login | Login user |
| POST | /api/v1/auth/logout | Logout user |
| POST | /api/v1/passwords/evaluate | Evaluate password |
| POST | /api/v1/passwords/generate | Generate password |

### Generate modes

| mode | Description |
|------|-------------|
| `ai` | AI-generated (Llama 3.2, memorable, Spanish vocab). Default. |
| `random` | Cryptographically random (secrets module). Traditional generator. |
