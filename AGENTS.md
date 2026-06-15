# SparkGate API — Backend

## Stack

Python 3.12+ / FastAPI / Supabase / Ollama (Llama 3.2 3B) / Groq API / HIBP.

## Commands

```
./start.sh          # venv → deps → Ollama check → uvicorn :8000
./stop.sh           # kill uvicorn + ollama serve
uvicorn app.main:app --reload --port 8000
pytest --cov=. -k "not ollama and not performance"     # default (83 tests)
pytest --cov=. --cov-report=term-missing -k "not ollama and not performance"  # with misses
```

## Config

`pydantic-settings` reads `.env`. Must exist (`cp .env.example .env`). Singleton at `app.core.config.settings`.

No `pyproject.toml`. Dependencies in `requirements.txt` (pinned loose: `>=`).

## Entrypoint

`app.main:app` — FastAPI instance. CORS, routers, exception handlers registered.

## Architecture

```
api/routes/        ← coordinators (auth guard, call services, build response)
services/          ← all I/O (Ollama, Groq, HIBP, Supabase, entropy, random gen)
core/              ← config, exception classes + handlers
schemas/           ← Pydantic models
```

Routes import services. Services never import routes.

## Auth

`HTTPBearer`. `verify_token` dependency returns `dict | None`. `None` → 401.

Tests always override:
```python
app.dependency_overrides[verify_token] = lambda: {"id": "test-user", "premium": True}
```

`auth.py` endpoints take **individual params**, not Pydantic models:
```python
@router.post("/register")
async def register(email: str, password: str):
```
Send as JSON fields or form data, not nested.

## Endpoints

| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/v1/health` | Ollama root url + Supabase session |
| POST | `/api/v1/auth/register` | Proxy Supabase Auth |
| POST | `/api/v1/auth/login` | Returns `access_token` |
| POST | `/api/v1/passwords/evaluate` | 3 dimensions (entropy + AI + HIBP) |
| POST | `/api/v1/passwords/generate` | 2 modes: `ai` (default) or `random`; AI supports style/word_count/theme/personal_words |

## Evaluate (3 dimensions)

1. **Entropy**: `H = L × log₂(R)`. `app/services/entropy.py`. Umbral: 60 bits. R=95 para charset completo (26+26+10+33).
2. **AI**: Ollama or Groq → `ai_score`, `ai_feedback` (Spanish), `ai_suggestions`. JSON parse chain: direct → regex → repair → entropy-based fallback.
3. **HIBP**: SHA-1 k-anonymity. Only first 5 hex chars sent.

## Generate

- **AI mode**: retries up to 3 times if entropy < 60 bits. Routes `passwords.py:84-111`.
- **Random mode**: `secrets` module via `random_generator.py`. Accepts charset toggles (upper/lower/digits/symbols).

## External services

| Service | URL (base) | Timeout | Path appended in | Notes |
|---------|-----------|---------|------------------|-------|
| Ollama | `settings.ollama_url` = `http://localhost:11434` | 30s | `ai_engine.py` adds `/api/generate` | Model `llama3.2:3b`, `format: "json"` required |
| Groq | `https://api.groq.com/openai/v1/chat/completions` | 30s | — | Only when `AI_BACKEND=groq` in `.env`. Model `llama-3.1-8b-instant` (configurable via `GROQ_MODEL`). API key from `GROQ_API_KEY`. OpenAI-compatible format. |
| HIBP | `settings.hibp_api_url` = `https://api.pwnedpasswords.com` | default | `hibp_client.py` adds `/range/{prefix}` | Header `Add-Padding: true` |
| Supabase | from `.env` | default | — | Singleton, lazy init |

Health endpoint calls Ollama at root (`settings.ollama_url`), not `/api/generate`.
AI backend routing: `settings.ai_backend` = "ollama" (default) or "groq". Switch by changing `.env`.

## Tests

No `conftest.py`. Each test file defines own fixtures. Pattern:

```python
@pytest.fixture
def client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")
```

Tests with `@pytest.mark.asyncio`. External HTTP mocked with `respx` context manager.

AI backend tests use `ollama_backend` / `groq_backend` fixtures that set `settings.ai_backend` directly (not dependent on `.env`). Defined inside `test_ai_engine.py`.

**Categories:**

| Dir | What | How |
|-----|------|-----|
| `test_ai_engine.py` | Ollama + Groq parsing | respx mock at respective API URLs; `ollama_backend`/`groq_backend` fixtures toggle backend |
| `test_api_evaluate.py`, `test_api_generate.py` | Endpoint integration | ASGITransport + dependency override |
| `test_auth_invalid.py` | 401 with invalid token | No override, real Bearer token sent |
| `test_entropy.py` | Formula correctness | Pure unit (duplicates `calculate`) |
| `test_exceptions.py` | Exception classes + handlers | Constructor asserts + handler JSON response |
| `test_fault_tolerance.py` | HIBP down, AI down | respx mock for external failures |
| `test_generator.py` | 10 parametrized passwords | Parametrize, entropy ≥ 60 |
| `test_health.py`, `test_health_advanced.py` | Health endpoint | respx mock for Ollama down + up |
| `test_hibp_client.py` | SHA-1 prefix + integration | Pure unit + respx mock for found/not-found |
| `test_ollama.py` | Real Ollama | `@pytest.mark.skip` — manual only |
| `test_passwords_advanced.py` | AI personalization params | Style/theme/word_count/personal_words + retry exhaustion |
| `test_performance.py` | Latency | `@pytest.mark.skip` — manual only |
| `test_random_generator.py` | Unit | 13 tests, 100% branch |

**Coverage:** 88% (target 70%). Uncovered: `auth.py` (33% — needs real Supabase), `db_client.py` line 21-22 (exception handler), `health.py` lines 16-17 (Ollama connection error path), `ai_engine.py` lines 143-146 (broken JSON brace extraction fallback).

## Style

- Spanish user-facing text (tildes, ortografía correcta).
- `sparkgate.*` loggers at INFO. Services use `logger = logging.getLogger("sparkgate.{name}")`.
- `.env` gitignored. Never commit.
- Chrome extension separate repo.
