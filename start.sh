#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== SparkGate API — Start ==="

# 1. Verificar .env
if [ ! -f .env ]; then
    echo "[ERROR] .env file not found. Copy .env.example to .env and fill credentials."
    exit 1
fi

# 2. Activar virtualenv
if [ ! -d .venv ]; then
    echo "[...] Creating virtualenv..."
    python3 -m venv .venv
fi
source .venv/bin/activate

# 3. Instalar dependencias
pip install -q -r requirements.txt

# 4. Verificar Ollama
if curl -sf http://localhost:11434 > /dev/null 2>&1; then
    echo "[OK]   Ollama running"
else
    echo "[WARN] Ollama not running. Starting..."
    ollama serve &
    sleep 3
    if ! curl -sf http://localhost:11434 > /dev/null 2>&1; then
        echo "[ERROR] Failed to start Ollama"
        exit 1
    fi
fi

# 5. Verificar modelo
if ! ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
    echo "[...] Pulling llama3.2:3b (first time only)..."
    ollama pull llama3.2:3b
fi

# 6. Iniciar backend
echo "[OK]   Starting SparkGate API on http://localhost:8000"
echo "[OK]   Docs at http://localhost:8000/docs"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
