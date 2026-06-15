#!/usr/bin/env bash
set -euo pipefail

echo "=== SparkGate API — Stop ==="

# Detener backend (uvicorn)
UVICORN_PID=$(pgrep -f "uvicorn app.main:app" 2>/dev/null || true)
if [ -n "$UVICORN_PID" ]; then
    kill "$UVICORN_PID" 2>/dev/null || true
    echo "[OK]   Backend stopped (PID $UVICORN_PID)"
else
    echo "[OK]   Backend not running"
fi

# Detener Ollama
OLLAMA_PID=$(pgrep -f "ollama serve" 2>/dev/null || true)
if [ -n "$OLLAMA_PID" ]; then
    kill "$OLLAMA_PID" 2>/dev/null || true
    echo "[OK]   Ollama stopped (PID $OLLAMA_PID)"
else
    echo "[OK]   Ollama not running"
fi

echo "=== Done ==="
