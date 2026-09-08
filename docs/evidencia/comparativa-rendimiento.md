# Comparativa de rendimiento — CPU vs GPU (+ tuning + cache)

Fecha: 2026-09-07. Hardware: Ryzen 12 hilos · GTX 1650 Ti Mobile 4 GB · Ollama 0.30.8 · llama3.2:3b.

## Contexto

Baseline previo corriendo completamente en CPU (Ollama sin GPU). Optimización aplicada:

1. **GPU**: GTX 1650 Ti activada con los drivers NVIDIA actualizados. Modelo residente en GPU (100% offload, 2.1 GB de 4 GB VRAM).
2. **Tuning** (`app/services/ai_engine.py`): `num_ctx` 2048→1024, `num_thread` 12, `num_predict` acotado por propósito.
3. **Caché**: evaluate (TTL 1h, key por password+context+backend+versión de prompt) y HIBP (TTL 24h, por prefijo SHA-1). `generate` **nunca** se cachea.

## Números medidos (vía ruta HTTP con auth override)

| Medición | CPU baseline | GPU + tuning | Caché | Delta |
|---|---|---|---|---|
| Generate AI (avg, n=5) | 10.63 s | 1.57 s | n/a (no caché) | −85 % |
| Evaluate AI cold (avg, n=3) | 15.88 s (solo Ollama) | 2.76 s | n/a | −74 % |
| Evaluate cached | n/a | — | 0.001 s | ~0 ms |
| Ollama /api/generate directo (con opciones de prod, 160 tokens) | 15.88 s | 3.2 s @ 59 tok/s | n/a | −80 % |

Nota: las muestras de evaluate cold arrancan y terminan con HIBP real + Ollama en GPU residente; primera carga fría del modelo cuesta ~15 s extra (una sola vez, hasta que expira el keep_alive).

## Consumo GPU (durante carga del modelo)

```
nvidia-smi: 2117 MiB / 4096 MiB usados · 100% GPU · temperatura ~57°C
ollama ps:  llama3.2:3b 2.1 GB 100% GPU  ctx=1024
```

## Umbrales de aceptación (PT10)

| Criterio | Umbral | GPU+ tuning | Cumple |
|---|---|---|---|
| Evaluate promedio < 5 s | 5.0 s | ~2.8 s (cold) | ✅ |
| Generate promedio < 3 s | 3.0 s | 1.57 s | ✅ |
| Haz pequeño el límite real (num_predict truncaba JSON a 80 tok → subido a 200) | — | JSON parsea completo | ✅ |

## Hallazgos

- **ctx coherente**: Ollama recompila/reasigna KV al cambiar `num_ctx` entre peticiones (~5 s extra). Mantener 1024 en todos los paths de producción evita el golpe. `tests/test_ollama.py` ahora usa las mismas opciones que la app.
- **Caché evaluate**: respuesta completa desde memoria (~1 ms); `AI_EVALUATE_VERSION` invalida si cambian prompts.
- **Calidad preservada**: mismo modelo llama3.2:3b, sin cambiar prompts; solo se acotó salida. Verificado: ai_score semántico real (83–85) en evaluate, generación `attempts=1`.

Reproducción: `SPARKGATE_RUN_MANUAL=1 pytest tests/test_ollama.py tests/test_performance.py` (modelo caliente).