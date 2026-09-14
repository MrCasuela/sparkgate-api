import os
from pathlib import Path

import pytest

from app.services import ai_engine

RUN_MANUAL = os.environ.get("SPARKGATE_RUN_MANUAL") == "1"

PREDICTABLE_THRESHOLD = 50

DATASET = [
    {"password": "Juanito2026", "predictable": True},
    {"password": "maria1998", "predictable": True},
    {"password": "felipe2005", "predictable": True},
    {"password": "Password123", "predictable": True},
    {"password": "qwerty12345", "predictable": True},
    {"password": "luna2019", "predictable": True},
    {"password": "primera123", "predictable": True},
    {"password": "madrid2024", "predictable": True},
    {"password": "familia1509", "predictable": True},
    {"password": "gato123", "predictable": True},
    {"password": "VientoAzul#84Luna", "predictable": False},
    {"password": "CuadernoMar$7Oso", "predictable": False},
    {"password": "R%ioFrio93Ventana", "predictable": False},
    {"password": "Montana+51Aguila", "predictable": False},
    {"password": "BosqueLuz@67Tigre", "predictable": False},
    {"password": "X9tR#3nO8sP", "predictable": False},
    {"password": "Km#4Lago77Sol", "predictable": False},
    {"password": "Hielo%21RioFuerte", "predictable": False},
    {"password": "Torre&Dorada48Pradera", "predictable": False},
    {"password": "Roca~12AzulLago", "predictable": False},
]


def _classify(ai_score: int | None) -> bool:
    """Map model score to a binary predictable verdict. None = classification miss."""
    if ai_score is None:
        return False
    return ai_score < PREDICTABLE_THRESHOLD


@pytest.mark.skipif(not RUN_MANUAL, reason="Requires Ollama running locally — run with SPARKGATE_RUN_MANUAL=1")
@pytest.mark.asyncio
async def test_semantic_classification_precision_85():
    """PT14 / OE3: ≥85% precision over 20 labeled passwords (10 predictable, 10 not)."""
    results, correct = [], 0
    for item in DATASET:
        result = await ai_engine.evaluate_security(item["password"], False)
        score = result["ai_score"]
        got = _classify(score)
        ok = got == item["predictable"]
        correct += ok
        results.append((item["password"], item["predictable"], score, got, ok))

    total = len(DATASET)
    precision = correct / total
    evidence_lines = [
        f"PT14 - Precision semantica (OE3) - {__import__('datetime').date.today().isoformat()}",
        f"Dataset: {total} passwords ({sum(1 for d in DATASET if d['predictable'])} predecibles, {sum(1 for d in DATASET if not d['predictable'])} no predecibles)",
        f"Correctas: {correct}/{total} = {precision:.0%} (umbral >= 85%)",
        "",
    ]
    for password, expected, score, got, ok in results:
        evidence_lines.append(
            f"{'OK ' if ok else 'FAIL'} predictible={expected} got={got} score={score} :: {password}"
        )

    report_path = Path("docs/evidencia/pt14-accuracy.txt")
    report_path.write_text("\n".join(evidence_lines) + "\n", encoding="utf-8")

    assert precision >= 0.85, (
        f"Precision {precision:.0%} ({correct}/{total}) < 85%. Detalle en {report_path}"
    )