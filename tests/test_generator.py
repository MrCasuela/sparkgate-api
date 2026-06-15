import math
import pytest


def calculate_entropy(password: str) -> float:
    L = len(password)
    R = 0
    if any(c.islower() for c in password):
        R += 26
    if any(c.isupper() for c in password):
        R += 26
    if any(c.isdigit() for c in password):
        R += 10
    if any(not c.isalnum() for c in password):
        R += 33
    return L * math.log2(R) if R > 0 else 0.0


@pytest.mark.parametrize("password", [
    "CaballoAzul#72",
    "MariposaRoja!5",
    "SolNaciente*88",
    "MontañaVerde_21",
    "RioProfundo?33",
    "LunaPlateada#99",
    "VientoFuerte!77",
    "FuegoAzul*44",
    "TierraFertil#66",
    "MarTranquilo_11",
])
def test_generated_password_entropy(password):
    h = calculate_entropy(password)
    assert h >= 60.0, f"Password '{password}' has entropy {h:.2f} bits, below 60 bit threshold"
