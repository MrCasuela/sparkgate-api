import math


MIN_ENTROPY_BITS = 60.0


def calculate(password: str) -> float:
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


def meets_threshold(password: str) -> bool:
    return calculate(password) >= MIN_ENTROPY_BITS
