import math

import pytest


def calculate_entropy(password: str) -> float:
    L = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    R = 0
    if has_lower:
        R += 26
    if has_upper:
        R += 26
    if has_digit:
        R += 10
    if has_symbol:
        R += 33

    if R == 0:
        return 0.0
    return L * math.log2(R)


class TestEntropy:
    def test_lowercase_only(self):
        h = calculate_entropy("abcdefgh")
        expected = 8 * math.log2(26)
        assert abs(h - expected) < 0.01

    def test_mixed_case(self):
        h = calculate_entropy("AbCdEfGh")
        expected = 8 * math.log2(52)
        assert abs(h - expected) < 0.01

    def test_full_complexity(self):
        h = calculate_entropy("Ab1!xY9#")
        expected = 8 * math.log2(95)
        assert abs(h - expected) < 0.01

    def test_60_bit_threshold(self):
        h = calculate_entropy("CaballoAzul#72")
        assert h >= 60.0

    def test_empty_string(self):
        assert calculate_entropy("") == 0.0
