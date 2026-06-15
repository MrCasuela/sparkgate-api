import pytest
from app.services import random_generator


class TestRandomGenerator:
    def test_default_length(self):
        pwd = random_generator.generate()
        assert len(pwd) == 16

    def test_custom_length(self):
        pwd = random_generator.generate(length=24)
        assert len(pwd) == 24

    def test_min_length(self):
        pwd = random_generator.generate(length=12)
        assert len(pwd) == 12

    def test_max_length(self):
        pwd = random_generator.generate(length=64)
        assert len(pwd) == 64

    def test_all_charsets_included(self):
        pwd = random_generator.generate(length=64)
        assert any(c.islower() for c in pwd)
        assert any(c.isupper() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(not c.isalnum() for c in pwd)

    def test_no_lowercase(self):
        pwd = random_generator.generate(length=16, use_lower=False)
        assert not any(c.islower() for c in pwd)

    def test_no_uppercase(self):
        pwd = random_generator.generate(length=16, use_upper=False)
        assert not any(c.isupper() for c in pwd)

    def test_no_digits(self):
        pwd = random_generator.generate(length=16, use_digits=False)
        assert not any(c.isdigit() for c in pwd)

    def test_no_symbols(self):
        pwd = random_generator.generate(length=16, use_symbols=False)
        assert not any(not c.isalnum() for c in pwd)

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="Length must be between"):
            random_generator.generate(length=4)

    def test_too_long_raises(self):
        with pytest.raises(ValueError, match="Length must be between"):
            random_generator.generate(length=100)

    def test_no_charset_raises(self):
        with pytest.raises(ValueError, match="At least one character set"):
            random_generator.generate(length=16, use_lower=False, use_upper=False, use_digits=False, use_symbols=False)

    def test_passwords_unique(self):
        pwds = {random_generator.generate() for _ in range(100)}
        assert len(pwds) > 90  # occasional collisions possible, but should be rare
