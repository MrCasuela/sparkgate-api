import time

import pytest

from app.services.cache import TTLCache


def test_set_get_roundtrip():
    cache = TTLCache(maxsize=10, ttl=60)
    cache.set("k", {"a": 1})
    assert cache.get("k") == {"a": 1}


def test_get_missing_returns_none():
    cache = TTLCache(maxsize=10, ttl=60)
    assert cache.get("missing") is None


def test_get_expired_returns_none():
    cache = TTLCache(maxsize=10, ttl=0.05)
    cache.set("k", "v")
    time.sleep(0.08)
    assert cache.get("k") is None


def test_set_drops_oldest_when_full():
    cache = TTLCache(maxsize=2, ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.get("a") is None
    assert cache.get("b") == 2
    assert cache.get("c") == 3


def test_set_replaces_existing_key_without_eviction():
    cache = TTLCache(maxsize=2, ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("a", 99)
    assert cache.get("a") == 99
    assert cache.get("b") == 2


def test_get_purges_expired_entry():
    cache = TTLCache(maxsize=10, ttl=0.05)
    cache.set("old", 1)
    time.sleep(0.08)
    assert cache.get("old") is None
    cache.set("new", 2)
    assert cache.get("new") == 2


def test_clear_empties():
    cache = TTLCache(maxsize=10, ttl=60)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.clear()
    assert cache.get("a") is None
    assert cache.get("b") is None


def test_clear_caches_global():
    from app.services.cache import evaluate_cache, hibp_cache, clear_caches

    evaluate_cache.set(("evaluate", "x", "", "ollama", 1), {})
    hibp_cache.set(("hibp", "ABCDE"), {"F": 1})
    clear_caches()
    assert evaluate_cache.get(("evaluate", "x", "", "ollama", 1)) is None
    assert hibp_cache.get(("hibp", "ABCDE")) is None


def test_evaluate_cache_key_hashes_password():
    """Cache key must not embed the plaintext password (CU05 RNF privacidad)."""
    from app.api.routes.passwords import _evaluate_cache_key

    key1 = _evaluate_cache_key("secretpass123!", None)
    key2 = _evaluate_cache_key("secretpass123!", None)
    key3 = _evaluate_cache_key("secretpass123!", "banco")
    assert key1 == key2
    assert key1 != key3
    assert not any("secretpass123!" in str(part) for part in key1)
    assert len(key1[1]) == 64