import logging
import threading
import time

logger = logging.getLogger("sparkgate.cache")


class TTLCache:
    """Thread-safe TTL cache with no external dependencies.

    Options: maxsize (drop oldest when full) and ttl in seconds.
    """

    def __init__(self, maxsize: int = 1024, ttl: float = 3600.0):
        self._maxsize = maxsize
        self._ttl = ttl
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            value, expires = item
            if time.monotonic() > expires:
                del self._data[key]
                return None
            return value

    def set(self, key, value) -> None:
        with self._lock:
            now = time.monotonic()
            if len(self._data) >= self._maxsize and key not in self._data:
                self._evict_expired(now)
            if len(self._data) >= self._maxsize and key not in self._data:
                try:
                    del self._data[next(iter(self._data))]
                except StopIteration:
                    pass
            self._data[key] = (value, now + self._ttl)

    def _evict_expired(self, now: float) -> None:
        expired = [k for k, (_, expires) in self._data.items() if now > expires]
        for k in expired:
            del self._data[k]

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


# Full result of POST /passwords/evaluate for repeated identical inputs.
evaluate_cache = TTLCache(maxsize=1024, ttl=3600.0)
# HIBP k-anonymity responses grouped by SHA-1 5-hex prefix.
hibp_cache = TTLCache(maxsize=512, ttl=86400.0)


def clear_caches() -> None:
    evaluate_cache.clear()
    hibp_cache.clear()