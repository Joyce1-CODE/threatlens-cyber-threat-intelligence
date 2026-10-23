import time
from typing import Dict, Tuple, Optional, Any
from threading import Lock

from app.providers.base import ProviderResult

class ProviderCache:
    """
    In-memory thread-safe TTL cache for threat intelligence lookups.
    Reduces redundant external API calls to conserve rate limits and quotas.
    """
    def __init__(self, max_size: int = 1000, default_ttl: int = 600):
        self._cache: Dict[Tuple[str, str, str], Tuple[ProviderResult, float]] = {}
        self._lock = Lock()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def get(self, provider_name: str, indicator_type: str, indicator: str) -> Optional[ProviderResult]:
        key = (provider_name.lower(), indicator_type.lower(), indicator.lower())
        now = time.time()

        with self._lock:
            if key in self._cache:
                result, expires_at = self._cache[key]
                if now < expires_at:
                    self._hits += 1
                    # Return copy marked as cached
                    cached_result = result.model_copy()
                    cached_result.cached = True
                    return cached_result
                else:
                    # Expired
                    del self._cache[key]

            self._misses += 1
            return None

    def set(
        self,
        provider_name: str,
        indicator_type: str,
        indicator: str,
        result: ProviderResult,
        ttl_seconds: Optional[int] = None
    ) -> None:
        # Only cache conclusive states; do not cache transient errors or rate limits
        if result.status not in ("success", "clean", "not_found"):
            return

        key = (provider_name.lower(), indicator_type.lower(), indicator.lower())
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        expires_at = time.time() + ttl

        with self._lock:
            if len(self._cache) >= self._max_size:
                # Evict expired entries first
                now = time.time()
                expired_keys = [k for k, (_, exp) in self._cache.items() if now >= exp]
                for k in expired_keys:
                    del self._cache[k]
                # If still at capacity, evict oldest 20%
                if len(self._cache) >= self._max_size:
                    keys_to_remove = list(self._cache.keys())[: max(1, self._max_size // 5)]
                    for k in keys_to_remove:
                        del self._cache[k]

            self._cache[key] = (result, expires_at)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            now = time.time()
            active_count = sum(1 for _, exp in self._cache.values() if now < exp)
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100.0) if total_requests > 0 else 0.0
            return {
                "active_entries": active_count,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate_pct": round(hit_rate, 2),
                "max_size": self._max_size,
                "default_ttl_seconds": self._default_ttl,
            }

# Global singleton cache
provider_cache = ProviderCache()
