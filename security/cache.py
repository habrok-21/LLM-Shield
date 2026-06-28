"""
ShieldLLM — Local Static Semantic Cache.

Provides a lightweight, in-memory dictionary-based cache that stores
exact or normalized matches of user prompts. When a repeat (or near-
repeat) greeting or FAQ question is received, the cached response is
returned instantly (<1ms latency) without hitting the upstream LLM.

Use cases:
  - "Hello", "Hi there", "Good morning" → cached greeting
  - "Where is my order?" → cached FAQ response
  - Any static / deterministic interaction

The cache supports a configurable TTL and maximum entry count to
prevent unbounded memory growth.
"""

import hashlib
import json
import threading
import time
from typing import Any, Dict, Optional, Tuple


class SemanticCache:
    """A thread-safe, TTL-aware, in-memory response cache.

    The `normalize` hook allows callers to provide a custom
    normalization function (e.g., lowercase + strip punctuation +
    collapse whitespace) to improve hit rate on semantically
    identical prompts that differ cosmetically.
    """

    def __init__(
        self,
        max_entries: int = 1000,
        ttl_seconds: int = 3600,
        normalize_fn=None,
    ):
        self._max_entries = max_entries
        self._ttl = ttl_seconds
        self._normalize = normalize_fn or self._default_normalize
        self._store: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, messages: list) -> Optional[Any]:
        """Look up a cached response for the given messages.

        Returns the cached response dict or None.
        """
        key = self._make_key(messages)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            ts, value = entry
            if time.time() - ts > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, messages: list, response: Any) -> None:
        """Store a response in the cache."""
        key = self._make_key(messages)
        with self._lock:
            if len(self._store) >= self._max_entries:
                self._evict_one()
            self._store[key] = (time.time(), response)

    def invalidate(self, messages: list) -> None:
        """Remove a single entry from the cache."""
        key = self._make_key(messages)
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        """Empty the cache entirely."""
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)

    @property
    def config(self) -> dict:
        return {
            "max_entries": self._max_entries,
            "ttl_seconds": self._ttl,
            "size": self.size,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _make_key(self, messages: list) -> str:
        """Generate a normalized, hashed cache key from the message list."""
        normalized = self._normalize(messages)
        raw = json.dumps(normalized, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def _default_normalize(messages: list) -> list:
        """Default normalizer: lowercase, strip extra whitespace."""
        result = []
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, str):
                content = " ".join(content.lower().split())
            result.append({"role": role, "content": content})
        return result

    def _evict_one(self) -> None:
        """Evict the oldest entry when the cache is full."""
        oldest_key = min(self._store, key=lambda k: self._store[k][0])
        del self._store[oldest_key]
