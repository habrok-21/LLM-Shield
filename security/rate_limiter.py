"""
ShieldLLM — Sliding-Window Token Budget Rate Limiter.

Tracks token consumption per identity (IP / User-ID) within a rolling
time window. When a caller exceeds the configured budget they receive
a 429 Too Many Requests response, defeating Denial-of-Wallet attacks.

Thread-safe via a per-identity reentrant lock.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Tuple


class TokenBucketRateLimiter:
    """Sliding-window rate limiter keyed by caller identity.

    Each identity tracks a list of (timestamp, token_count) tuples
    within a rolling window. Old entries are pruned on every check.
    """

    def __init__(
        self,
        window_seconds: int = 60,
        max_tokens: int = 400,
    ):
        self._window = window_seconds
        self._max_tokens = max_tokens
        self._buckets: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, identity: str, tokens: int = 1) -> bool:
        """Check and record token usage for `identity`.

        Returns True if the caller is within budget, False if they
        should be throttled (429).
        """
        with self._lock:
            self._prune(identity)
            usage = sum(c for _, c in self._buckets[identity])
            if usage + tokens > self._max_tokens:
                return False
            self._buckets[identity].append((time.time(), tokens))
            return True

    def get_usage(self, identity: str) -> int:
        """Return the current token count for `identity` within the window."""
        with self._lock:
            self._prune(identity)
            return sum(c for _, c in self._buckets[identity])

    def get_remaining(self, identity: str) -> int:
        """Return the remaining token budget for `identity`."""
        return max(0, self._max_tokens - self.get_usage(identity))

    def get_reset_in(self, identity: str) -> float:
        """Return the seconds until the oldest entry expires."""
        with self._lock:
            self._prune(identity)
            if not self._buckets[identity]:
                return 0.0
            oldest_ts = self._buckets[identity][0][0]
            return max(0.0, self._window - (time.time() - oldest_ts))

    def reset(self, identity: str) -> None:
        """Clear all usage data for a single identity."""
        with self._lock:
            self._buckets.pop(identity, None)

    def reset_all(self) -> None:
        """Clear all usage data (use sparingly)."""
        with self._lock:
            self._buckets.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _prune(self, identity: str) -> None:
        """Remove entries outside the sliding window."""
        cutoff = time.time() - self._window
        bucket = self._buckets[identity]
        while bucket and bucket[0][0] < cutoff:
            bucket.pop(0)
        if not bucket:
            self._buckets.pop(identity, None)

    @property
    def window_seconds(self) -> int:
        return self._window

    @window_seconds.setter
    def window_seconds(self, value: int) -> None:
        self._window = value

    @property
    def max_tokens(self) -> int:
        return self._max_tokens

    @max_tokens.setter
    def max_tokens(self, value: int) -> None:
        self._max_tokens = value

    @property
    def config(self) -> dict:
        return {
            "window_seconds": self._window,
            "max_tokens": self._max_tokens,
        }
