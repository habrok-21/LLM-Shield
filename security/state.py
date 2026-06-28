import threading
import time
from collections import deque
from typing import Dict, List


class StatsTracker:
    def __init__(self, max_history: int = 5000):
        self._lock = threading.RLock()
        self._total_requests = 0
        self._ingress_blocks = 0
        self._egress_blocks = 0
        self._rate_limits = 0
        self._cache_hits = 0
        self._upstream_errors = 0
        self._allowed = 0
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0
        self._event_history: deque = deque(maxlen=max_history)
        self._token_history: deque = deque(maxlen=120)
        self._start_time = time.time()

    def record_request(self):
        with self._lock:
            self._total_requests += 1

    def record_ingress_block(self, prompt_tokens: int = 0):
        with self._lock:
            self._ingress_blocks += 1
            self._total_prompt_tokens += prompt_tokens

    def record_egress_block(self, prompt_tokens: int = 0, completion_tokens: int = 0):
        with self._lock:
            self._egress_blocks += 1
            self._total_prompt_tokens += prompt_tokens
            self._total_completion_tokens += completion_tokens

    def record_rate_limit(self, prompt_tokens: int = 0):
        with self._lock:
            self._rate_limits += 1
            self._total_prompt_tokens += prompt_tokens

    def record_cache_hit(self):
        with self._lock:
            self._cache_hits += 1

    def record_upstream_error(self):
        with self._lock:
            self._upstream_errors += 1

    def record_allowed(self, prompt_tokens: int = 0, completion_tokens: int = 0):
        with self._lock:
            self._allowed += 1
            self._total_prompt_tokens += prompt_tokens
            self._total_completion_tokens += completion_tokens
            now = time.time()
            self._token_history.append({
                "time": now,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            })

    def push_event(self, event: dict):
        with self._lock:
            event["_time"] = time.time()
            self._event_history.append(dict(event))

    def clear_events(self):
        with self._lock:
            self._event_history.clear()

    @property
    def snapshot(self) -> dict:
        with self._lock:
            uptime = time.time() - self._start_time
            recent_tokens = list(self._token_history)
            recent_events = list(self._event_history)[-100:]
            return {
                "uptime_seconds": round(uptime, 1),
                "total_requests": self._total_requests,
                "ingress_blocks": self._ingress_blocks,
                "egress_blocks": self._egress_blocks,
                "rate_limits": self._rate_limits,
                "cache_hits": self._cache_hits,
                "upstream_errors": self._upstream_errors,
                "allowed": self._allowed,
                "total_prompt_tokens": self._total_prompt_tokens,
                "total_completion_tokens": self._total_completion_tokens,
                "total_tokens": self._total_prompt_tokens + self._total_completion_tokens,
                "token_history": recent_tokens,
                "recent_events": recent_events,
            }


stats = StatsTracker()
