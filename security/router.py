"""
ShieldLLM — Dynamic Fallback / Routing Module.

Provides automatic failover between upstream LLM providers.
If the primary endpoint returns a 429 (rate-limited), 5xx, or
times out, the Router will attempt the backup endpoint.

Supports a simple circuit-breaker pattern to avoid hammering a
failing primary endpoint on every request.
"""

import logging
import os
import threading
import time
from typing import Dict, Optional, Tuple

import httpx

logger = logging.getLogger("shieldllm.router")

# CHANGE_ME (optional): Set defaults or use env vars LLM_PRIMARY_URL / LLM_BACKUP_URL
PRIMARY_URL = os.environ.get(
    "LLM_PRIMARY_URL",
    "https://api.openai.com/v1/chat/completions",
)
BACKUP_URL = os.environ.get(
    "LLM_BACKUP_URL",
    "https://api.deepseek.com/v1/chat/completions",
)

REQUEST_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "30"))
CIRCUIT_BREAKER_RESET = int(os.environ.get("CB_RESET_SECONDS", "300"))
CIRCUIT_BREAKER_THRESHOLD = int(os.environ.get("CB_THRESHOLD", "3"))


class Router:
    """Routes requests to primary or backup LLM endpoints.

    Simple circuit-breaker: after `threshold` consecutive failures on
    the primary, it switches to backup-only mode for `reset_seconds`
    before probing the primary again.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._primary_failures = 0
        self._circuit_open = False
        self._circuit_opened_at: float = 0.0
        self._backup_failures = 0
        self._primary_url = PRIMARY_URL
        self._backup_url = BACKUP_URL
        self._timeout = REQUEST_TIMEOUT
        self._cb_threshold = CIRCUIT_BREAKER_THRESHOLD
        self._cb_reset = CIRCUIT_BREAKER_RESET

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stream_target(self) -> Tuple[Optional[str], str]:
        """Return (url, provider) for streaming, respecting circuit breaker.

        Returns (None, "") if the circuit is open and no backup is configured.
        Thread-safe.
        """
        with self._lock:
            if self._circuit_open:
                if time.time() - self._circuit_opened_at > self._cb_reset:
                    self._circuit_open = False
                    self._primary_failures = 0
                elif not self._backup_url:
                    return None, ""
                else:
                    return self._backup_url, "backup"
            return self._primary_url, "primary"

    async def forward(
        self,
        headers: Dict[str, str],
        body: dict,
        client: httpx.AsyncClient,
    ) -> Tuple[int, dict, str]:
        """Send the request to the best available upstream.

        Returns (status_code, response_json, provider_name).
        On total failure returns (503, error_body, "none").
        """
        # Check circuit breaker (atomic under lock)
        with self._lock:
            if self._circuit_open:
                if time.time() - self._circuit_opened_at > self._cb_reset:
                    logger.info("circuit_breaker probing primary again")
                    self._circuit_open = False
                    self._primary_failures = 0
                    use_backup = False
                else:
                    logger.info("circuit_breaker open, routing to backup")
                    use_backup = True
            else:
                use_backup = False

        if use_backup:
            return await self._try_backup(headers, body, client)

        # Try primary
        status, data, ok = await self._try_endpoint(
            self._primary_url, headers, body, client, "primary"
        )

        # Update state atomically to avoid TOCTOU races
        with self._lock:
            if ok:
                self._primary_failures = 0
            else:
                self._primary_failures += 1
                if self._primary_failures >= self._cb_threshold and not self._circuit_open:
                    self._circuit_open = True
                    self._circuit_opened_at = time.time()
                    logger.warning(
                        "circuit_breaker opened after %d failures",
                        self._primary_failures,
                    )

        if not ok:
            return await self._try_backup(headers, body, client)

        return status, data, "primary"

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _try_endpoint(
        self,
        url: str,
        headers: Dict[str, str],
        body: dict,
        client: httpx.AsyncClient,
        label: str,
    ) -> Tuple[int, dict, bool]:
        """Attempt a single upstream call. Returns (status, data, success)."""
        try:
            resp = await client.post(url, headers=headers, json=body,
                                     timeout=self._timeout)
            data = resp.json()
        except httpx.TimeoutException:
            logger.warning("upstream_timeout provider=%s", label)
            return 504, {"error": {"message": "Upstream timeout",
                                   "code": "upstream_timeout"}}, False
        except Exception as exc:
            logger.warning("upstream_error provider=%s error=%s", label, exc)
            return 502, {"error": {"message": "Upstream error",
                                   "code": "upstream_error"}}, False

        if resp.status_code in (429, 500, 502, 503):
            logger.warning(
                "upstream_rejected provider=%s status=%d",
                label, resp.status_code,
            )
            return resp.status_code, data, False

        return resp.status_code, data, True

    async def _try_backup(
        self,
        headers: Dict[str, str],
        body: dict,
        client: httpx.AsyncClient,
    ) -> Tuple[int, dict, str]:
        """Attempt the backup endpoint."""
        if not self._backup_url:
            logger.error("no_backup_configured")
            return 503, {
                "error": {"message": "All upstreams unavailable",
                          "code": "all_upstreams_down"}
            }, "none"

        status, data, ok = await self._try_endpoint(
            self._backup_url, headers, body, client, "backup"
        )

        with self._lock:
            if ok:
                self._backup_failures = 0
            else:
                self._backup_failures += 1

        if ok:
            return status, data, "backup"

        return 503, {
            "error": {"message": "All upstreams unavailable",
                      "code": "all_upstreams_down"}
        }, "none"

    @property
    def circuit_breaker_threshold(self) -> int:
        with self._lock:
            return self._cb_threshold

    @circuit_breaker_threshold.setter
    def circuit_breaker_threshold(self, value: int) -> None:
        with self._lock:
            self._cb_threshold = value

    @property
    def circuit_breaker_reset(self) -> int:
        with self._lock:
            return self._cb_reset

    @circuit_breaker_reset.setter
    def circuit_breaker_reset(self, value: int) -> None:
        with self._lock:
            self._cb_reset = value

    @property
    def circuit_open(self) -> bool:
        with self._lock:
            return self._circuit_open

    @circuit_open.setter
    def circuit_open(self, value: bool) -> None:
        with self._lock:
            self._circuit_open = value

    @property
    def primary_failures(self) -> int:
        with self._lock:
            return self._primary_failures

    @primary_failures.setter
    def primary_failures(self, value: int) -> None:
        with self._lock:
            self._primary_failures = value

    @property
    def backup_failures(self) -> int:
        with self._lock:
            return self._backup_failures

    @backup_failures.setter
    def backup_failures(self, value: int) -> None:
        with self._lock:
            self._backup_failures = value

    @property
    def config(self) -> dict:
        with self._lock:
            return {
                "primary_url": self._primary_url,
                "backup_url": self._backup_url,
                "timeout": self._timeout,
                "circuit_breaker_threshold": self._cb_threshold,
                "circuit_breaker_reset_seconds": self._cb_reset,
                "circuit_open": self._circuit_open,
                "primary_failures": self._primary_failures,
                "backup_failures": self._backup_failures,
            }
