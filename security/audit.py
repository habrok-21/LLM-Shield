"""
ShieldLLM — Structured Security Audit Logging.

Produces JSON-formatted log records to stdout for ingestion by
cloud monitoring tools (AWS CloudWatch, Datadog, Grafana Loki, etc.).

Every security event includes:
  - timestamp (ISO-8601)
  - masked_client_ip  (last octet zeroed for privacy)
  - event_type        (INGRESS_BLOCK, EGRESS_BLOCK, RATE_LIMIT, CACHE_HIT,
                       ALLOWED, UPSTREAM_ERROR)
  - rule_triggered    (the specific rule or pattern that fired)
  - prompt_length     (character count of the user prompt)
  - token_usage       (dict: prompt, completion, total)
  - provider          (which upstream served the request)
  - request_id        (correlation id if provided)
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional


class AuditLogger:
    """Produces structured JSON audit records via the standard logging module."""

    def __init__(self, name: str = "shieldllm.audit"):
        self._logger = logging.getLogger(name)
        self._logger.setLevel(logging.INFO)

        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.INFO)

            class JSONFormatter(logging.Formatter):
                def format(self, record: logging.LogRecord) -> str:
                    return record.getMessage()

            handler.setFormatter(JSONFormatter())
            self._logger.addHandler(handler)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingress_block(
        self,
        client_ip: str,
        rule: str,
        message_count: int,
        prompt_length: int,
        request_id: Optional[str] = None,
    ) -> None:
        self._emit("INGRESS_BLOCK", client_ip, rule, prompt_length,
                   None, None, message_count, request_id)

    def egress_block(
        self,
        client_ip: str,
        rule: str,
        prompt_length: int,
        completion_length: int,
        token_usage: Optional[dict],
        request_id: Optional[str] = None,
    ) -> None:
        self._emit("EGRESS_BLOCK", client_ip, rule, prompt_length,
                   completion_length, token_usage, None, request_id)

    def rate_limit(
        self,
        client_ip: str,
        rule: str,
        prompt_length: int,
        request_id: Optional[str] = None,
    ) -> None:
        self._emit("RATE_LIMIT", client_ip, rule, prompt_length,
                   None, None, None, request_id)

    def cache_hit(
        self,
        client_ip: str,
        prompt_length: int,
        request_id: Optional[str] = None,
    ) -> None:
        self._emit("CACHE_HIT", client_ip, "semantic_cache", prompt_length,
                   None, None, None, request_id)

    def allowed(
        self,
        client_ip: str,
        prompt_length: int,
        completion_length: int,
        token_usage: dict,
        provider: str,
        request_id: Optional[str] = None,
    ) -> None:
        self._emit("ALLOWED", client_ip, None, prompt_length,
                   completion_length, token_usage, None, request_id, provider)

    def upstream_error(
        self,
        client_ip: str,
        rule: str,
        prompt_length: int,
        request_id: Optional[str] = None,
    ) -> None:
        self._emit("UPSTREAM_ERROR", client_ip, rule, prompt_length,
                   None, None, None, request_id)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _mask_ip(ip: str) -> str:
        """Mask the last octet for privacy (e.g. 192.168.1.xxx)."""
        match = re.match(r"(\d+\.\d+\.\d+)\.\d+", ip)
        if match:
            return f"{match.group(1)}.0"
        # IPv6 or hostname — truncate last segment
        parts = ip.split(":")
        if len(parts) > 2:
            return ":".join(parts[:-1]) + ":xxxx"
        return ip

    def _emit(
        self,
        event_type: str,
        client_ip: str,
        rule: Optional[str],
        prompt_length: int,
        completion_length: Optional[int],
        token_usage: Optional[dict],
        message_count: Optional[int],
        request_id: Optional[str],
        provider: Optional[str] = None,
    ) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "shieldllm_event": event_type,
            "masked_client_ip": self._mask_ip(client_ip),
        }

        if rule:
            record["rule_triggered"] = rule
        if prompt_length is not None:
            record["prompt_length"] = prompt_length
        if completion_length is not None:
            record["completion_length"] = completion_length
        if token_usage:
            record["token_usage"] = token_usage
        if message_count is not None:
            record["message_count"] = message_count
        if request_id:
            record["request_id"] = request_id
        if provider:
            record["provider"] = provider

        self._logger.info(json.dumps(record, default=str))
