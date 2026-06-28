"""
ShieldLLM — Streaming SSE Inspector.

Intercepts Server-Sent Events (SSE) from upstream LLM streaming
responses. Accumulates content tokens on the fly and runs egress
checks against the partial response. If a policy violation is
detected mid-stream, the inspector signals termination so the
proxy can emit an error event instead of forwarding the violation.
"""

import json
import re
import logging
from typing import Optional, Tuple

from .egress import EgressResult, check_egress
from . import exfiltration
from . import safety
from . import cyber

logger = logging.getLogger("shieldllm.streaming")

SSE_DATA_RE = re.compile(r"^data:\s*(.+)")


class StreamInspector:
    """Accumulates streaming tokens and inspects them for policy violations.

    Usage:
        inspector = StreamInspector()
        async for chunk in upstream_stream:
            action, data = inspector.feed(chunk)
            if action == "forward":
                yield data
            elif action == "error":
                yield error_event
                break
    """

    def __init__(self):
        self._accumulated = ""
        self._violation: Optional[str] = None
        self._finished = False

    def feed(self, raw_chunk: bytes) -> Tuple[str, Optional[str]]:
        """Process a raw chunk from the upstream SSE stream.

        Returns (action, payload) where action is one of:
          - "forward":  payload is the original chunk (or modified) to send to client
          - "error":    payload is an error JSON to send instead
          - "done":     stream is complete, no more data
          - "skip":     internal chunk (no client payload)
        """
        if self._violation:
            return "error", self._build_error()

        text = raw_chunk.decode("utf-8", errors="replace")

        # Parse SSE data lines
        for line in text.split("\n"):
            m = SSE_DATA_RE.match(line)
            if not m:
                if line.strip() == "data: [DONE]":
                    self._finished = True
                    return "forward", raw_chunk
                continue

            payload = m.group(1).strip()
            if payload == "[DONE]":
                self._finished = True
                return "forward", raw_chunk

            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                continue

            # Accumulate content delta
            choices = event.get("choices", [])
            for choice in choices:
                delta = choice.get("delta", {})
                content = delta.get("content", "")
                if content:
                    self._accumulated += content

            # Check accumulated content for violations
            result = EgressResult()
            check_egress(self._accumulated, result)

            # AI security: exfiltration, safety, contradiction
            if self._accumulated:
                exfil = exfiltration.check_exfiltration(self._accumulated)
                if exfil:
                    result.reject(exfil)
                safe = safety.check_safety(self._accumulated)
                if safe:
                    result.reject(safe)
                contra = safety.check_contradiction(self._accumulated)
                if contra:
                    result.reject(contra)

                # Cyber security: internal leakage, malicious URLs, XSS, command injection
                inet = cyber.check_internal_leakage(self._accumulated)
                if inet:
                    result.reject(inet)
                malurl = cyber.check_malicious_url(self._accumulated)
                if malurl:
                    result.reject(malurl)
                xss = cyber.check_xss(self._accumulated)
                if xss:
                    result.reject(xss)
                cmdi = cyber.check_command_injection(self._accumulated)
                if cmdi:
                    result.reject(cmdi)

            if result.flagged:
                self._violation = "; ".join(result.reasons)
                logger.warning(
                    "stream_violation accumulated_len=%d reasons=%s",
                    len(self._accumulated),
                    self._violation,
                )
                return "error", self._build_error()

        return "forward", raw_chunk

    @property
    def accumulated(self) -> str:
        return self._accumulated

    @property
    def violation(self) -> Optional[str]:
        return self._violation

    @property
    def finished(self) -> bool:
        return self._finished

    def _build_error(self) -> str:
        error_event = {
            "error": {
                "message": f"ShieldLLM blocked: {self._violation}",
                "type": "policy_violation",
                "code": "egress_blocked_stream",
            }
        }
        return f"data: {json.dumps(error_event)}\n\ndata: [DONE]\n\n"
