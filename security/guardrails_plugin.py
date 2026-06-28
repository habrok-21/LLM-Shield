"""
ShieldLLM — Optional Guardrails AI Plugin.

Wraps Guardrails AI (https://github.com/guardrails-ai/guardrails) as an
optional deep-inspection layer for both ingress and egress.

ShieldLLM's built-in filters handle the fast path (<1ms) for 90% of
attacks. This plugin runs Guardrails AI validators on the remaining
traffic for deeper ML-powered analysis.

Install:  pip install guardrails-ai
Enable:   export GUARDRAILS_ENABLED=true
"""

import logging
import os
from typing import Optional

logger = logging.getLogger("shieldllm.guardrails_plugin")

GUARDRAILS_ENABLED = os.environ.get("GUARDRAILS_ENABLED", "").lower() in (
    "1", "true", "yes"
)

_guard = None


def _load():
    """Lazy-load Guardrails AI."""
    global _guard
    try:
        from guardrails import Guard
        from guardrails.hub import (
            DetectJailbreak,
            ToxicLanguage,
        )

        _guard = Guard()
        _guard.use(
            DetectJailbreak(
                llm_fallback=False,
                on_fail="exception",
            )
        )
        _guard.use(
            ToxicLanguage(
                threshold=0.5,
                validation_method="sentence",
                on_fail="exception",
            )
        )
        logger.info("guardrails_plugin loaded validators: DetectJailbreak, ToxicLanguage")
        return True
    except ImportError:
        logger.info("guardrails_plugin not available (install guardrails-ai)")
        return False
    except Exception as exc:
        logger.warning("guardrails_plugin init error: %s", exc)
        return False


def check_prompt(text: str) -> Optional[str]:
    """Check a single prompt string with Guardrails AI validators.

    Returns violation string or None.
    """
    if not GUARDRAILS_ENABLED:
        return None

    global _guard
    if _guard is None:
        if not _load():
            return None

    try:
        result = _guard.validate(text)
        if not result.valid:
            reasons = "; ".join(result.failures)
            logger.info("guardrails_plugin blocked reason=%s", reasons)
            return f"Guardrails AI: {reasons}"
        return None
    except Exception as exc:
        logger.debug("guardrails_plugin error: %s", exc)
        return None


def check_response(text: str) -> Optional[str]:
    """Check a response string with Guardrails AI validators.

    Returns violation string or None.
    """
    if not GUARDRAILS_ENABLED:
        return None

    global _guard
    if _guard is None:
        if not _load():
            return None

    try:
        result = _guard.validate(text)
        if not result.valid:
            reasons = "; ".join(result.failures)
            logger.info("guardrails_plugin blocked response reason=%s", reasons)
            return f"Guardrails AI: {reasons}"
        return None
    except Exception as exc:
        logger.debug("guardrails_plugin response error: %s", exc)
        return None


def is_available() -> bool:
    if not GUARDRAILS_ENABLED:
        return False
    if _guard is None:
        return _load()
    return True
