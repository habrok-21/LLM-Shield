"""
ShieldLLM — Optional ML-Powered Prompt Injection Guard.

Provides an optional, pluggable machine-learning layer that scores
user prompts for injection / jailbreak probability using a
lightweight ONNX model running on CPU.

Two backends are supported (tried in order):
  1. ONNX Runtime (lightweight, no PyTorch needed)
  2. Transformers pipeline (fallback, requires transformers + torch)

The guard is DISABLED by default. Set GUARD_MODEL_ENABLED=true to
activate. On first run the model is downloaded and cached locally.
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("shieldllm.guard_model")

GUARD_ENABLED = os.environ.get("GUARD_MODEL_ENABLED", "").lower() in (
    "1", "true", "yes"
)
GUARD_CONFIDENCE = float(os.environ.get("GUARD_MODEL_CONFIDENCE", "0.7"))
CACHE_DIR = Path.home() / ".cache" / "shieldllm" / "guard_model"

# ---------------------------------------------------------------------------
# Backend abstraction
# ---------------------------------------------------------------------------

_backend = None  # Lazy-loaded singleton


def _load_backend():
    """Load the best available backend."""
    global _backend

    # Try ONNX Runtime backend first (lightweight)
    try:
        from .guard_onnx import ONNXGuardBackend
        _backend = ONNXGuardBackend(cache_dir=CACHE_DIR)
        logger.info("guard_model backend=onnxruntime")
        return
    except ImportError:
        logger.debug("guard_model onnxruntime not available")
    except Exception as exc:
        logger.warning("guard_model onnxruntime_init_error: %s", exc)

    # Fallback: Transformers pipeline
    try:
        from .guard_hf import HFGuardBackend
        _backend = HFGuardBackend(cache_dir=CACHE_DIR)
        logger.info("guard_model backend=transformers")
        return
    except ImportError:
        logger.debug("guard_model transformers not available")
    except Exception as exc:
        logger.warning("guard_model transformers_init_error: %s", exc)

    logger.warning("guard_model no backend available — guard disabled")


def is_available() -> bool:
    """Check if the guard model is loaded and ready."""
    if _backend is None:
        _load_backend()
    return _backend is not None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(text: str) -> Optional[dict]:
    """Score a prompt for injection probability.

    Args:
        text: The user message content to analyze.

    Returns:
        None if guard is disabled or unavailable.
        Otherwise a dict:
            {"injection": bool, "score": float, "label": str}
    """
    if not GUARD_ENABLED:
        return None

    if not is_available():
        return None

    try:
        result = _backend.predict(text)
        is_injection = result["score"] >= GUARD_CONFIDENCE
        logger.debug(
            "guard_analysis injection=%s score=%.3f label=%s len=%d",
            is_injection, result["score"], result["label"], len(text),
        )
        return {
            "injection": is_injection,
            "score": result["score"],
            "label": result["label"],
        }
    except Exception as exc:
        logger.warning("guard_model inference error: %s", exc)
        return None
