"""
ShieldLLM — HuggingFace Transformers Guard Backend.

Fallback backend using the transformers library for prompt injection
detection. Heavier dependency but requires no manual model export.

Model: ProtectAI/distilroberta-base-prompt-injection (~200MB)
"""

import logging
from pathlib import Path

logger = logging.getLogger("shieldllm.guard_hf")

MODEL_ID = "ProtectAI/distilroberta-base-prompt-injection"


class HFGuardBackend:
    """HuggingFace pipeline backend for prompt injection detection."""

    def __init__(self, cache_dir: Path):
        self._pipeline = None
        self._load(cache_dir)

    def _load(self, cache_dir: Path):
        try:
            from transformers import pipeline
        except ImportError:
            raise ImportError("transformers not installed")

        self._pipeline = pipeline(
            "text-classification",
            model=MODEL_ID,
            device=-1,  # CPU
            cache_dir=str(cache_dir),
        )
        logger.info("hf_model_loaded model=%s", MODEL_ID)

    def predict(self, text: str) -> dict:
        result = self._pipeline(text, truncation=True, max_length=512)[0]
        score = result["score"]
        label = result["label"]
        return {
            "score": score if label.upper() == "INJECTION" else 1.0 - score,
            "label": label,
        }
