"""
ShieldLLM — ONNX Runtime Guard Backend.

Downloads and runs a lightweight ONNX prompt-injection classification
model using onnxruntime (CPU). Tokenization uses the `tokenizers`
Rust-based library for speed.

Model: ProtectAI/distilroberta-base-prompt-injection
  (exported to ONNX via optimum)
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("shieldllm.guard_onnx")

MODEL_REPO = "ProtectAI/distilroberta-base-prompt-injection"
ONNX_FILENAME = "model.onnx"
TOKENIZER_FILENAME = "tokenizer.json"
CONFIG_FILENAME = "config.json"

# ---------------------------------------------------------------------------
# ONNX backend
# ---------------------------------------------------------------------------


class ONNXGuardBackend:
    """ONNX Runtime backend for prompt injection detection."""

    def __init__(self, cache_dir: Path):
        self._cache_dir = cache_dir
        self._session = None
        self._tokenizer = None
        self._config = None
        self._load()

    def _load(self):
        """Download model files and create ONNX session."""
        try:
            import onnxruntime as ort
        except ImportError:
            raise ImportError("onnxruntime not installed")

        # Resolve model paths
        model_path = self._resolve_file(ONNX_FILENAME)
        tokenizer_path = self._resolve_file(TOKENIZER_FILENAME)
        config_path = self._resolve_file(CONFIG_FILENAME)

        # Load config
        with open(config_path) as f:
            self._config = json.load(f)

        # Load tokenizer
        try:
            from tokenizers import Tokenizer
            self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        except ImportError:
            raise ImportError("tokenizers not installed")

        # Create ONNX session
        so = ort.SessionOptions()
        so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        so.intra_op_num_threads = 2
        self._session = ort.InferenceSession(
            str(model_path),
            sess_options=so,
            providers=["CPUExecutionProvider"],
        )

        logger.info(
            "onnx_model_loaded model=%s inputs=%s",
            MODEL_REPO,
            [inp.name for inp in self._session.get_inputs()],
        )

    def _resolve_file(self, filename: str) -> Path:
        """Get file path, downloading if necessary."""
        local_path = self._cache_dir / filename
        if local_path.exists():
            return local_path

        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._download_file(filename, local_path)
        return local_path

    def _download_file(self, filename: str, dest: Path) -> None:
        """Download a model file from HuggingFace Hub."""
        logger.info("downloading_model_file file=%s", filename)
        import requests

        url = f"https://huggingface.co/{MODEL_REPO}/resolve/main/onnx/{filename}"
        resp = requests.get(url, stream=True, timeout=300)
        resp.raise_for_status()

        tmp = dest.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        tmp.rename(dest)
        logger.info("downloaded_model_file file=%s size=%d", filename, dest.stat().st_size)

    def predict(self, text: str) -> dict:
        """Run inference. Returns {"score": float, "label": str}."""
        # Tokenize
        encoding = self._tokenizer.encode(text)
        input_ids = encoding.ids
        attention_mask = encoding.attention_mask

        # Pad/truncate to model max length
        max_len = self._config.get("max_position_embeddings", 512)
        if len(input_ids) > max_len:
            input_ids = input_ids[:max_len]
            attention_mask = attention_mask[:max_len]
        else:
            pad_id = self._config.get("pad_token_id", 1)
            padding = [pad_id] * (max_len - len(input_ids))
            input_ids = input_ids + padding
            attention_mask = attention_mask + [0] * (max_len - len(attention_mask))

        import numpy as np

        inputs = {
            "input_ids": np.array([input_ids], dtype=np.int64),
            "attention_mask": np.array([attention_mask], dtype=np.int64),
        }

        outputs = self._session.run(None, inputs)
        scores = outputs[0][0]
        probs = 1.0 / (1.0 + np.exp(-scores))  # sigmoid

        injection_score = float(probs[1] if len(probs) > 1 else probs[0])
        return {
            "score": injection_score,
            "label": "INJECTION" if injection_score > 0.5 else "SAFE",
        }
