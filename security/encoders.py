"""
ShieldLLM — Encoded Payload Detection.

Detects encoded / obfuscated content in user prompts that attackers
use to bypass keyword-based ingress filters:

  - Base64
  - Hex encoding
  - URL encoding
  - Binary / octal escape sequences
  - Unicode confusables / homoglyphs
  - Reversed text
  - Leetspeak substitution scoring

Heuristic-based — each detector returns a confidence score (0.0 – 1.0)
rather than a hard boolean, so downstream policy can tune sensitivity.
"""

import base64
import binascii
import logging
import re
import string
from typing import Optional

logger = logging.getLogger("shieldllm.encoders")

# ---------------------------------------------------------------------------
# Heuristic thresholds
# ---------------------------------------------------------------------------
BASE64_MIN_LENGTH = 16
BASE64_PADDING_THRESHOLD = 0.02
BASE64_ALPHABET_RATIO = 0.85

HEX_MIN_LENGTH = 20
HEX_CHAR_RATIO = 0.40

URL_ENCODE_RATIO = 0.20
CONFUSABLE_DENSITY = 0.30


# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------


def score_base64(text: str) -> float:
    """Score 0.0–1.0 for base64-like content.

    Strips whitespace, scans for long base64-ish tokens within text,
    and tries to decode candidates.
    """
    # Strip whitespace to get the raw content
    compact = "".join(text.split())
    if len(compact) < BASE64_MIN_LENGTH:
        return 0.0

    # Find all contiguous runs of base64 chars (including = padding)
    b64_alphabet = set(string.ascii_uppercase + string.ascii_lowercase +
                       string.digits + "+/=")
    runs = re.findall(rf"[{re.escape(''.join(b64_alphabet))}]+", compact)
    candidates = [r for r in runs if len(r) >= BASE64_MIN_LENGTH]
    if not candidates:
        return 0.0

    best_score = 0.0
    for cand in candidates:
        # Base64 conformity ratio
        b64_ratio = sum(1 for c in cand if c in b64_alphabet) / len(cand)
        if b64_ratio < BASE64_ALPHABET_RATIO:
            continue

        padding = cand.count("=")
        padding_ratio = padding / len(cand) if len(cand) > 0 else 0

        try:
            decoded = base64.b64decode(cand, validate=True)
            printable = sum(1 for b in decoded if 32 <= b < 127 or b in (9, 10, 13))
            text_ratio = printable / len(decoded) if len(decoded) > 0 else 0
            if text_ratio > 0.5 and len(decoded) > 0:
                score = min(1.0, padding_ratio * 5 + 0.4 + text_ratio * 0.2)
                best_score = max(best_score, score)
        except (binascii.Error, ValueError):
            # Even without valid decode, high base64 conformity + padding
            # is suspicious
            if padding_ratio > BASE64_PADDING_THRESHOLD and b64_ratio > 0.9:
                best_score = max(best_score, padding_ratio * 3)

    return min(1.0, best_score)


def score_hex(text: str) -> float:
    """Score 0.0–1.0 for hex-encoded content."""
    # Look for hex sequences: long runs of hex chars
    runs = re.findall(r"[0-9a-fA-F]{10,}", text)
    if not runs:
        return 0.0

    max_run = max(len(r) for r in runs)
    total_hex_chars = sum(len(r) for r in runs)
    ratio = total_hex_chars / len(text) if len(text) > 0 else 0

    # Long contiguous hex run is suspicious regardless of surrounding text
    if max_run >= 20:
        return 1.0

    if ratio > HEX_CHAR_RATIO and total_hex_chars > HEX_MIN_LENGTH:
        return min(1.0, ratio)

    return 0.0


def score_url_encoded(text: str) -> float:
    """Score 0.0–1.0 for URL-encoded content."""
    encoded = re.findall(r"%[0-9a-fA-F]{2}", text)
    if not encoded:
        return 0.0

    encoded_chars = sum(len(e) for e in encoded)
    ratio = encoded_chars / len(text) if len(text) > 0 else 0
    return min(1.0, ratio / URL_ENCODE_RATIO)


def score_confusables(text: str) -> float:
    """Score 0.0–1.0 for unicode confusable / homoglyph characters."""
    # Characters outside basic ASCII that look like ASCII
    ascii_letters = set(string.ascii_letters + string.digits +
                        string.punctuation + " ")
    non_ascii = sum(1 for c in text if ord(c) > 127 and c not in ascii_letters)
    ratio = non_ascii / len(text) if len(text) > 0 else 0
    return min(1.0, ratio / CONFUSABLE_DENSITY)


def score_reversed(text: str) -> float:
    """Score 0.0–1.0 for reversed or palindrome-like text."""
    cleaned = text.strip().lower()
    if len(cleaned) < 30:
        return 0.0
    # Check if it reads naturally in reverse
    reversed_text = cleaned[::-1]
    # Simple heuristic: check for common English words in reversed text
    common_words = {"the", "and", "for", "are", "but", "not", "you", "all",
                    "can", "had", "her", "was", "one", "our", "out"}
    reversed_words = set(reversed_text.split())
    overlap = len(common_words & reversed_words)
    return min(0.8, overlap * 0.15)


def score_leetspeak(text: str) -> float:
    """Score 0.0–1.0 for leetspeak substitutions."""
    # Exclude hex-only runs to avoid false positives on hex strings
    hex_runs = re.findall(r"[0-9a-fA-F]{10,}", text)
    hex_chars = sum(len(r) for r in hex_runs)
    if hex_chars > 0:
        total_hex_ratio = hex_chars / len(text) if len(text) > 0 else 0
        if total_hex_ratio > 0.5:
            return 0.0

    leet_map = {
        "4": "a", "@": "a", "8": "b", "3": "e", "9": "g",
        "1": "l", "!": "i", "0": "o", "5": "s", "$": "s",
        "7": "t", "2": "z", "<": "c", "(": "c", "6": "g",
    }
    # Count substitutions
    subs = sum(1 for c in text if c in leet_map)
    ratio = subs / len(text) if len(text) > 0 else 0
    return min(1.0, ratio * 3)


# ---------------------------------------------------------------------------
# Composite analysis
# ---------------------------------------------------------------------------

ALL_DETECTORS = [
    ("base64", score_base64),
    ("hex", score_hex),
    ("url_encoded", score_url_encoded),
    ("confusables", score_confusables),
    ("reversed", score_reversed),
    ("leetspeak", score_leetspeak),
]

ENCODING_POLICY_THRESHOLD = 0.6


def analyze(text: str) -> Optional[str]:
    """Run all detectors. Returns a violation string if any exceeds threshold.

    Returns None if content appears clean.
    """
    if not text or len(text) < 10:
        return None

    scores = {}
    for name, detector in ALL_DETECTORS:
        try:
            score = detector(text)
            if score > 0:
                scores[name] = round(score, 3)
        except Exception as exc:
            logger.debug("encoder_detector_error name=%s error=%s", name, exc)

    if not scores:
        return None

    max_score = max(scores.values())
    if max_score >= ENCODING_POLICY_THRESHOLD:
        top = max(scores, key=scores.get)
        return (
            f"encoded payload detected ({top} score={max_score:.2f}): "
            + " ".join(f"{k}={v}" for k, v in sorted(scores.items()))
        )

    return None
