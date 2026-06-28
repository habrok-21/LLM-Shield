"""
ShieldLLM — Egress (Output) Security Module.

Intercepts LLM responses to detect:
  - Generated code blocks (markdown fences, function/class definitions)
  - PII / sensitive data leakage
  - System prompt leakage
  - Repetition loops (token-hoarding)
  - Excessive response length
"""

import re
import threading
from typing import Optional

# ---------------------------------------------------------------------------
# Code generation patterns
# ---------------------------------------------------------------------------
EGRESS_CODE_PATTERN = re.compile(
    r"(```\w*\s*\n|"                          # markdown code fences
    r"def \w+\s*\(|"                          # Python / Ruby function def
    r"class \w+[\s(:]|"                       # Class definitions
    r"import\s+(?:os|sys|subprocess|socket|requests|numpy|pandas|json|re|typing|collections|math|random|datetime|pathlib|shutil|glob|pickle|sqlite3)\b|"  # Import statements
    r"from \w+ import|"                       # From-import
    r"function\s+\w+\s*\(|"                   # JavaScript / TS function
    r"const\s+\w+\s*=\s*\(|"                  # JS arrow function
    r"let\s+\w+\s*=\s*\(|"                    # JS let arrow
    r"var\s+\w+\s*=\s*\(|"                    # JS var arrow
    r"int\s+main\s*\(|"                       # C/C++/Java main
    r"public\s+static\s+void\s+main|"         # Java main
    r"fn\s+\w+\s*\(|"                         # Rust
    r"func\s+\w+\s*\(|"                       # Go
    r"defmodule\s+|"                          # Elixir
    r"defimpl\s+|"                            # Elixir
    r"defstruct\s+|"                          # Elixir
    r"#include\s*<|"                          # C/C++ include
    r"using\s+System|"                        # C#
    r"namespace\s+\w+|"                       # C#
    r"package\s+\w+;|"                        # Java
    r"<script\b|"                             # HTML/JS
    r"public\s+class|"                        # Java
    r"private\s+\w+\s+\w+|"                   # Access modifiers
    r"protected\s+\w+\s+\w+|"                 # Access modifiers
    r"void\s+\w+\s*\(|"                       # C/C++/Java method
    r"->\s*void|"                             # Go
    r"impl\s+\w+\s+for|"                      # Rust impl
    r"trait\s+\w+|"                           # Rust trait
    r"interface\s+\w+|"                       # TypeScript / Java
    r"enum\s+\w+|"                            # Rust / TypeScript / Java
    r"std::|"                                 # C++ / Rust std
    r"console\.log|"                          # JS debugging
    r"print\(|"                               # Python print
    r"printf\(|"                              # C printf
    r"System\.out|"                            # Java output
    r"@app\.\w+|"                              # Flask / FastAPI decorator
    r"@\w+\.route)"                            # Flask route
)
"""
Variant: simplified set if you want a smaller footprint
_EGRESS_CODE_PATTERN_SIMPLE = re.compile(
    r"(```\w*\s*\n|"
    r"def \w+\s*\(|"
    r"class \w+[\s(:]|"
    r"import \w+|"
    r"from \w+ import|"
    r"function\s+\w+\s*\(|"
    r"int\s+main|"
    r"public\s+static\s+void\s+main|"
    r"fn\s+\w+\s*\(|"
    r"func\s+\w+\s*\(|"
    r"#include\s*<|"
    r"<script\b)"
)
"""

# ---------------------------------------------------------------------------
# System prompt leakage
# ---------------------------------------------------------------------------
EGRESS_SYSTEM_LEAK_PATTERN = re.compile(
    r"(?i)(you are an?\s+(ai|assistant|chatbot|language model|"
    r"large language model|helpful assistant|virtual assistant)|"
    r"you were created|"
    r"your purpose is|"
    r"your role is|"
    r"you are designed to|"
    r"as an ai|"
    r"as a language model|"
    r"as an ai assistant|"
    r"i am an?\s+(ai|assistant|chatbot|language model)|"
    r"i am gpt|"
    r"i am claude|"
    r"i am deepseek|"
    r"i am llama|"
    r"i am gemini)"
)

# ---------------------------------------------------------------------------
# PII / sensitive data
# ---------------------------------------------------------------------------
EGRESS_PII_PATTERN = re.compile(
    r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b|"     # SSN-like
    r"\b\d{16,19}\b"                         # Credit-card-like
)

# ---------------------------------------------------------------------------
# Repetition / token-hoarding
# ---------------------------------------------------------------------------
EGRESS_REPETITION_PATTERN = re.compile(r"(.{30,}?)\1{3,}")

# ---------------------------------------------------------------------------
# Max response length / length ratio anomaly (mutable at runtime)
# ---------------------------------------------------------------------------
_MAX_RESPONSE_CHARS = 10000
_MAX_LENGTH_RATIO = 200
_egress_lock = threading.RLock()


def get_max_response_chars() -> int:
    return _MAX_RESPONSE_CHARS


def set_max_response_chars(n: int) -> None:
    global _MAX_RESPONSE_CHARS
    _MAX_RESPONSE_CHARS = n


def get_max_length_ratio() -> int:
    return _MAX_LENGTH_RATIO


def set_max_length_ratio(n: int) -> None:
    global _MAX_LENGTH_RATIO
    _MAX_LENGTH_RATIO = n


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class EgressResult:
    """Encapsulates the result of an egress inspection."""

    def __init__(self):
        self.flagged: bool = False
        self.reasons: list[str] = []

    def reject(self, reason: str) -> None:
        self.flagged = True
        self.reasons.append(reason)


def check_egress(text: str, result: EgressResult) -> None:
    """Inspect LLM response text for policy violations. Populates `result`."""
    if not text:
        return

    # 1. Code generation
    if EGRESS_CODE_PATTERN.search(text):
        result.reject("generated code detected in response")

    # 2. System prompt leakage
    if EGRESS_SYSTEM_LEAK_PATTERN.search(text):
        result.reject("system prompt leakage detected in response")

    # 3. PII / sensitive data
    if EGRESS_PII_PATTERN.search(text):
        result.reject("PII / sensitive data detected in response")

    # 4. Repetition loops
    if EGRESS_REPETITION_PATTERN.search(text):
        result.reject("excessive repetition detected in response")

    # 5. Response length
    max_chars = _MAX_RESPONSE_CHARS
    if len(text) > max_chars:
        result.reject(
            f"response exceeds {max_chars} character limit "
            f"(got {len(text)})"
        )


def check_length_ratio(prompt_length: int, response_length: int) -> Optional[str]:
    if prompt_length <= 0 or response_length <= 0:
        return None
    ratio = response_length / prompt_length
    max_ratio = _MAX_LENGTH_RATIO
    if ratio > max_ratio:
        return (
            f"response/prompt length ratio anomaly: "
            f"{response_length} / {prompt_length} = {ratio:.1f}x "
            f"(threshold {max_ratio}x)"
        )
    return None
