"""
ShieldLLM — Ingress (Input) Security Module.

Scans incoming chat messages for:
  - System instruction override attempts (jailbreak / prompt injection)
  - Banned task intents (code generation, math, essays)
  - Token-hoarding / spam patterns
  - Prompt extraction / system prompt leakage attempts
"""

import re
import threading
from typing import Optional

BANNED_KEYWORDS = [
    # ---- Code generation ----
    "write code",
    "write a program",
    "write a script",
    "generate code",
    "generate a program",
    "generate a script",
    "python script",
    "python code",
    "javascript code",
    "golang code",
    "rust code",
    "def ",
    "class ",
    "import requests",
    "import os",
    "import subprocess",
    "import sys",
    "import socket",
    "```python",
    "```javascript",
    "```java",
    "```go",
    "```rust",
    "```c",
    "```c++",
    "```bash",
    "```sql",
    "```html",
    "```css",
    "```typescript",
    "create a function",
    "write a function",
    "implement a function",
    "implement a class",
    # ---- System override / jailbreak ----
    "ignore previous instructions",
    "ignore all instructions",
    "ignore your instructions",
    "ignore your prior instructions",
    "ignore all previous instructions",
    "disregard previous",
    "disregard all previous",
    "forget your instructions",
    "forget your previous instructions",
    "forget everything",
    "you are now",
    "act as dan",
    "act as if",
    "roleplay as",
    "pretend to be",
    "from now on you are",
    "you are free",
    "no restrictions",
    "no rules",
    "you have no limits",
    "you are unconstrained",
    "do not follow",
    "do not obey",
    "break character",
    "out of character",
    "new personality",
    "new persona",
    "override",
    "jailbreak",
    "system override",
    # ---- Prompt extraction ----
    "what are your instructions",
    "what is your prompt",
    "what are your rules",
    "what was your initial",
    "reveal your",
    "show your system",
    "output your",
    "print your instructions",
    "leak your",
    "give me your prompt",
    "ignore everything above",
    "ignore everything before",
    "disregard everything above",
    # ---- Token-hoarding / abuse ----
    "repeat the word",
    "say the word",
    "write a very long",
    "write an extremely long",
    "generate a long",
    "write a 5000 word",
    "write a 10000 word",
    # ---- Domain restriction (food-ordering bot) ----
    "solve this math",
    "solve this equation",
    "calculate",
    "write an essay",
    "write a poem about",
    "write a story about",
    "explain quantum",
    "explain physics",
    "tutorial on",
    "lesson on",
]

JAILBREAK_PATTERNS = [
    re.compile(
        r"(?i)(?:repeat|say|output|print|echo)\s+"
        r"(?:the\s+)?word\s+['\"]?\w+['\"]?\s+(?:over|many|\d+)"
    ),
    re.compile(
        r"(?i)(?:write|generate|create|make|compose)\s+"
        r"(?:a\s+)?(?:poem|story|essay|article|blog)\s+"
        r"(?:about|that|on|regarding)"
    ),
    re.compile(r"(?i)system\s*(?:prompt|message|instruction)"),
    re.compile(r"(?i)developer\s*(?:prompt|message|instruction)"),
    re.compile(r"(?i)initial\s*(?:prompt|message|instruction|system)"),
    re.compile(r"(?i)you\s+are\s+(?:now\s+)?(?:dan|chatgpt|gpt|free|unlocked)"),
    re.compile(r"(?i)new\s+(?:rule|rules|instruction|persona|character|role)"),
    re.compile(r"(?i)(?:remove|disable|turn\s+off|bypass|circumvent)\s+"
               r"(?:all\s+)?(?:restrictions|limitations|safeguards|filters|guardrails)"),
    re.compile(r"(?i)do\s+(?:not\s+)?(?:follow|obey|adhere\s+to)\s+"
               r"(?:your\s+)?(?:previous\s+)?(?:instructions|rules|guidelines)"),
    re.compile(r"(?i)simulate\s+.*?(?:no\s+)?(?:rules|restrictions|limits|filter)"),
    re.compile(r"(?i)hypothetical\s+.*?(?:no\s+)?(?:rules|restrictions|limits)"),
]

_MAX_MESSAGE_CHARS = 16000
_MANY_SHOT_THRESHOLD = 20
_BANNED_KEYWORDS = list(BANNED_KEYWORDS)
_JAILBREAK_PATTERNS = list(JAILBREAK_PATTERNS)
_rules_lock = threading.RLock()


# Pattern for repetitive many-shot: alternating user/assistant turns with short content
_MANY_SHOT_REPETITION = re.compile(
    r"(?i)(?:(?:user|assistant|system)\s*[:>]\s*\w+\s*(?:\n|$)){10,}"
)


def get_max_message_chars() -> int:
    return _MAX_MESSAGE_CHARS


def set_max_message_chars(n: int) -> None:
    global _MAX_MESSAGE_CHARS
    _MAX_MESSAGE_CHARS = n


def list_keywords() -> list:
    with _rules_lock:
        return list(_BANNED_KEYWORDS)


def add_keyword(kw: str) -> None:
    with _rules_lock:
        kw_lower = kw.lower()
        if kw_lower not in _BANNED_KEYWORDS:
            _BANNED_KEYWORDS.append(kw_lower)


def remove_keyword(kw: str) -> bool:
    with _rules_lock:
        kw_lower = kw.lower()
        if kw_lower in _BANNED_KEYWORDS:
            _BANNED_KEYWORDS.remove(kw_lower)
            return True
        return False


def list_jailbreak_patterns() -> list:
    with _rules_lock:
        return [p.pattern for p in _JAILBREAK_PATTERNS]


def add_jailbreak_pattern(pattern: str) -> None:
    with _rules_lock:
        compiled = re.compile(pattern)
        _JAILBREAK_PATTERNS.append(compiled)


def remove_jailbreak_pattern(pattern: str) -> bool:
    with _rules_lock:
        for i, p in enumerate(_JAILBREAK_PATTERNS):
            if p.pattern == pattern:
                _JAILBREAK_PATTERNS.pop(i)
                return True
        return False


def get_many_shot_threshold() -> int:
    return _MANY_SHOT_THRESHOLD


def set_many_shot_threshold(n: int) -> None:
    global _MANY_SHOT_THRESHOLD
    _MANY_SHOT_THRESHOLD = n


def check_many_shot(messages: list) -> Optional[str]:
    if len(messages) >= _MANY_SHOT_THRESHOLD:
        combined = " ".join(
            f"{m.get('role', '')}: {m.get('content', '')}"
            for m in messages if isinstance(m.get('content'), str)
        )
        if _MANY_SHOT_REPETITION.search(combined):
            return (
                f"many-shot jailbreak attempt detected: "
                f"{len(messages)} messages with repetitive turn pattern"
            )
        return (
            f"excessive message count detected: "
            f"{len(messages)} messages exceeds threshold of {_MANY_SHOT_THRESHOLD}"
        )
    return None


def check_ingress(messages: list) -> Optional[str]:
    """Scan all messages for policy violations. Returns the first violation or None."""
    for idx, msg in enumerate(messages):
        content = msg.get("content", "")
        if not isinstance(content, str):
            continue

        content_lower = content.lower()

        with _rules_lock:
            keywords = list(_BANNED_KEYWORDS)
            patterns = list(_JAILBREAK_PATTERNS)
            max_chars = _MAX_MESSAGE_CHARS

        # 1. Keyword match
        for keyword in keywords:
            if keyword in content_lower:
                return f"message[{idx}] matched banned keyword '{keyword}'"

        # 2. Jailbreak regex patterns
        for pat in patterns:
            if pat.search(content):
                return f"message[{idx}] matched jailbreak pattern: {pat.pattern}"

        # 3. Excessive length (token-hoarding / DoW)
        if len(content) > max_chars:
            return (
                f"message[{idx}] exceeds maximum allowed length "
                f"({len(content)} > {max_chars} chars)"
            )

    return None
