import re
from typing import Optional

TOXIC_PATTERNS = [
    (re.compile(r"(?i)(?:hate|despise|kill|murder)\s+(?:all|every|those|people|the\s+\w+)\s*(?:because|for|if)?", re.UNICODE), "hateful rhetoric"),
    (re.compile(r"(?i)(?:i['\"]?ll\s+kill|i['\"]?m\s+going\s+to\s+kill|let['\"]?s\s+kill|we\s+should\s+kill)", re.UNICODE), "violent threat"),
    (re.compile(r"(?i)(?:(?:build|make|create|construct)\s+(?:a\s+)?(?:bomb|explosive|weapon)|(?:bomb|explosive|weapon|massacre|shooting)\s+(?:making|build|create|instructions|how\s+to))", re.UNICODE), "weapon/explosive instructions"),
    (re.compile(r"(?i)(?:how\s+to\s+(?:commit|attempt|die\s+by)\s+(?:suicide|self-harm|selfharm))", re.UNICODE), "self-harm instructions"),
    (re.compile(r"(?i)(?:you\s+should\s+(?:kill|hurt|harm)\s+(?:yourself|your\s+own))", re.UNICODE), "encouraging self-harm"),
    (re.compile(r"(?i)(?:manufacture|synthesize|produce)\s+(?:illegal|illicit|banned|controlled|narcotic|drug)", re.UNICODE), "illegal drug production"),
    (re.compile(r"(?i)(?:child\s*(?:porn|abuse|exploit)|cp\s+(?:content|material|video))", re.UNICODE), "child exploitation"),
    (re.compile(r"(?i)(?:human\s+trafficking|sex\s+trafficking|traffick\s+(?:human|children|woman))", re.UNICODE), "human trafficking"),
    (re.compile(r"(?i)(?:harass|dox|doxx|swat|stalk)\s+(?:someone|a\s+person|them|this)", re.UNICODE), "harassment instructions"),
]

CONTRADICTION_INDICATORS = [
    (re.compile(r"(?i)(?:the\s+answer\s+is\s+)(\w+)", re.UNICODE), "answer value"),
    (re.compile(r"(?i)(?:the\s+result\s+is\s+)(\w+)", re.UNICODE), "result value"),
    (re.compile(r"(?i)(?:it['\"]?s\s+)(\w+)", re.UNICODE), "it is value"),
]

SENTENCE_SPLIT = re.compile(r"(?:[.!?]+\s+)", re.UNICODE)


def check_safety(text: str) -> Optional[str]:
    if not text:
        return None
    matches = []
    for pattern, label in TOXIC_PATTERNS:
        if pattern.search(text):
            matches.append(label)
    if matches:
        return "content safety violation: " + "; ".join(sorted(set(matches)))
    return None


def check_contradiction(text: str) -> Optional[str]:
    if not text or len(text) < 50:
        return None
    sentences = [s.strip() for s in SENTENCE_SPLIT.split(text) if len(s.strip()) > 10]
    if len(sentences) < 3:
        return None
    values = []
    for s in sentences:
        for pattern, label in CONTRADICTION_INDICATORS:
            m = pattern.search(s)
            if m:
                values.append((s, m.group(1).lower()))
    contradictions = []
    for i in range(len(values)):
        for j in range(i + 1, len(values)):
            val_i = values[i][1]
            val_j = values[j][1]
            if val_i != val_j:
                if _are_contradictory_values(val_i, val_j):
                    contradictions.append(f"'{val_i}' vs '{val_j}'")
    if contradictions:
        return "response self-contradiction detected: " + "; ".join(contradictions[:3])
    return None


_BOOLEAN_POSITIVE = {"yes", "true", "correct", "right", "affirmative", "positive", "valid"}
_BOOLEAN_NEGATIVE = {"no", "false", "incorrect", "wrong", "negative", "invalid"}
_NEGATION_PREFIXES = {"not", "no", "cannot", "can't", "won't", "don't", "doesn't", "isn't", "aren't"}


def _are_contradictory_values(a: str, b: str) -> bool:
    if a in _BOOLEAN_POSITIVE and b in _BOOLEAN_NEGATIVE:
        return True
    if a in _BOOLEAN_NEGATIVE and b in _BOOLEAN_POSITIVE:
        return True
    a_clean = a.replace(",", "").replace(".", "")
    b_clean = b.replace(",", "").replace(".", "")
    if a_clean.isdigit() and b_clean.isdigit():
        try:
            return abs(float(a_clean) - float(b_clean)) > 0.01
        except ValueError:
            return False
    return False
