import re
from typing import Optional

EXFILTRATION_PATTERNS = [
    (re.compile(r"(?i)(?:sk-[a-zA-Z0-9]{20,})"), "OpenAI API key"),
    (re.compile(r"(?i)(?:ghp_[a-zA-Z0-9]{36})"), "GitHub personal access token"),
    (re.compile(r"(?i)(?:gho_[a-zA-Z0-9]{36})"), "GitHub OAuth token"),
    (re.compile(r"(?i)(?:xox[baprs]-[a-zA-Z0-9-]{10,})"), "Slack token"),
    (re.compile(r"(?i)(?:AKIA[0-9A-Z]{16})"), "AWS access key ID"),
    (re.compile(r"(?i)(?:eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)"), "JWT token"),
    (re.compile(r"(?i)(?:-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+(?:PRIVATE\s+)?KEY-----)"), "private key block"),
    (re.compile(r"(?i)(?:AIza[0-9A-Za-z_-]{35})"), "Google API key"),
    (re.compile(r"(?i)(?:sk_live_[a-zA-Z0-9]{10,})"), "Stripe live API key"),
    (re.compile(r"(?i)(?:rk_live_[a-zA-Z0-9]{10,})"), "Stripe live restricted key"),
    (re.compile(r"(?i)(?:pk_live_[a-zA-Z0-9]{10,})"), "Stripe live publishable key"),
    (re.compile(r"(?i)(?:[a-zA-Z0-9+/=]{40,}\s*(?:password|secret|token|key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-!@#$%^&*()+=]{8,})"), "credential pattern in text"),
    (re.compile(r"(?i)(?:postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@)"), "PostgreSQL connection string"),
    (re.compile(r"(?i)(?:mysql://[a-zA-Z0-9_]+:[^@\s]+@)"), "MySQL connection string"),
    (re.compile(r"(?i)(?:mongodb(?:\+srv)?://[a-zA-Z0-9_]+:[^@\s]+@)"), "MongoDB connection string"),
    (re.compile(r"(?i)(?:redis://[^@\s]+@)"), "Redis connection string"),
]

EXFILTRATION_DOMAIN_THRESHOLD = 3


def check_exfiltration(text: str) -> Optional[str]:
    if not text:
        return None
    matches = []
    for pattern, label in EXFILTRATION_PATTERNS:
        if pattern.search(text):
            matches.append(label)
    if matches:
        return "data exfiltration detected: " + "; ".join(sorted(set(matches)))
    return None
