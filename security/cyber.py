import re
from typing import Optional

# ═══════════════════════════════════════════════════════════════════════════════
# 1. SSRF Attempt Detection (Ingress)
#    Detects prompts asking the LLM to fetch internal/cloud resources.
# ═══════════════════════════════════════════════════════════════════════════════

SSRF_PROMPT_PATTERNS = [
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:169\.254\.169\.254)"),
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:127\.0\.0\.1|localhost)"),
    re.compile(r"(?i)(?:127\.0\.0\.1|localhost)"),
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:192\.168\.\d{1,3}\.\d{1,3})"),
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:172\.1[6-9]\.\d{1,3}\.\d{1,3})"),
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:172\.2[0-9]\.\d{1,3}\.\d{1,3})"),
    re.compile(r"(?i)(?:fetch|get|curl|wget|request|visit|open|load|read)\s+(?:https?://)?(?:172\.3[0-1]\.\d{1,3}\.\d{1,3})"),
    re.compile(r"(?i)metadata\.google\.internal"),
    re.compile(r"(?i)169\.254\.169\.254"),
]

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Internal Network Leakage (Egress)
#    Detects internal IPs, hostnames, cloud metadata in LLM responses.
# ═══════════════════════════════════════════════════════════════════════════════

INTERNAL_IP_RE = re.compile(
    r"(?i)(?:"
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|"
    r"(?:192\.168\.\d{1,3}\.\d{1,3})|"
    r"(?:172\.1[6-9]\.\d{1,3}\.\d{1,3})|"
    r"(?:172\.2[0-9]\.\d{1,3}\.\d{1,3})|"
    r"(?:172\.3[0-1]\.\d{1,3}\.\d{1,3})"
    r")"
)

CLOUD_METADATA_RE = re.compile(
    r"(?i)(?:"
    r"(?:169\.254\.169\.254)|"
    r"(?:metadata\.google\.internal)|"
    r"(?:metadata\.amazonaws\.com)|"
    r"(?:169\.254\.170\.\d{1,3})"
    r")"
)

INTERNAL_HOSTNAME_RE = re.compile(
    r"(?i)(?:"
    r"(?:\.local(?:host|domain)?\b)|"
    r"(?:\.internal\b)|"
    r"(?:\.corp\b)|"
    r"(?:\.private\b)|"
    r"(?:localhost(?:6)?\b)"
    r")"
)

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Malicious URL Detection (Egress)
#    Detects phishing, malware, suspicious URL patterns in responses.
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_DOMAIN_RE = re.compile(
    r"(?i)(?:"
    r"(?:bit\.ly|tinyurl|shorturl|short\.link|t\.co)\S*|"
    r"(?:malware|phishing|hack|exploit|c2|botnet)\S*|"
    r"\S*\.(?:tk|ml|ga|cf|gq|xyz|top|club|work|date|men|loan|click|download|zip)(?:/\S*)?"
    r")", re.UNICODE
)

PHISHING_KEYWORD_RE = re.compile(
    r"(?i)(?:"
    r"(?:login|signin|verify|confirm|secure)\s*(?:your\s+)?(?:account|bank|email|password|credit\s+card)|"
    r"(?:click\s+here\s+to\s+(?:verify|confirm|reset|secure))|"
    r"(?:update\s+(?:your\s+)?(?:payment|billing|account\s+info))"
    r")"
)

# ═══════════════════════════════════════════════════════════════════════════════
# 4. XSS Detection (Egress)
#    Detects script injection / HTML event handler patterns in responses.
# ═══════════════════════════════════════════════════════════════════════════════

XSS_PATTERNS = [
    re.compile(r"(?i)(?:<script[\s>])"),
    re.compile(r"(?i)(?:javascript\s*:)"),
    re.compile(r"(?i)(?:onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|onblur\s*=|onchange\s*=|onsubmit\s*=|onkeydown\s*=|onkeyup\s*=)"),
    re.compile(r"(?i)(?:<iframe[\s>]|<embed[\s>]|<object[\s>]|<frame[\s>])"),
    re.compile(r"(?i)(?:alert\s*\(|confirm\s*\(|prompt\s*\()"),
    re.compile(r"(?i)(?:eval\s*\(|setTimeout\s*\(|setInterval\s*\()"),
    re.compile(r"(?i)(?:document\.(?:cookie|domain|location|write|writeln))"),
    re.compile(r"(?i)(?:window\.(?:location|name|status))"),
]

# ═══════════════════════════════════════════════════════════════════════════════
# 5. Command Injection Detection (Egress)
#    Detects shell command execution patterns in responses.
# ═══════════════════════════════════════════════════════════════════════════════

CMD_INJECTION_PATTERNS = [
    re.compile(r"(?i)(?:`[a-z]+\s+-[a-z]+\s+)"),
    re.compile(r"(?i)(?:\$\([a-z]+\s+)"),
    re.compile(r"(?i)(?:curl\s+(?:-s|-o|-L|--output)\s+\S+)"),
    re.compile(r"(?i)(?:wget\s+(?:-O|-q|--output-document)\s+\S+)"),
    re.compile(r"(?i)(?:chmod\s+\+[xwusr]\s+\S+)"),
    re.compile(r"(?i)(?:rm\s+(?:-rf|-r|-f)\s+/)"),
    re.compile(r"(?i)(?:bash\s+-c\s+[\"'\[(])"),
    re.compile(r"(?i)(?:eval\s+\$\(|<\(\))"),
    re.compile(r"(?i)(?:python\s+-c\s+[\"'])"),
    re.compile(r"(?i)(?:perl\s+-e\s+[\"'])"),
    re.compile(r"(?i)(?:nc\s+-[lvue]\s+\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"(?i)(?:nslookup\s+\S+\s+\S+)"),
    re.compile(r"(?i)(?:dig\s+@\S+\s+\S+)"),
]

# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════


def check_ssrf_attempt(text: str) -> Optional[str]:
    if not text:
        return None
    for pattern in SSRF_PROMPT_PATTERNS:
        if pattern.search(text):
            return "SSRF attempt detected: prompt targets internal/cloud metadata endpoint"
    return None


def check_internal_leakage(text: str) -> Optional[str]:
    if not text:
        return None
    reasons = []
    if INTERNAL_IP_RE.search(text):
        reasons.append("internal IP address")
    if CLOUD_METADATA_RE.search(text):
        reasons.append("cloud metadata endpoint")
    if INTERNAL_HOSTNAME_RE.search(text):
        reasons.append("internal hostname")
    if reasons:
        return "internal network leakage detected: " + "; ".join(reasons)
    return None


def check_malicious_url(text: str) -> Optional[str]:
    if not text:
        return None
    reasons = []
    if SUSPICIOUS_DOMAIN_RE.search(text):
        reasons.append("suspicious domain pattern")
    if PHISHING_KEYWORD_RE.search(text):
        reasons.append("phishing language pattern")
    if reasons:
        return "malicious content detected: " + "; ".join(reasons)
    return None


def check_xss(text: str) -> Optional[str]:
    if not text:
        return None
    for pattern in XSS_PATTERNS:
        if pattern.search(text):
            return "XSS detected in response: script injection pattern found"
    return None


def check_command_injection(text: str) -> Optional[str]:
    if not text:
        return None
    for pattern in CMD_INJECTION_PATTERNS:
        if pattern.search(text):
            return "command injection detected in response: shell execution pattern found"
    return None
