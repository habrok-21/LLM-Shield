# ShieldLLM — AI Reverse Proxy Firewall

**ShieldLLM** is a lightweight, self-hosted AI reverse proxy firewall that sits between your users and any OpenAI-compatible LLM API. It inspects every request and response in real time, blocking prompt injection, data exfiltration, harmful content, denial-of-wallet attacks, and cybersecurity threats — all without ML models or external dependencies.

## Who Should Use This

**Security engineers** enforcing LLM usage policies. **Platform teams** deploying a zero-dependency sidecar proxy. **AI/ML engineers** protecting prompts and controlling token spend. **Compliance officers** preventing PII and secret leakage in LLM responses. **CTOs** shipping AI products confidently without slowing velocity.

## Where to Deploy

Anywhere Python runs — single VM, containerized in Docker/K8s, on-prem air-gapped, edge/IoT devices, or behind a corporate VPN. Use it as a sidecar proxy for a single app, a multi-tenant shared gateway, or a CI/CD test harness.

## Why ShieldLLM?

- **Zero dependencies** — No ML models, no databases, no CDNs, no JavaScript frameworks. Runs anywhere Python 3.9+ runs. Fully offline.
- **Live dashboard** — Real-time SSE event feed, animated stats, interactive config panel.
- **Runtime configuration** — Add/remove keywords, jailbreak patterns, IP filters, and adjust thresholds via REST API. No restart needed.
- **Streaming support** — Inspects SSE streaming responses token-by-token in real time, terminating on policy violation mid-stream.
- **Thread-safe** — All modules use reentrant locks for safe concurrent access.
- **Privacy-first** — Audit logs mask the last octet of client IPs.
- **Vendor-agnostic** — Works with OpenAI, Anthropic, DeepSeek, or any OpenAI-compatible endpoint.

## The Problem

| Threat | Impact |
|---|---|
| **Prompt injection & jailbreaks** | Attackers bypass system prompts to make the LLM ignore instructions, generate code, or reveal its system prompt |
| **Data exfiltration** | LLMs leak API keys, database credentials, JWT tokens, internal infrastructure |
| **Denial of Wallet (DoW)** | Malicious actors consume expensive token budgets with repetitive or token-hoarding prompts |
| **Harmful content** | LLMs generate hate speech, violence instructions, self-harm content, phishing pages |
| **Cyber blind spots** | Traditional firewalls don't inspect LLM traffic for SSRF, command injection, XSS, internal network leakage |
| **No observability** | No visibility into what users send, what models return, or how often policy is violated |

## Architecture

```
┌─────────┐     ┌───────────────────────────────────────────────────────────────--───┐
│  Client │────▶│                        ShieldLLM                                   │
└─────────┘     │                                                                    │
                │  ┌──────────┐  ┌────────────--┐  ┌──────────┐  ┌────────────────┐  │
                │  │  IP      │──│   Ingress    │──│  Rate    │──│   Cache        │  │
                │  │  Filter  │  │  Pipeline    │  │  Limiter │  │   (non-stream) │  │
                │  └──────────┘  │              │  └──────────┘  └────────────────┘  │
                │                │  • Keywords  │                                    │
                │                │  • Jailbreak │        ┌──────────────────────┐    │
                │                │  • Encoded   │        │    Upstream Router   │    │
                │                │  • Many-shot │        │                      │    │
                │                │  • SSRF      │        │  Primary ──▶ OpenAI  │    │
                │                │  • ML Guard  │────────│  Backup  ──▶ DeepSeek│    │
                │                └────────────-─┘        │  (auto failover)     │    │
                │                                        └──────────────────────┘    │
                │  ┌──────────────────────────────────────────────────────────┐      │
                │  │                 Egress Pipeline                          │      │
                │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │      │
                │  │  │  Code/   │ │   Data   │ │  Content │ │   Cyber    │   │      │
                │  │  │  Leak/   │ │Exfiltrat.│ │  Safety  │ │ • SSRF     │   │      │
                │  │  │  PII     │ │• API keys│ │• Hate    │ │ • Internal │   │      │
                │  │  │          │ │• JWT     │ │• Violence│ │ • Mal URLs │   │      │
                │  │  │          │ │• Secrets │ │• Self-   │ │ • XSS      │   │      │
                │  │  │          │ │• DB URLs │ │  harm    │ │ • CMD inj  │   │      │
                │  │  └──────────┘ └──────────┘ └──────────┘ └────────────┘   │      │
                │  └──────────────────────────────────────────────────────────┘      │
                │                                                                    │
                │  ┌──────────────────────────────────────────────────────────┐      │
                │  │              Real-Time Dashboard (SSE)                   │      │
                │  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐   │      │
                │  │  │  Stats   │ │  Event   │ │  Token   │ │   Config   │   │      │
                │  │  │  Cards   │ │  Feed    │ │  Chart   │ │   Panel    │   │      │
                │  │  └──────────┘ └──────────┘ └──────────┘ └────────────┘   │      │
                │  └──────────────────────────────────────────────────────────┘      │
                │                                                                    │
                └────────────────────────────────────────────────────────────────--──┘
                                │
                                ▼
                      ┌─────────────────┐
                      │  LLM Provider   │
                      │  (OpenAI, etc.) │
                      └─────────────────┘
```

## Security Features

### Ingress (input) protection

| Category | What it blocks |
|---|---|
| **Banned keywords** | Code generation, jailbreak phrases, prompt extraction, token-hoarding, off-domain requests |
| **Jailbreak regex** | Word repetition, essay generation, system prompt references, role-play escalation, restriction bypass |
| **Encoded payloads** | Base64, hex, URL-encoded, unicode confusables, reversed text, leetspeak |
| **Many-shot jailbreak** | Excessive message counts (>20) and repetitive user/assistant turn patterns |
| **SSRF attempt** | Prompts asking the LLM to fetch cloud metadata (`169.254.169.254`), localhost, or private networks |
| **ML guard** | Optional ONNX or HuggingFace model for prompt injection scoring |

### Egress (output) protection

| Category | What it blocks |
|---|---|
| **Code generation** | Markdown fences, function/class definitions, imports, shell commands, SQL, HTML/JS |
| **System leakage** | LLM self-identification patterns (`you are an AI`, `I am a language model`) |
| **PII** | SSN-like patterns, credit card numbers |
| **Repetition loops** | Repeated substrings indicating token-hoarding |
| **Data exfiltration** | OpenAI keys, AWS keys, JWT tokens, private key blocks, DB connection strings, GitHub/Slack/Stripe/Google tokens |
| **Content safety** | Hate speech, violent threats, weapon instructions, self-harm, illegal activity, human trafficking |
| **Self-contradiction** | Boolean contradictions (yes/no), numerical contradictions in the same response |
| **Internal network leakage** | Internal IPs, cloud metadata endpoints, `.internal`/`.local` hostnames |
| **Malicious URLs** | Suspicious TLDs (`.tk`, `.ml`, `.ga`, `.xyz`), URL shorteners, phishing patterns |
| **XSS** | `<script>` tags, `javascript:` protocol, event handlers, `alert()`/`eval()`, `document.cookie` |
| **Command injection** | `curl`, `wget`, `chmod +x`, `rm -rf /`, `bash -c`, `eval`, `python -c`, `netcat`, `dig` |

### Rate limiting & circuit breaker

- Sliding-window token budget per IP with tiktoken-accurate counting (char/4 fallback)
- Automatic failover between primary and backup LLM providers with configurable threshold and reset interval

## Getting Started

See **[deployment.md](deployment.md)** for full install, configuration, production deployment, Docker, systemd, nginx setup, troubleshooting, and monitoring.

Quickstart:

```bash
git clone https://github.com/habrok-21/LLM-Shield.git shieldllm && cd shieldllm
pip install -r requirements.txt
python3 app.py
```

Open `http://localhost:8080/dashboard` — point your app to `http://localhost:8080/v1/chat/completions`.

### Test all features without an LLM API key

```bash
# Start the server
python3 app.py &

# Run the demo — tests every security layer, no config needed
bash demo.sh
```

The demo script tests ingress blocking (keywords, jailbreaks, encoded payloads, SSRF, many-shot), simulates egress blocks and cache hits via built-in demo APIs, exercises rate limiting and live config changes, and prints a summary of all results. No real API key required.

## Project Structure

```
shieldllm/
├── app.py                  # FastAPI server, proxy pipeline, all API endpoints
├── dashboard.html           # Self-contained SPA (no CDN deps)
├── config.yml              # YAML config with env var overrides
├── security/
│   ├── __init__.py          # Public API exports
│   ├── ingress.py           # Keyword, jailbreak, many-shot, length checks
│   ├── egress.py            # Code, leak, PII, repetition, length ratio checks
│   ├── exfiltration.py      # API key, JWT, secret, DB string detection
│   ├── safety.py            # Content safety, self-contradiction detection
│   ├── cyber.py             # SSRF, internal leakage, malware URLs, XSS, CMD injection
│   ├── rate_limiter.py      # Sliding-window token budget limiter
│   ├── router.py            # Primary/backup routing with circuit breaker
│   ├── cache.py             # TTL-aware semantic response cache
│   ├── streaming.py         # Real-time SSE stream inspector
│   ├── encoders.py          # Base64, hex, URL, confusables detection
│   ├── guard_model.py       # Optional ONNX/HuggingFace ML guard
│   ├── ip_filter.py         # IP allowlist/blocklist with CIDR and glob
│   ├── state.py             # Thread-safe stats tracker
│   ├── dashboard.py         # SSE event bus for live dashboard
│   ├── audit.py             # Structured JSON audit logging
│   └── config.py            # Configuration loader with env overrides
└── tests/
    ├── test_cache.py
    ├── test_egress.py
    ├── test_egress_ai.py
    ├── test_encoders.py
    ├── test_exfiltration.py
    ├── test_ingress.py
    ├── test_ingress_ai.py
    ├── test_rate_limiter.py
    ├── test_safety.py
    └── test_cyber.py
```

## Running Tests

```bash
python3 -m pytest tests/ -v
```

## Tech Stack

| Component | Technology |
|---|---|
| Runtime | Python 3.9+ |
| Web server | FastAPI + Uvicorn |
| HTTP client | httpx (async) |
| Token counting | tiktoken (optional, char/4 fallback) |
| Config | YAML via pyyaml (optional) |
| ML guard | ONNX Runtime or Transformers (optional) |
| Frontend | Vanilla HTML/CSS/JS — zero dependencies, zero CDN |

## License

Apache 2.0
