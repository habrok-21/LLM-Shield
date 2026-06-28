"""
ShieldLLM — AI Reverse Proxy Firewall.

Integrates:
  - Ingress filtering (keywords, jailbreak regex, encoded payloads, ML guard)
  - Egress filtering  (code, PII, leak, repetition on non-streaming responses)
  - Streaming SSE inspection (real-time egress on token chunks)
  - Token-budget rate limiter with tiktoken-accurate counting
  - Dynamic upstream routing with circuit-breaker failover
  - Structured JSON audit logging + live SSE dashboard
  - Optional ML prompt-injection guard (ONNX or HuggingFace)
  - Semantic response caching
  - Live web dashboard with real-time stats, dynamic config, custom rules
"""

import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

from security import (
    AuditLogger,
    EgressResult,
    Router,
    SemanticCache,
    StreamInspector,
    TokenBucketRateLimiter,
    check_egress,
    check_encoded,
    check_guard_model,
    check_ingress,
    check_many_shot,
    check_length_ratio,
    cyber,
    event_bus,
    event_generator,
    exfiltration,
    get_many_shot_threshold,
    get_max_length_ratio,
    IPFilter,
    safety,
    set_many_shot_threshold,
    set_max_length_ratio,
    shield_config,
)
from security.ingress import (
    add_jailbreak_pattern,
    add_keyword,
    get_max_message_chars,
    list_jailbreak_patterns,
    list_keywords,
    remove_jailbreak_pattern,
    remove_keyword,
    set_max_message_chars,
)
from security.state import stats

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT = int(os.environ.get("PORT", "8080"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "60.0"))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, os.environ.get("SHIELDLLM_LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s SHIELDLLM %(levelname)s %(message)s",
)
logger = logging.getLogger("shieldllm")

audit = AuditLogger()


def _positive_int(value, name: str) -> int:
    v = int(value)
    if v <= 0:
        raise ValueError(f"{name} must be a positive integer, got {v}")
    return v

# ---------------------------------------------------------------------------
# Tokenizer (tiktoken — lazy loaded)
# ---------------------------------------------------------------------------

_tokenizer = None


def get_tokenizer():
    global _tokenizer
    if _tokenizer is None:
        try:
            import tiktoken
            _tokenizer = tiktoken.get_encoding("cl100k_base")
            logger.info("tokenizer_loaded engine=cl100k_base")
        except ImportError:
            logger.warning("tiktoken not installed; falling back to char/4 estimate")
    return _tokenizer


def count_tokens(text: str) -> int:
    tok = get_tokenizer()
    if tok:
        return len(tok.encode(text))
    return len(text) // 4


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

rate_limiter = TokenBucketRateLimiter()
router = Router()
cache = SemanticCache()
ip_filter = IPFilter()

_client: httpx.AsyncClient = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _client
    _client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT)
    yield
    await _client.aclose()


app = FastAPI(
    title="ShieldLLM",
    version="1.2.0",
    description="Lightweight open-source AI Reverse Proxy Firewall",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Helper: build response and publish audit event
# ---------------------------------------------------------------------------

def _event(event_type: str, data: dict):
    data["shieldllm_event"] = event_type
    event_bus.publish(data)


# ---------------------------------------------------------------------------
# Helper: ingress pipeline (keywords → encoded → ML guard)
# ---------------------------------------------------------------------------

def _check_ingress_pipeline(messages: list, total_prompt_length: int) -> str:
    ing = check_ingress(messages)
    if ing:
        return ing
    many_shot = check_many_shot(messages)
    if many_shot:
        return many_shot
    for msg in messages:
        content = msg.get("content", "")
        if not isinstance(content, str):
            continue
        # SSRF attempt detection
        ssrf = cyber.check_ssrf_attempt(content)
        if ssrf:
            return ssrf
        enc = check_encoded(content)
        if enc:
            return enc
        guard = check_guard_model(content)
        if guard and guard.get("injection"):
            score = guard.get("score", 0)
            return f"ML guard detected prompt injection (score={score:.3f})"
    return None


# ---------------------------------------------------------------------------
# IP filter middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def ip_filter_middleware(request: Request, call_next):
    if request.url.path in ("/health", "/metrics", "/events", "/dashboard", "/",
                            "/api/stats", "/api/config", "/api/events/history",
                            "/api/ip-filter", "/api/events/clear",
                            "/api/cache", "/api/cache/clear",
                            "/api/router/reset-circuit", "/api/rate-limiter/reset",
                            "/api/rules/ingress", "/api/rules/many-shot",
                            "/api/rules/length-ratio",
                            "/api/demo/event", "/api/demo/seed-cache"):
        return await call_next(request)
    client_ip = request.client.host if request.client else "unknown"
    allowed, reason = ip_filter.is_allowed(client_ip)
    if not allowed:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": f"ShieldLLM blocked: {reason}",
                    "type": "policy_violation",
                    "code": "ip_blocked",
                }
            },
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "ShieldLLM",
        "version": "1.2.0",
    }


@app.get("/metrics")
async def metrics():
    return {
        "rate_limiter": rate_limiter.config,
        "router": router.config,
        "cache": cache.config,
        "stats": stats.snapshot,
    }


@app.get("/events")
async def events(request: Request):
    """SSE endpoint: live stream of ShieldLLM security events."""
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

DASHBOARD_HTML: str = None


def _load_dashboard() -> str:
    global DASHBOARD_HTML
    if DASHBOARD_HTML is not None:
        return DASHBOARD_HTML
    path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    try:
        with open(path) as f:
            DASHBOARD_HTML = f.read()
    except FileNotFoundError:
        DASHBOARD_HTML = "<html><body><h1>Dashboard not found</h1></body></html>"
    return DASHBOARD_HTML


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    return HTMLResponse(content=_load_dashboard())


# ---------------------------------------------------------------------------
# REST API — Stats
# ---------------------------------------------------------------------------


@app.get("/api/stats")
async def api_stats():
    return stats.snapshot


@app.get("/api/events/history")
async def api_events_history(limit: int = 100):
    events = stats.snapshot["recent_events"]
    return events[-limit:]


@app.post("/api/events/clear")
async def api_events_clear():
    stats.clear_events()
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# REST API — Config
# ---------------------------------------------------------------------------


@app.get("/api/config")
async def api_config():
    return shield_config.get()


@app.post("/api/config")
async def api_config_update(body: dict, request: Request):
    cfg = shield_config.get()

    try:
        rate_limiter_section = body.get("rate_limiter", {})
        if "window_seconds" in rate_limiter_section:
            v = _positive_int(rate_limiter_section["window_seconds"], "window_seconds")
            rate_limiter.window_seconds = v
        if "max_tokens" in rate_limiter_section:
            v = _positive_int(rate_limiter_section["max_tokens"], "max_tokens")
            rate_limiter.max_tokens = v

        egress_section = body.get("egress", {})
        if "max_response_chars" in egress_section:
            from security.egress import set_max_response_chars
            set_max_response_chars(_positive_int(egress_section["max_response_chars"], "max_response_chars"))

        ingress_section = body.get("ingress", {})
        if "max_message_chars" in ingress_section:
            set_max_message_chars(_positive_int(ingress_section["max_message_chars"], "max_message_chars"))

        circuit_section = body.get("circuit_breaker", {})
        if "threshold" in circuit_section:
            router.circuit_breaker_threshold = _positive_int(circuit_section["threshold"], "threshold")
        if "reset_seconds" in circuit_section:
            router.circuit_breaker_reset = _positive_int(circuit_section["reset_seconds"], "reset_seconds")
    except (ValueError, TypeError) as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

    for section, values in body.items():
        if section in cfg and isinstance(cfg[section], dict) and isinstance(values, dict):
            cfg[section].update(values)

    _event("CONFIG_UPDATE", {"updates": list(body.keys())})
    return {"status": "ok", "config": cfg}


# ---------------------------------------------------------------------------
# REST API — Custom Ingress Rules
# ---------------------------------------------------------------------------


@app.get("/api/rules/ingress")
async def api_rules_ingress():
    return {
        "keywords": list_keywords(),
        "jailbreak_patterns": list_jailbreak_patterns(),
        "max_message_chars": get_max_message_chars(),
    }


@app.post("/api/rules/ingress/keywords")
async def api_add_keyword(body: dict):
    kw = body.get("keyword", "").strip()
    if not kw:
        return JSONResponse(status_code=400, content={"error": "keyword is required"})
    add_keyword(kw)
    _event("RULE_ADD", {"type": "keyword", "value": kw})
    return {"status": "ok", "keyword": kw}


@app.delete("/api/rules/ingress/keywords")
async def api_remove_keyword(body: dict):
    kw = body.get("keyword", "").strip()
    if not kw:
        return JSONResponse(status_code=400, content={"error": "keyword is required"})
    found = remove_keyword(kw)
    if not found:
        return JSONResponse(status_code=404, content={"error": "keyword not found"})
    _event("RULE_REMOVE", {"type": "keyword", "value": kw})
    return {"status": "ok", "keyword": kw}


@app.post("/api/rules/ingress/jailbreak")
async def api_add_jailbreak(body: dict):
    pattern = body.get("pattern", "").strip()
    if not pattern:
        return JSONResponse(status_code=400, content={"error": "pattern is required"})
    try:
        add_jailbreak_pattern(pattern)
    except re.error as e:
        return JSONResponse(status_code=400, content={"error": f"invalid regex: {e}"})
    _event("RULE_ADD", {"type": "jailbreak_pattern", "value": pattern})
    return {"status": "ok", "pattern": pattern}


@app.delete("/api/rules/ingress/jailbreak")
async def api_remove_jailbreak(body: dict):
    pattern = body.get("pattern", "").strip()
    if not pattern:
        return JSONResponse(status_code=400, content={"error": "pattern is required"})
    found = remove_jailbreak_pattern(pattern)
    if not found:
        return JSONResponse(status_code=404, content={"error": "pattern not found"})
    _event("RULE_REMOVE", {"type": "jailbreak_pattern", "value": pattern})
    return {"status": "ok", "pattern": pattern}


# ---------------------------------------------------------------------------
# REST API — IP Filter
# ---------------------------------------------------------------------------


@app.get("/api/ip-filter")
async def api_ip_filter():
    return ip_filter.config


@app.post("/api/ip-filter")
async def api_ip_filter_update(body: dict):
    if "allowlist" in body:
        ip_filter._allowlist = list(body["allowlist"])
    if "blocklist" in body:
        ip_filter._blocklist = list(body["blocklist"])
    _event("IP_FILTER_UPDATE", {
        "allowlist": ip_filter._allowlist,
        "blocklist": ip_filter._blocklist,
    })
    return {"status": "ok", "config": ip_filter.config}


# ---------------------------------------------------------------------------
# REST API — AI Security Config
# ---------------------------------------------------------------------------


@app.get("/api/rules/many-shot")
async def api_many_shot_config():
    return {"threshold": get_many_shot_threshold()}


@app.post("/api/rules/many-shot")
async def api_many_shot_update(body: dict):
    try:
        v = _positive_int(body.get("threshold", 20), "many_shot_threshold")
        set_many_shot_threshold(v)
        return {"status": "ok", "threshold": v}
    except (ValueError, TypeError) as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/rules/length-ratio")
async def api_length_ratio_config():
    return {"max_ratio": get_max_length_ratio()}


@app.post("/api/rules/length-ratio")
async def api_length_ratio_update(body: dict):
    try:
        v = _positive_int(body.get("max_ratio", 200), "max_length_ratio")
        set_max_length_ratio(v)
        return {"status": "ok", "max_ratio": v}
    except (ValueError, TypeError) as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


# ---------------------------------------------------------------------------
# REST API — Rate Limiter
# ---------------------------------------------------------------------------


@app.post("/api/rate-limiter/reset")
async def api_rate_limiter_reset(body: dict = None):
    if body and body.get("identity"):
        rate_limiter.reset(body["identity"])
        return {"status": "ok", "identity": body["identity"]}
    rate_limiter.reset_all()
    return {"status": "ok", "reset": "all"}


# ---------------------------------------------------------------------------
# REST API — Cache
# ---------------------------------------------------------------------------


@app.post("/api/cache/clear")
async def api_cache_clear():
    cache.clear()
    return {"status": "ok"}


@app.get("/api/cache")
async def api_cache_info():
    return cache.config


# ---------------------------------------------------------------------------
# REST API — Router
# ---------------------------------------------------------------------------


@app.post("/api/router/reset-circuit")
async def api_router_reset_circuit():
    router.circuit_open = False
    router.primary_failures = 0
    router.backup_failures = 0
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Demo API — Simulate events for dashboard demonstration
# ---------------------------------------------------------------------------


@app.post("/api/demo/event")
async def api_demo_event(body: dict, request: Request):
    """Simulate a security event so the dashboard shows non-zero stats.

    Use this in your demo script to demonstrate Egress Blocks,
    Cache Hits, Allowed requests with token counts, etc.

    body.event:       Event type (EGRESS_BLOCK, CACHE_HIT, ALLOWED, etc.)
    body.rule:        Description of what was triggered
    body.prompt_tokens:  Simulated prompt token count
    body.completion_tokens: Simulated completion token count
    """
    event_type = body.get("event", "EGRESS_BLOCK")
    rule = body.get("rule", "demo simulation")
    prompt_tokens = body.get("prompt_tokens", 50)
    completion_tokens = body.get("completion_tokens", 100)
    client_ip = request.client.host if request.client else "127.0.0.1"

    if event_type == "EGRESS_BLOCK":
        stats.record_egress_block(prompt_tokens, completion_tokens)
    elif event_type == "CACHE_HIT":
        stats.record_cache_hit()
    elif event_type == "ALLOWED":
        stats.record_allowed(prompt_tokens, completion_tokens)
    elif event_type == "INGRESS_BLOCK":
        stats.record_ingress_block(prompt_tokens)
    elif event_type == "RATE_LIMIT":
        stats.record_rate_limit(prompt_tokens)
    elif event_type == "UPSTREAM_ERROR":
        stats.record_upstream_error()

    _event(event_type, {
        "masked_client_ip": client_ip,
        "rule_triggered": rule,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "demo": True,
    })

    return {"status": "ok", "event": event_type, "rule": rule}


@app.post("/api/demo/seed-cache")
async def api_demo_seed_cache(body: dict):
    """Seed the semantic cache with a mock LLM response.

    The proxy checks the cache BEFORE requiring an API key, so a
    cached response will be served even without upstream access.
    Perfect for demonstrating Cache Hits in your demo.

    body.messages: messages list to cache (default: hello)
    body.response: response dict to cache (default: greeting)
    """
    messages = body.get("messages", [
        {"role": "user", "content": "Say hello"},
    ])
    response = body.get("response", {
        "id": "chatcmpl-demo",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-4",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello! Welcome to ShieldLLM. This is a cached response.",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 12, "total_tokens": 15},
    })

    cache.set(messages, response)
    return {"status": "ok", "cache_size": cache.size}


# ---------------------------------------------------------------------------
# Main proxy endpoint
# ---------------------------------------------------------------------------


@app.post("/v1/chat/completions")
async def proxy(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    request_id = request.headers.get("x-request-id")

    stats.record_request()

    # ------------------------------------------------------------------
    # 1. Parse body
    # ------------------------------------------------------------------
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": "Invalid JSON body",
                    "type": "invalid_request",
                    "param": None,
                    "code": "bad_json",
                }
            },
        )

    messages = body.get("messages", [])
    is_streaming = body.get("stream", False)

    total_prompt_length = sum(
        len(m.get("content", "")) for m in messages
        if isinstance(m.get("content"), str)
    )
    prompt_tokens = count_tokens(
        " ".join(m.get("content", "") for m in messages
                 if isinstance(m.get("content"), str))
    )

    # ------------------------------------------------------------------
    # 2. Ingress pipeline (keywords → encoded → ML guard)
    # ------------------------------------------------------------------
    ingress_violation = _check_ingress_pipeline(messages, total_prompt_length)
    if ingress_violation:
        stats.record_ingress_block(prompt_tokens)
        audit.ingress_block(
            client_ip=client_ip,
            rule=ingress_violation,
            message_count=len(messages),
            prompt_length=total_prompt_length,
            request_id=request_id,
        )
        _event("INGRESS_BLOCK", {
            "masked_client_ip": client_ip,
            "rule_triggered": ingress_violation,
            "prompt_tokens": prompt_tokens,
            "prompt_length": total_prompt_length,
            "message_count": len(messages),
        })
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": f"ShieldLLM blocked: {ingress_violation}",
                    "type": "policy_violation",
                    "param": None,
                    "code": "ingress_blocked",
                }
            },
        )

    # ------------------------------------------------------------------
    # 3. Auth header (checked BEFORE rate limiter and cache to prevent
    #    unauthenticated resource exhaustion)
    # ------------------------------------------------------------------
    api_key = request.headers.get("authorization", "")
    if not api_key:
        return JSONResponse(
            status_code=401,
            content={
                "error": {
                    "message": "Missing API key",
                    "type": "auth_error",
                    "param": None,
                    "code": "missing_api_key",
                }
            },
        )

    headers = {
        "Content-Type": "application/json",
        "Authorization": api_key,
    }

    # ------------------------------------------------------------------
    # 4. Rate limiter (token budget — tiktoken accurate)
    # ------------------------------------------------------------------
    if not rate_limiter.is_allowed(client_ip, prompt_tokens):
        stats.record_rate_limit(prompt_tokens)
        audit.rate_limit(
            client_ip=client_ip,
            rule=f"token_budget_exceeded (budget={rate_limiter.config['max_tokens']})",
            prompt_length=total_prompt_length,
            request_id=request_id,
        )
        _event("RATE_LIMIT", {
            "masked_client_ip": client_ip,
            "rule_triggered": "token_budget_exceeded",
            "prompt_tokens": prompt_tokens,
        })
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "message": (
                        f"ShieldLLM: token budget exceeded. "
                        f"Max {rate_limiter.config['max_tokens']} tokens per "
                        f"{rate_limiter.config['window_seconds']}s. "
                        f"Reset in {rate_limiter.get_reset_in(client_ip):.0f}s."
                    ),
                    "type": "rate_limit",
                    "param": None,
                    "code": "rate_limited",
                }
            },
        )

    # ------------------------------------------------------------------
    # 5. Semantic cache lookup (non-streaming only)
    # ------------------------------------------------------------------
    if not is_streaming:
        cached = cache.get(messages)
        if cached is not None:
            stats.record_cache_hit()
            audit.cache_hit(
                client_ip=client_ip,
                prompt_length=total_prompt_length,
                request_id=request_id,
            )
            _event("CACHE_HIT", {
                "masked_client_ip": client_ip,
                "prompt_length": total_prompt_length,
            })
            logger.info("cache_hit ip=%s", client_ip)
            return JSONResponse(status_code=200, content=cached)

    # ------------------------------------------------------------------
    # 6. Route to upstream
    # ------------------------------------------------------------------
    if is_streaming:
        target_url, provider_name = router.get_stream_target()
        if target_url is None:
            stats.record_upstream_error()
            audit.upstream_error(
                client_ip=client_ip,
                rule="circuit_open no backup configured",
                prompt_length=total_prompt_length,
                request_id=request_id,
            )
            return JSONResponse(
                status_code=503,
                content={"error": {"message": "All upstreams unavailable",
                                   "code": "all_upstreams_down"}},
            )
        return await _proxy_streaming(
            headers, body, messages, client_ip, request_id,
            total_prompt_length, prompt_tokens,
            target_url, provider_name,
        )

    status_code, response_data, provider = await router.forward(
        headers, body, _client
    )

    # ------------------------------------------------------------------
    # 7. Track upstream errors (5xx server errors + 429 rate-limited by upstream)
    # ------------------------------------------------------------------
    if status_code >= 400 and status_code != 200:
        stats.record_upstream_error()
        audit.upstream_error(
            client_ip=client_ip,
            rule=f"upstream_error provider={provider} status={status_code}",
            prompt_length=total_prompt_length,
            request_id=request_id,
        )
        _event("UPSTREAM_ERROR", {
            "masked_client_ip": client_ip,
            "provider": provider,
            "status_code": status_code,
        })
        return JSONResponse(status_code=status_code, content=response_data)

    # ------------------------------------------------------------------
    # 8. Extract token usage
    # ------------------------------------------------------------------
    usage = response_data.get("usage", {}) if status_code == 200 else {}
    completion_tokens = usage.get("completion_tokens", 0)

    # ------------------------------------------------------------------
    # 9. Egress filtering (non-streaming)
    # ------------------------------------------------------------------
    if status_code == 200:
        choices = response_data.get("choices", [])
        result = EgressResult()

        for choice in choices:
            content = choice.get("message", {}).get("content", "")
            check_egress(content, result)

            # AI security: exfiltration, safety, contradiction
            exfil = exfiltration.check_exfiltration(content)
            if exfil:
                result.reject(exfil)
            safe = safety.check_safety(content)
            if safe:
                result.reject(safe)
            contra = safety.check_contradiction(content)
            if contra:
                result.reject(contra)

            # Cyber security: internal leakage, malicious URLs, XSS, command injection
            inet = cyber.check_internal_leakage(content)
            if inet:
                result.reject(inet)
            malurl = cyber.check_malicious_url(content)
            if malurl:
                result.reject(malurl)
            xss = cyber.check_xss(content)
            if xss:
                result.reject(xss)
            cmdi = cyber.check_command_injection(content)
            if cmdi:
                result.reject(cmdi)

        # AI security: length ratio anomaly
        if total_prompt_length > 0:
            completion_len = sum(
                len(c.get("message", {}).get("content", ""))
                for c in choices
            )
            lr = check_length_ratio(total_prompt_length, completion_len)
            if lr:
                result.reject(lr)

        if result.flagged:
            stats.record_egress_block(prompt_tokens, completion_tokens)
            reasons = "; ".join(result.reasons)
            audit.egress_block(
                client_ip=client_ip,
                rule=reasons,
                prompt_length=total_prompt_length,
                completion_length=sum(
                    len(c.get("message", {}).get("content", ""))
                    for c in choices
                ),
                token_usage={
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
                request_id=request_id,
            )
            _event("EGRESS_BLOCK", {
                "masked_client_ip": client_ip,
                "rule_triggered": reasons,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            })
            logger.warning("egress_blocked ip=%s reasons=%s", client_ip, reasons)
            return JSONResponse(
                status_code=422,
                content={
                    "error": {
                        "message": f"ShieldLLM blocked: {reasons}",
                        "type": "policy_violation",
                        "param": None,
                        "code": "egress_blocked",
                    }
                },
            )

        cache.set(messages, response_data)

    # ------------------------------------------------------------------
    # 10. Log allowed
    # ------------------------------------------------------------------
    total_completion_length = sum(
        len(c.get("message", {}).get("content", ""))
        for c in response_data.get("choices", [])
    )
    stats.record_allowed(prompt_tokens, completion_tokens)
    audit.allowed(
        client_ip=client_ip,
        prompt_length=total_prompt_length,
        completion_length=total_completion_length,
        token_usage={
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
        provider=provider,
        request_id=request_id,
    )
    _event("ALLOWED", {
        "masked_client_ip": client_ip,
        "provider": provider,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    })

    return JSONResponse(status_code=status_code, content=response_data)


# ---------------------------------------------------------------------------
# Streaming proxy
# ---------------------------------------------------------------------------

async def _proxy_streaming(
    headers: dict,
    body: dict,
    messages: list,
    client_ip: str,
    request_id: str,
    total_prompt_length: int,
    prompt_tokens: int,
    target_url: str,
    provider_name: str,
) -> StreamingResponse:
    """Handle streaming requests: inspect chunks in real-time via StreamInspector.

    Uses the Router-provided target_url (respects circuit breaker) and records
    stats/audit events on completion.
    """
    inspector = StreamInspector()

    async def generate() -> AsyncGenerator[bytes, None]:
        completion_tokens = 0
        try:
            async with _client.stream(
                "POST", target_url, headers=headers, json=body,
            ) as upstream_resp:
                async for raw in upstream_resp.aiter_bytes():
                    action, payload = inspector.feed(raw)
                    if action == "forward":
                        yield raw
                    elif action == "error":
                        stats.record_egress_block(prompt_tokens, count_tokens(inspector.accumulated))
                        audit.egress_block(
                            client_ip=client_ip,
                            rule=inspector.violation or "stream violation",
                            prompt_length=total_prompt_length,
                            completion_length=len(inspector.accumulated),
                            token_usage={
                                "prompt_tokens": prompt_tokens,
                                "completion_tokens": count_tokens(inspector.accumulated),
                            },
                            request_id=request_id,
                        )
                        _event("EGRESS_BLOCK", {
                            "masked_client_ip": client_ip,
                            "rule_triggered": inspector.violation,
                            "prompt_tokens": prompt_tokens,
                            "stream": True,
                        })
                        yield payload.encode()
                        return
                    elif action == "done":
                        yield raw
                        completion_tokens = count_tokens(inspector.accumulated)
                        break

            # Stream completed successfully
            stats.record_allowed(prompt_tokens, completion_tokens)
            audit.allowed(
                client_ip=client_ip,
                prompt_length=total_prompt_length,
                completion_length=len(inspector.accumulated),
                token_usage={
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens,
                },
                provider=provider_name,
                request_id=request_id,
            )
            _event("ALLOWED", {
                "masked_client_ip": client_ip,
                "provider": provider_name,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "stream": True,
            })
            return
        except Exception as exc:
            logger.error("stream_error ip=%s error=%s", client_ip, exc)
            stats.record_upstream_error()
            audit.upstream_error(
                client_ip=client_ip,
                rule=f"stream_error provider={provider_name}",
                prompt_length=total_prompt_length,
                request_id=request_id,
            )
            _event("UPSTREAM_ERROR", {
                "masked_client_ip": client_ip,
                "provider": provider_name,
                "stream": True,
            })
            error_event = json.dumps({
                "error": {
                    "message": f"ShieldLLM upstream stream error",
                    "type": "upstream_error",
                    "code": "stream_error",
                }
            })
            yield f"data: {error_event}\n\ndata: [DONE]\n\n".encode()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=PORT, reload=False)
