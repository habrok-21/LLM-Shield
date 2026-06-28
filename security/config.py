"""
ShieldLLM — Configuration Loader.

Loads settings from a YAML config file with environment variable
overrides. The config file path is set via SHIELDLLM_CONFIG env var
(defaults to ./config.yml if it exists).

Priority (lowest → highest):
  1. Built-in defaults
  2. config.yml file
  3. Environment variables
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("shieldllm.config")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

# CHANGE_ME: Replace default URLs with your LLM provider or use env vars / config.yml
DEFAULTS: Dict[str, Any] = {
    "server": {
        "port": 8080,
        "host": "0.0.0.0",
    },
    "upstream": {
        "primary_url": "https://api.openai.com/v1/chat/completions",
        "backup_url": "https://api.deepseek.com/v1/chat/completions",
        "timeout": 60.0,
        "per_endpoint_timeout": 30.0,
    },
    "rate_limiter": {
        "window_seconds": 60,
        "max_tokens": 400,
    },
    "circuit_breaker": {
        "threshold": 3,
        "reset_seconds": 300,
    },
    "egress": {
        "max_response_chars": 10000,
    },
    "ingress": {
        "max_message_chars": 16000,
    },
    "cache": {
        "max_entries": 1000,
        "ttl_seconds": 3600,
    },
    "ip_filter": {
        "allowlist": [],
        "blocklist": [],
    },
    "logging": {
        "level": "INFO",
        "json": True,
    },
}


# ---------------------------------------------------------------------------
# Env var overrides
# ---------------------------------------------------------------------------

ENV_MAP = {
    "PORT": ("server", "port", int),
    "UPSTREAM_TIMEOUT": ("upstream", "timeout", float),
    "LLM_PRIMARY_URL": ("upstream", "primary_url", str),
    "LLM_BACKUP_URL": ("upstream", "backup_url", str),
    "LLM_TIMEOUT": ("upstream", "per_endpoint_timeout", float),
    "CB_THRESHOLD": ("circuit_breaker", "threshold", int),
    "CB_RESET_SECONDS": ("circuit_breaker", "reset_seconds", int),
    "MAX_RESPONSE_CHARS": ("egress", "max_response_chars", int),
    "MAX_MESSAGE_CHARS": ("ingress", "max_message_chars", int),
    "SHIELDLLM_LOG_LEVEL": ("logging", "level", str),
}


def _apply_env_overrides(cfg: dict) -> dict:
    for env_key, (section, key, cast) in ENV_MAP.items():
        val = os.environ.get(env_key)
        if val is not None:
            try:
                cfg.setdefault(section, {})[key] = cast(val)
            except (ValueError, TypeError) as exc:
                logger.warning("config_override_error key=%s value=%s error=%s", env_key, val, exc)
    return cfg


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

_config: Optional[Dict[str, Any]] = None


def load(config_path: Optional[str] = None) -> dict:
    """Load configuration, merging file + env overrides + defaults."""
    global _config

    cfg = dict(DEFAULTS)  # deep enough for our use

    # Load YAML file
    if config_path is None:
        config_path = os.environ.get("SHIELDLLM_CONFIG", "config.yml")
    yaml_path = Path(config_path)
    if yaml_path.is_file():
        try:
            import yaml
            with open(yaml_path) as f:
                file_cfg = yaml.safe_load(f) or {}
            _deep_merge(cfg, file_cfg)
            logger.info("config_loaded path=%s", yaml_path)
        except ImportError:
            logger.warning("pyyaml not installed; skipping config file")
        except Exception as exc:
            logger.warning("config_load_error path=%s error=%s", yaml_path, exc)
    else:
        logger.debug("config_file_not_found path=%s", yaml_path)

    cfg = _apply_env_overrides(cfg)
    _config = cfg
    return cfg


def get() -> dict:
    """Return the loaded config (loads on first call)."""
    global _config
    if _config is None:
        _config = load()
    return _config


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
