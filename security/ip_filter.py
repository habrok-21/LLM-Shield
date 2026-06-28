"""
ShieldLLM — IP Allowlist / Blocklist Filter.

Evaluates client IP addresses against configurable allowlists and
blocklists before any other processing occurs. This is the outermost
security layer.

Lists can be:
  - Single IPs:       "192.168.1.1"
  - CIDR ranges:      "10.0.0.0/8"
  - Wildcard globs:   "192.168.*.*"
"""

import ipaddress
import logging
import re
from typing import Optional

logger = logging.getLogger("shieldllm.ip_filter")


def _ip_matches_glob(ip: str, pattern: str) -> bool:
    """Match an IP against a wildcard glob like '192.168.*.*'."""
    pat = re.escape(pattern).replace(r"\*", r"\d+").replace(r"\?", r"\d")
    return bool(re.match(f"^{pat}$", ip))


class IPFilter:
    """Evaluates client IPs against allow/block lists."""

    def __init__(
        self,
        allowlist: Optional[list] = None,
        blocklist: Optional[list] = None,
    ):
        self._allowlist = allowlist or []
        self._blocklist = blocklist or []

    def is_allowed(self, client_ip: str) -> tuple[bool, Optional[str]]:
        """Check if an IP is allowed.

        Returns (True, None) if allowed.
        Returns (False, reason) if blocked.
        """
        # 1. Blocklist check (fast path)
        reason = self._match_list(client_ip, self._blocklist)
        if reason:
            logger.info("ip_blocked ip=%s reason=%s", client_ip, reason)
            return False, reason

        # 2. Allowlist check (if non-empty, must match)
        if self._allowlist:
            reason = self._match_list(client_ip, self._allowlist)
            if not reason:
                return False, f"IP {client_ip} not in allowlist"
            # matched allowlist — proceed

        return True, None

    @staticmethod
    def _match_list(ip: str, ip_list: list) -> Optional[str]:
        """Return a description if `ip` matches any entry in `ip_list`."""
        for entry in ip_list:
            entry = entry.strip()
            if not entry:
                continue

            # CIDR
            if "/" in entry:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return f"matched CIDR {entry}"
                except ValueError:
                    continue

            # Wildcard glob
            if "*" in entry or "?" in entry:
                if _ip_matches_glob(ip, entry):
                    return f"matched glob {entry}"

            # Exact match
            if ip == entry:
                return f"matched exact {entry}"

        return None

    @property
    def config(self) -> dict:
        return {
            "allowlist": self._allowlist,
            "blocklist": self._blocklist,
        }
