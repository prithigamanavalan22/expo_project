"""
PhishGuard DNS Validation
=========================

Pre-analysis validation gate for user-entered URLs.

This module performs TWO lightweight checks BEFORE the PhishGuard phishing
engine runs:

  1. URL FORMAT  — the trimmed input must carry an http:// or https:// scheme
                   and a parseable hostname.
  2. DNS REACHABILITY — the hostname must resolve via the SYSTEM RESOLVER
                   (socket.getaddrinfo). This is pure DNS lookup.

IMPORTANT DISTINCTIONS:
  - DNS resolution never contacts the website. It does NOT open, visit, crawl,
    or execute the entered URL, and it sends no credentials.
  - A resolvable domain is NOT proof the site is safe or that an HTTP/HTTPS
    server is even available. This gate only filters clearly-garbage or
    nonexistent domains; the actual safety verdict comes AFTER it, from the
    existing PhishGuard engine (ML + lexical + sandbox + brand checks).

ERROR HANDLING:
  All failure modes below are collapsed into a clean dict — the caller never
  sees a raw Python exception (socket.gaierror, timeout, ...):
    - empty/missing hostname
    - DNS resolution failure (NXDOMAIN etc.)
    - DNS timeout
    - transient network errors during resolution
"""

import re
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from urllib.parse import urlparse

DNS_TIMEOUT = 5.0  # seconds; the DNS lookup is abandoned after this

_SCHEME_RE = re.compile(r"^(?:https?)://", re.IGNORECASE)


def check_dns(hostname: str, timeout: float = DNS_TIMEOUT) -> dict:
    """Resolve `hostname` through the system resolver.  Never raises.

    Performs `socket.getaddrinfo` only — an A/AAAA lookup. No socket is ever
    connected, so the URL is NOT opened or visited.

    Returns:
      {"dns_valid": bool, "hostname": str, "error": str | None}
      `error` is a short, safe label ('dns_timeout', 'no_records',
      'resolution_failed', 'network_error', 'empty hostname', ...).
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return {"dns_valid": False, "hostname": "", "error": "empty hostname"}

    # getaddrinfo can block for a long time on slow resolvers / dead routers,
    # so run it in a short-lived worker with a deadline.
    def _resolve():
        return socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                addrinfo = pool.submit(_resolve).result(timeout=timeout)
            except FutureTimeout:
                return {"dns_valid": False, "hostname": host, "error": "dns_timeout"}
        if not addrinfo:
            return {"dns_valid": False, "hostname": host, "error": "no_records"}
        return {"dns_valid": True, "hostname": host, "error": None}
    except socket.gaierror as exc:
        # NXDOMAIN / no address records / resolver hiccup — all reported as a
        # single clean failure label (raw error text is never forwarded).
        label = "no_records"
        ecode = getattr(exc, "errno", None)
        if ecode is None or ecode == socket.EAI_NONAME:
            label = "no_records"      # name does not exist
        else:
            label = "resolution_failed"
        return {"dns_valid": False, "hostname": host, "error": label}
    except OSError:
        return {"dns_valid": False, "hostname": host, "error": "network_error"}
    except Exception:
        return {"dns_valid": False, "hostname": host, "error": "unknown"}


def extract_hostname(raw_url: str) -> str:
    """Parse the hostname out of a URL.  Empty string when malformed."""
    try:
        parsed = urlparse((raw_url or "").strip())
        host = parsed.hostname or ""
        return host.strip().lower().rstrip(".")
    except Exception:
        return ""


def validate_url_dns(raw_url: str) -> dict:
    """Full pre-analysis gate: URL format + hostname + DNS resolution.

    Returns:
      {
        "url_valid": bool,   # False → caller must stop and show "Is not valid URL"
        "hostname": str,
        "dns_valid": bool,
        "message": str,      # short headline for the UI
        "explanation": str,  # short human explanation for the UI
      }
    Never raises. `url_valid` is False when the format is bad OR the hostname
    did not resolve through DNS.
    """
    text = (raw_url or "").strip()
    hostname = extract_hostname(text)

    if not _SCHEME_RE.match(text) or not hostname:
        return {
            "url_valid": False,
            "hostname": hostname,
            "dns_valid": False,
            "message": "Is not valid URL",
            "explanation": "The entered text is not a valid HTTP/HTTPS URL.",
        }

    dns = check_dns(hostname)
    if not dns["dns_valid"]:
        return {
            "url_valid": False,
            "hostname": hostname,
            "dns_valid": False,
            "message": "Is not valid URL",
            "explanation": "The entered URL does not resolve to a valid DNS domain.",
        }

    return {
        "url_valid": True,
        "hostname": dns["hostname"],
        "dns_valid": True,
        "message": "URL is reachable through DNS",
        "explanation": "Continue to PhishGuard analysis...",
    }