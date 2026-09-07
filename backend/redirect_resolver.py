"""
PhishGuard Redirect Resolver
============================

Detects when a URL is wrapped in one or more redirects (link shorteners,
open redirects, or attacker multi-hop chains) and resolves it to its FINAL
landing URL — the "base"/destination the user is actually taken to.

WHY THIS MATTERS:
  An attacker hides the real phishing destination behind 1..N redirect hops so
  the URL the user sees looks harmless (e.g. bit.ly/abc123 -> shorturl.at/x ->
  paypal.com.verify-account.xyz/login). Scanning only the ORIGINAL URL misses
  the destination entirely. This resolver unwraps the chain FIRST so the rest
  of the pipeline analyzes the page the user actually lands on.

SECURITY / DESIGN:
  - SSRF-guarded: a hop targeting a private/reserved/internal network is never
    followed (reuses sandbox._is_private_host).
  - Only http/https schemes are followed.
  - Bounded hop count, per-hop timeout, and NO page content is downloaded
    (responses are closed immediately — this is a lightweight redirect probe).
  - Any failure degrades gracefully to the original URL (never blocks scans).
"""

from urllib.parse import urljoin, urlparse

import requests

from backend.sandbox import _is_private_host

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 6
REQUEST_TIMEOUT = 6.0
USER_AGENT = "PhishGuard-RedirectResolver/1.0 (+phishing safety analyzer)"


def resolve_redirects(url: str) -> dict:
    """
    Follow the redirect chain for `url` and report the final landing URL.
    Never raises.

    Returns:
      {
        "resolved": bool,          # True when final_url differs from input
        "final_url": str,          # URL the user ends up on (== url if none)
        "original_url": str,       # the input URL
        "redirect_chain": [        # [{url, status}, ..., {url, status, final: True}]
        "redirect_count": int,     # number of redirect hops followed
        "redirected": bool,        # True when at least one hop occurred
        "error": str | None,       # non-fatal note if the chain was truncated/blocked
      }
    """
    chain: list[dict] = []
    original = url
    current = url
    error = None

    def _host_of(u: str) -> str:
        try:
            return (urlparse(u).hostname or "").lower()
        except Exception:
            return ""

    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
            break
        # SSRF guard: never probe private/reserved/internal hosts.
        if _is_private_host(_host_of(current)):
            error = "redirect target reached a private/reserved host; chain stopped"
            break

        try:
            resp = requests.get(
                current,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
        except Exception as exc:
            error = f"redirect probe failed: {exc.__class__.__name__}"
            break

        # We only need the headers — never download the body.
        try:
            resp.close()
        except Exception:
            pass

        chain.append({"url": current, "status": resp.status_code})

        location = resp.headers.get("Location")
        if resp.is_redirect and location:
            current = urljoin(current, location)
            continue
        break

    if chain:
        chain[-1]["final"] = True
    else:
        # Nothing usable was obtained — report the input URL as final.
        chain.append({"url": url, "status": 0, "final": True})

    final_url = chain[-1]["url"]
    redirect_count = max(len(chain) - 1, 0)

    return {
        "resolved": final_url != original,
        "final_url": final_url,
        "original_url": original,
        "redirect_chain": chain,
        "redirect_count": redirect_count,
        "redirected": redirect_count > 0,
        "error": error,
    }