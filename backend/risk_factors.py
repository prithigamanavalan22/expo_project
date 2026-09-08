"""
PhishGuard Structured Risk Factors
==================================

Produces an exhaustive, structured list of individual risk factors for a URL:
  [{ code, name, severity(low|medium|high|critical), description }]

Each factor is independently verifiable and gives the user a clear
"here is exactly why" breakdown. This powers both the API and the
extension's risk-factor display.

No new dependencies beyond the stdlib.
"""

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Structured factor helper
# ---------------------------------------------------------------------------
def _f(code: str, name: str, severity: str, description: str) -> dict:
    """Build a factor dict. `status` is a presentational mapping of `severity`:
    critical/high -> dangerous, medium/low -> warning, and the no-signals
    marker (code='no_signals') -> safe.
    """
    status = {
        "critical": "danger",
        "high": "danger",
        "medium": "warning",
        "low": "warning",
    }.get(severity, "warning")
    if code == "no_signals":
        status = "safe"
    return {
        "code": code,
        "name": name,
        "severity": severity,
        "status": status,
        "description": description,
    }


_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_SUSPICIOUS_WORDS = [
    "secure", "verify", "login", "account", "update", "confirm",
    "bank", "signin", "auth", "payment", "wallet", "unlock",
]


def risk_factors(url: str, hostname: str, sandbox: dict | None = None,
                 brand: dict | None = None, blacklisted: bool = False,
                 visual: dict | None = None) -> list[dict]:
    """Compute the full structured risk-factor list for a URL."""
    factors: list[dict] = []
    u = url.lower()
    h = (hostname or "").lower()

    # --- Blacklist (critical) ---
    if blacklisted:
        factors.append(_f(
            "blacklist", "Known phishing blacklist hit", "critical",
            "This domain is on the phishing blacklist.",
        ))

    # --- Length / obfuscation ---
    if len(url) > 75:
        factors.append(_f(
            "url_long", "Unusually long URL", "medium",
            f"URL is {len(url)} characters, a common obfuscation trick.",
        ))
    if "@" in u:
        factors.append(_f(
            "at_symbol", "'@' symbol present", "high",
            "The '@' symbol can hide the real destination host.",
        ))
    # -- double slash after scheme --
    scheme_end = u.find("://")
    if scheme_end != -1 and "//" in u[scheme_end + 3:]:
        factors.append(_f(
            "double_slash", "Double slash after domain", "medium",
            "'//' after the domain can mask the true host in some browsers.",
        ))

    # --- Host structure ---
    if _IP_RE.match(h):
        factors.append(_f(
            "ip_host", "Raw IP address host", "high",
            f"The host is a raw IP address ({h}), atypical for legitimate sites.",
        ))

    # hyphen count
    hyphens = h.count("-")
    if hyphens:
        factors.append(_f(
            "hyphens", "Hyphens in hostname", "low",
            f"The hostname contains {hyphens} hyphen(s); brands rarely use them.",
        ))

    # subdomain depth
    depth = max(h.count(".") - 1, 0)
    if depth >= 2:
        factors.append(_f(
            "deep_subdomains", "Deep subdomain nesting", "medium",
            f"{depth} subdomain levels can mislead users about the real domain.",
        ))

    # suspicious tokens
    hits = [w for w in _SUSPICIOUS_WORDS if w in h]
    if hits:
        factors.append(_f(
            "suspicious_token", "Suspicious host tokens", "high",
            f"Hostname contains phishing-typical words: {', '.join(sorted(set(hits)))}.",
        ))

    # --- Transport ---
    if not u.startswith("https://"):
        factors.append(_f(
            "no_https", "No HTTPS", "medium",
            "Data is sent in plaintext; legitimate login pages always use HTTPS.",
        ))

    # --- Path / query ---
    q = urlparse(url).query
    if q and len(q.split("&")) >= 5:
        factors.append(_f(
            "many_params", "Excessive query parameters", "low",
            "Many query parameters can smuggle malicious data.",
        ))

    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)
    if digit_ratio > 0.25:
        factors.append(_f(
            "digit_heavy", "Digit-heavy URL", "medium",
            f"{digit_ratio:.0%} of the URL is digits, typical of generated links.",
        ))

    # --- Sandbox (content) factors ---
    if sandbox:
        if sandbox.get("unreachable"):
            factors.append(_f(
                "unreachable", "Page unreachable", "low",
                "Could not fetch page content for deep analysis.",
            ))
        else:
            if sandbox.get("credential_forms"):
                factors.append(_f(
                    "cred_forms", "Credential/login forms", "high",
                    f"Page contains {sandbox['credential_forms']} login/password form(s).",
                ))
            if sandbox.get("insecure_forms"):
                factors.append(_f(
                    "insecure_forms", "Forms submit over plaintext", "critical",
                    "Login forms submit WITHOUT HTTPS — credentials can be intercepted.",
                ))
            if sandbox.get("domain_mismatch"):
                factors.append(_f(
                    "domain_mismatch", "Forms/links point elsewhere", "high",
                    "Page forms point to a different domain than the page itself.",
                ))
            if sandbox.get("redirect_count"):
                factors.append(_f(
                    "redirects", "Redirect chain present", "medium",
                    f"Request followed {sandbox['redirect_count']} redirect(s) — see redirect chain.",
                ))
            if sandbox.get("has_iframe"):
                factors.append(_f(
                    "iframe", "Hidden iframe", "medium",
                    "Page embeds an iframe, sometimes used to load scams invisibly.",
                ))
            if sandbox.get("external_links"):
                factors.append(_f(
                    "external_links", "Links to unrelated domains", "low",
                    f"Page links to {sandbox['external_links']} unrelated domain(s).",
                ))
            if sandbox.get("suspicious_login_page"):
                factors.append(_f(
                    "suspicious_login_page", "Login/security verification page", "high",
                    "Page presents itself as a login or account-verification screen.",
                ))
            if sandbox.get("suspicious_anchors"):
                factors.append(_f(
                    "social_engineering", "Social-engineering link text", "high",
                    f"Links include pressure phrases like: {', '.join(sandbox['suspicious_anchors'][:5])}.",
                ))
            if sandbox.get("hidden_fields"):
                factors.append(_f(
                    "hidden_fields", "Hidden form fields", "medium",
                    f"Forms contain {sandbox['hidden_fields']} hidden input field(s) — often used to smuggle credentials to an attacker server.",
                ))
            if sandbox.get("external_link_ratio") and sandbox["external_link_ratio"] >= 0.9:
                factors.append(_f(
                    "external_links_only", "Nearly all links are external", "medium",
                    f"{int(sandbox['external_link_ratio']*100)}% of links point away from this domain.",
                ))
            if sandbox.get("suspicious_terms"):
                factors.append(_f(
                    "urgency_scam", "Urgency/scam language", "medium",
                    f"Page text uses pressure language: {', '.join(sandbox['suspicious_terms'][:4])}.",
                ))
            if sandbox.get("detected_technologies"):
                pass  # tech fingerprint is informational, not a risk factor

    # --- Brand-similarity / external signal ---
    if brand:
        if brand.get("verdict") == "lookalike" and brand.get("brand"):
            factors.append(_f(
                "brand_lookalike", "Lookalike brand domain", "critical",
                f"Domain resembles '{brand['brand']}' ({brand.get('brand_url')}) but is different.",
            ))
        elif brand.get("verdict") == "phishing":
            factors.append(_f(
                "external_phishing", "Flagged by external service", "critical",
                brand.get("reason") or "External reputation service flagged this URL.",
            ))

    # --- Visual brand-similarity factor (screenshot + image comparison) ---
    if visual and visual.get("checked"):
        vv = visual.get("verdict")
        sim = float(visual.get("similarity") or 0.0)
        matched = visual.get("best_brand")
        if vv == "impersonation":
            factors.append(_f(
                "visual_impersonation", "Visual brand impersonation", "critical",
                f"Rendered page visually imitates '{matched}' ({visual.get('best_brand_url')}) "
                f"at {sim:.0f}% similarity but is hosted on a different site.",
            ))
        elif vv == "lookalike":
            factors.append(_f(
                "visual_lookalike", "Visual brand lookalike", "high",
                f"Rendered page is {sim:.0f}% visually similar to '{matched}' — possible lookalike.",
            ))

    if not factors:
        factors.append(_f(
            "no_signals", "No phishing indicators", "low",
            "No obvious phishing indicators were found.",
        ))

    # Sort: critical > high > medium > low
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    factors.sort(key=lambda f: _order.get(f["severity"], 4))
    return factors
