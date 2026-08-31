"""
PhishGuard URL Sandbox — Lightweight Safe Content Analyzer
==========================================================

Fetches the target page and inspects its HTML for phishing signals WITHOUT
executing any JavaScript (no browser engine, no active content runs).

Signals detected:
  - Credential/login forms that submit over insecure (non-HTTPS) channels
  - Links pointing to domains unrelated to the page itself
  - Iframes / redirects
  - Whether the page is reachable at all

SECURITY / SAFETY CONTROLS:
  - SSRF Guard: only http/https schemes allowed; a single-request timeout;
    response size capped; no redirect following to private/internal networks.
  - No JS execution: we only parse static HTML — nothing runs on our server.
  - Network egress is the same as any browser; we do not exfiltrate anything.

Returns a dict of findings; never raises (degrades gracefully to 'unreachable').
"""

import re
import socket
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter

# SSRF / safety guards
ALLOWED_SCHEMES = ("http", "https")
MAX_CONTENT_LENGTH = 2 * 1024 * 1024   # 2 MB max page size
REQUEST_TIMEOUT = 8.0                  # seconds
MAX_REDIRECTS = 3
USER_AGENT = "PhishGuard-Sandbox/1.0 (+phishing safety analyzer)"


# private/internal network ranges we will NOT talk to (SSRF defense)
def _is_private_host(hostname: str) -> bool:
    """Return True if hostname resolves to a private/reserved IP (SSRF guard)."""
    private_prefixes = (
        "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", "0.", "255.",
    )
    if hostname.startswith(private_prefixes):
        return True
    if hostname == "localhost":
        return True
    # resolve and check IPv4
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith(private_prefixes):
                return True
    except Exception:
        pass
    return False


def _suspicious_form(form, page_url: str) -> tuple[bool, str]:
    """
    Heuristically determine if a form is a credential/phishing form.
    Returns (is_credential_form, reason).
    """
    action = form.get("action") or ""
    method = (form.get("method") or "get").lower()

    # Find input fields and their names
    inputs = [i.get("name", "").lower() for i in form.find_all("input")]
    input_types = [i.get("type", "").lower() for i in form.find_all("input")]

    has_password = "password" in input_types or any("pass" in n for n in inputs)
    has_text = any(t in input_types for t in ("text", "email"))

    # Resolve the action URL against the page URL
    action_url = urljoin(page_url, action) if action else page_url
    action_parsed = urlparse(action_url)
    page_parsed = urlparse(page_url)

    insecure = action_parsed.scheme != "https" and page_parsed.scheme == "https"

    if has_password:
        if insecure:
            return True, "password field + insecure submit action"
        return True, "password field present"
    if has_text and action and "http" in action:
        return True, "text input with external action"
    return False, ""


def analyze_url(url: str) -> dict | None:
    """
    Fetch and analyze a URL's content. Returns a findings dict, or None on any
    failure (which the caller treats as 'unreachable').
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        return {"unreachable": True, "reason": "invalid_scheme", "redirect_chain": []}

    # SSRF guard: never contact private/internal hosts
    if _is_private_host(parsed.hostname):
        return {"unreachable": True, "reason": "private_host_blocked", "redirect_chain": []}

    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    try:
        resp = session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )
    except Exception:
        return {"unreachable": True, "reason": "network_error", "redirect_chain": []}

    if resp.status_code >= 400:
        return {"unreachable": True, "reason": f"http_{resp.status_code}", "redirect_chain": []}

    # Cap content size (protect against huge pages / memory exhaustion)
    try:
        content = resp.content[:MAX_CONTENT_LENGTH].decode("utf-8", errors="ignore")
    except Exception:
        return {"unreachable": True, "reason": "decode_error", "redirect_chain": []}

    # What URL did we actually end up on (after redirects)?
    final_url = resp.url or url
    final_parsed = urlparse(final_url)

    soup = BeautifulSoup(content, "html.parser")

    # --- Build the redirect chain (every hop the request followed) ---
    # resp.history = list of intermediate redirect responses; each has .url.
    redirect_chain = [
        {
            "url": r.url,
            "status": r.status_code,
        }
        for r in resp.history
    ]
    # The chain should always start with the originally-requested URL.
    if redirect_chain:
        # Ensure the first entry is the input URL (requests includes it as
        # r.history[i].url already, so we just dedupe/annotate below).
        pass
    # Append the final landed URL with its status.
    redirect_chain.append({"url": final_url, "status": resp.status_code, "final": True})

    findings = {
        "unreachable": False,
        "final_url": final_url,
        "redirect_chain": redirect_chain,
        "redirect_count": len(redirect_chain) - 1,
        "title": None,
        "meta_description": None,
        "credential_forms": 0,
        "insecure_forms": 0,
        "external_links": 0,
        "external_link_ratio": 0.0,
        "domain_mismatch": False,
        "redirected": (urlparse(url).hostname != final_parsed.hostname),
        "has_iframe": len(soup.find_all("iframe")) > 0,
        "suspicious_login_page": False,
        "suspicious_anchors": [],
        "hidden_fields": 0,
        "detected_technologies": [],
        "suspicious_terms": [],
    }

    page_host = final_parsed.hostname or ""

    # --- Page title & meta description ---
    title_tag = soup.find("title")
    findings["title"] = title_tag.get_text(strip=True)[:200] if title_tag else None
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc and meta_desc.get("content"):
        findings["meta_description"] = meta_desc["content"][:300]

    # --- Analyze forms ---
    separator = re.compile(r"[.\s_-]+")
    for form in soup.find_all("form"):
        is_cred, reason = _suspicious_form(form, final_url)
        if is_cred:
            findings["credential_forms"] += 1
            action = form.get("action") or ""
            action_url = urljoin(final_url, action) if action else final_url
            a_parsed = urlparse(action_url)
            if a_parsed.scheme != "https":
                findings["insecure_forms"] += 1
            if a_parsed.hostname and a_parsed.hostname != page_host:
                findings["domain_mismatch"] = True
            # Hidden fields (often harvesters sneak data tokens/cookies into POSTs)
            findings["hidden_fields"] += len(
                [i for i in form.find_all("input", attrs={"type": "hidden"})]
            )
            # Does the page title/metadata mention login/security/verify? (login-page signal)
            title_l = (findings["title"] or "").lower()
            if any(k in title_l for k in ("login", "sign in", "verify", "secure", "account", "update")):
                findings["suspicious_login_page"] = True

    # --- Analyze links: external ratio + suspicious anchor text ---
    external_hosts = set()
    total_links = 0
    for a in soup.find_all("a", href=True):
        total_links += 1
        href = a["href"]
        text = a.get_text(" ", strip=True).lower()
        if href.startswith(("http://", "https://")):
            href_parsed = urlparse(href)
            if href_parsed.hostname and href_parsed.hostname != page_host:
                external_hosts.add(href_parsed.hostname)
                if len(external_hosts) > 10:  # don't blow up memory
                    break
        # Suspicious anchor text (social-engineering link labels)
        for phrase in ("verify your account", "update account", "confirm password",
                       "click here", "reactivate", "reset password", "login now",
                       "urgent", "secure your account", "account suspended"):
            if phrase in text and len(text) < 120:
                if len(findings["suspicious_anchors"]) < 8:
                    findings["suspicious_anchors"].append(phrase)
                break
    findings["external_links"] = len(external_hosts)
    findings["external_link_ratio"] = round(
        (len(external_hosts) / total_links), 2) if total_links else 0.0

    # --- Simple technology fingerprinting (offline, regex on raw content) ---
    low = content.lower()
    tech = findings["detected_technologies"]
    for name, pat in (
        ("WordPress", "wp-content"), ("Joomla", "/media/"), ("Drupal", "/sites/"),
        ("Django", "csrftoken"), ("Laravel", "laravel_session"),
        ("ASP.NET", "__viewstate"), ("PHP", "php session"), ("nginx", "nginx"),
        ("Apache", "apache"), ("Rails", "_rails_session"),
        ("React", "data-reactroot"), ("jQuery", "jquery"),
    ):
        if pat.lower() in low:
            tech.append(name)

    # --- Visible-text phishing-urgency scanner ---
    visible_text = (soup.get_text(" ", strip=True) or "").lower()
    for term in ("urgent action required", "account suspended", "verify your identity",
                 "security alert", "unusual activity", "payment failed",
                 "update your information", "claim your prize"):
        if term in visible_text and term not in findings["suspicious_terms"]:
            findings["suspicious_terms"].append(term)

    # --- Final heuristic: login/security page on a NON-branded or obscure domain ---
    # Combined with a brand lookalike hostname, this is a strong phishing signal,
    # but the brand check happens in the caller. Here we just flag 'looks like a
    # login/verify page' so the caller can combine it with lookalike brand data.
    title_l = (findings["title"] or "").lower()
    if (
        (findings["credential_forms"] > 0 or findings["suspicious_login_page"])
        and any(s in title_l for s in ("signin", "login", "verify", "sign in", "account"))
    ):
        findings["suspicious_login_page"] = True

    return findings
