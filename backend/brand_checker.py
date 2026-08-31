"""
PhishGuard Visual Brand Similarity Checker
==========================================

Checks a scanned URL/hostname against known-good brand knowledge for
"lookalike" (typosquat / brand-similar) detection.

Backend: Google Safe Browsing Lookup API (https://developers.google.com/safe-browsing/v4/lookup-api).

SECURITY / DESIGN:
  - The Google API key is read from the environment/config. If it is a
    placeholder/missing, the check is DORMANT and returns a neutral result —
    the scanner still works without it.
  - The external call is time-boxed and failure-tolerant: any network error or
    non-200 response degrades to "no external brand signal", never raises.
  - The URL sent is the parsed hostname (no full path), minimising data sent
    to Google. No API key is ever logged.
  - No user secrets are transmitted.

Returns a dict:
  {
    "checked": bool,          # True if an external brand check actually ran
    "brand": str or None,     # matching known brand, if any
    "brand_url": str or None, # canonical brand URL
    "threat_matches": list,   # any Safe Browsing threat matches
    "verdict": str,           # 'phishing' | 'lookalike' | 'clean' | 'no_data'
    "reason": str,            # human-readable explanation
  }
"""

import os
from urllib.parse import urlparse

import requests

# Google Safe Browsing Lookup API endpoint
GSB_LOOKUP_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Placeholder that means "not configured yet"
_PLACEHOLDERS = {"", "YOUR_GOOGLE_API_KEY", "CHANGE-ME", "placeholder"}


def _is_placeholder(key: str | None) -> bool:
    if not key:
        return True
    return key.strip().lower() in {p.lower() for p in _PLACEHOLDERS}


def get_api_key() -> str | None:
    """Return the Google Safe Browsing API key from env/config, or None."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if _is_placeholder(key):
        return None
    return key


def lookup_url(url: str, threat_types=None) -> dict:
    """
    Brand-similarity / external reputation check for a URL.
    Never raises — always returns a dict.

    The BUILT-IN brand-lookalike heuristic ALWAYS runs (works offline, no key).
    The external Google Safe Browsing lookup only runs when a real API key is
    configured; otherwise that part is dormant (reported as 'not configured').
    """
    # --- Built-in lexical lookalike check (always runs, offline) ---
    local_brand = _brand_lookalike(url)
    if local_brand:
        return {
            "checked": True,
            "external_checked": False,
            "brand": local_brand["brand"],
            "brand_url": local_brand["url"],
            "threat_matches": [],
            "verdict": "lookalike",
            "reason": (
                f"Domain visually/lexically resembles '{local_brand['brand']}' "
                f"({local_brand['url']}) but is a different site."
            ),
        }

    key = get_api_key()
    if key is None:
        return {
            "checked": False,
            "external_checked": False,
            "brand": None,
            "brand_url": None,
            "threat_matches": [],
            "verdict": "no_data",
            "reason": "No brand-lookalike found; external Google Safe Browsing API not configured (add a GOOGLE_SAFE_BROWSING_API_KEY to enable reputation lookups).",
        }

    if threat_types is None:
        threat_types = [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
        ]

    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": threat_types,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            GSB_LOOKUP_URL,
            params={"key": key},
            json=payload,
            timeout=6.0,
        )
    except Exception:
        return {
            "checked": True,
            "external_checked": True,
            "brand": None,
            "brand_url": None,
            "threat_matches": [],
            "verdict": "no_data",
            "reason": "External brand/reputation API could not be reached.",
        }

    if resp.status_code != 200:
        return {
            "checked": True,
            "external_checked": True,
            "brand": None,
            "brand_url": None,
            "threat_matches": [],
            "verdict": "no_data",
            "reason": f"External brand/reputation API returned HTTP {resp.status_code}.",
        }

    try:
        data = resp.json()
    except Exception:
        return {
            "checked": True,
            "external_checked": True,
            "brand": None,
            "brand_url": None,
            "threat_matches": [],
            "verdict": "no_data",
            "reason": "External brand/reputation API returned unparseable data.",
        }

    matches = data.get("matches", [])
    if matches:
        threats = [m.get("threatType", "unknown") for m in matches]
        return {
            "checked": True,
            "external_checked": True,
            "brand": None,
            "brand_url": None,
            "threat_matches": threats,
            "verdict": "phishing",
            "reason": f"Google Safe Browsing flagged this URL: {', '.join(threats)}.",
        }

    return {
        "checked": True,
        "external_checked": True,
        "brand": None,
        "brand_url": None,
        "threat_matches": [],
        "verdict": "clean",
        "reason": "No external threat or brand-lookalike matches.",
    }


# ---------------------------------------------------------------------------
# Lightweight brand-lookalike heuristic (lexical, runs even without a key)
# A curated list of the most-abused brands and their canonical domains.
# ---------------------------------------------------------------------------
_TOP_BRANDS = {
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "youtube": "youtube.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "microsoftonline": "microsoftonline.com",   # legit Azure/Office tenant domain
    "office": "office.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "github": "github.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "ebay": "ebay.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "payoneer": "payoneer.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "steam": "steampowered.com",
    "spotify": "spotify.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
    "tiktok": "tiktok.com",
    "snapchat": "snapchat.com",
    "telegram": "telegram.org",
    "outlook": "outlook.com",
    "icloud": "icloud.com",
    "zoom": "zoom.us",
    "whatsappweb": "web.whatsapp.com",
}


def _normalize(s: str) -> str:
    """Map leetspeak digits to their common letter lookalikes for comparison."""
    table = str.maketrans({
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
        "7": "t", "2": "z", "6": "b", "8": "b", "9": "g",
    })
    return s.translate(table)


def is_known_brand_domain(hostname: str) -> bool:
    """
    Return True if hostname is a canonical known-good brand domain or a
    subdomain of one (e.g. www.google.com, accounts.google.com, paypal.com).
    Used to PROTECT legitimate brands from being auto-blacklisted by a
    misclassifying ML model.
    """
    if not hostname:
        return False
    h = hostname.lower()
    for canonical in set(_TOP_BRANDS.values()):
        if not canonical:
            continue
        if h == canonical or h.endswith("." + canonical):
            return True
    return False


def _tld(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return parts[-2].lower()
    return hostname.lower()


def _brand_lookalike(url: str) -> dict | None:
    """Detect a hostname that looks like a known brand (typosquat/lookalike)."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except Exception:
        return None
    if not hostname or hostname.count(".") < 1:
        return None

    site_label = _tld(hostname)
    host_no_dots = hostname.replace(".", "")
    norm_host_no_dots = _normalize(host_no_dots)
    norm_label = _normalize(site_label)

    # NEVER flag any brand's own canonical domain or its subdomains:
    #   facebook.com, www.facebook.com, m.facebook.com, accounts.google.com,
    #   login.microsoftonline.com, tenant.office.com ...
    canonical_domains = set(_TOP_BRANDS.values()) - {None}
    for canonical in canonical_domains:
        if hostname == canonical or hostname.endswith("." + canonical):
            return None
    # Also skip when the site's own label is exactly a brand domain label
    label_to_brand = {}
    for brand_raw, canonical in _TOP_BRANDS.items():
        brand = brand_raw.split("@")[0].lower()
        label_to_brand[brand] = canonical
    if site_label in label_to_brand:
        return None

    import re
    # Word-boundary regex so that "x" matches "x.com" but NOT the letter in
    # "example"; and "paypal" matches "paypal-login.xyz" cleanly.
    def boundary_match(needle: str, haystack: str) -> bool:
        return re.search(r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])", haystack) is not None

    for brand_raw, canonical in _TOP_BRANDS.items():
        brand = brand_raw.split("@")[0].lower()
        # For very short brands (<4 chars), require a word-boundaried exact-ish
        # match to avoid single-letter false positives (e.g. "x" in "example").
        if len(brand) < 4:
            if brand == site_label or boundary_match(brand, hostname.replace(".", "-")):
                return {"brand": brand_raw.title(), "url": canonical}
            continue
        # --- Case 1: brand text embedded in the host (word-boundaried, leet-aware) ---
        if boundary_match(brand, hostname) or boundary_match(_normalize(brand), norm_host_no_dots):
            return {"brand": brand_raw.title(), "url": canonical}
        # --- Case 2: near-match TLD label (typosquat / leetspeak) ---
        norm_brand = _normalize(brand)
        import difflib
        if difflib.SequenceMatcher(None, norm_label, norm_brand).ratio() >= 0.82:
            return {"brand": brand_raw.title(), "url": canonical}

    return None

