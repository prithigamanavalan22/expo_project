"""
Feature Extraction Module for URL Phishing Detection.
Extracts 8+ lexical features from a raw URL string for ML classification.
"""

import re
from urllib.parse import urlparse


def extract_features(url: str) -> list[float]:
    """
    Extract lexical features from a URL string.

    Features extracted (8 primary + 2 bonus = 10 total):
      1. url_length          - Total character count of the URL
      2. has_at_symbol       - Whether the URL contains '@' (credential spoofing)
      3. has_double_slash    - Whether '//' appears after the protocol (redirect trick)
      4. uses_ip_address     - Whether the host is a raw IP address
      5. hyphen_count        - Number of hyphens in the domain (brand impersonation)
      6. has_https           - Whether the URL uses HTTPS protocol
      7. subdomain_depth     - Number of dots in the hostname minus 1 (subdomain depth)
      8. query_param_count   - Number of key=value pairs in the query string
      9. digit_count         - Proportion of digits in the URL (randomized domains)
     10. path_depth          - Number of path segments (nested directory depth)

    SECURITY NOTE:
    All inputs are parsed via urllib.parse (stdlib), not user-supplied code paths.
    No eval() or exec() is used — purely string/regex analysis.
    """
    if not url or not isinstance(url, str):
        return [0.0] * 10

    # Parse the URL using Python's stdlib parser
    parsed = urlparse(url)

    # --- Feature 1: Total URL length ---
    url_length = float(len(url))

    # --- Feature 2: Presence of '@' symbol (used in credential phishing) ---
    has_at_symbol = 1.0 if "@" in url else 0.0

    # --- Feature 3: Double slash after protocol (redirect obfuscation) ---
    # Check if '//' appears in the path portion (beyond the protocol)
    scheme_end = url.find("://")
    has_double_slash = 0.0
    if scheme_end != -1:
        rest_of_url = url[scheme_end + 3:]
        if "//" in rest_of_url:
            has_double_slash = 1.0

    # --- Feature 4: Raw IP address as hostname ---
    hostname = parsed.hostname or ""
    ip_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )
    uses_ip_address = 1.0 if ip_pattern.match(hostname) else 0.0

    # --- Feature 5: Hyphen count in the domain ---
    hyphen_count = float(hostname.count("-"))

    # --- Feature 6: HTTPS protocol status ---
    has_https = 1.0 if parsed.scheme.lower() == "https" else 0.0

    # --- Feature 7: Subdomain depth (dots in hostname - 1) ---
    subdomain_depth = float(max(hostname.count(".") - 1, 0))

    # --- Feature 8: Query parameter count ---
    query_string = parsed.query or ""
    if query_string:
        query_param_count = float(len(query_string.split("&")))
    else:
        query_param_count = 0.0

    # --- Feature 9: Proportion of digits in the URL ---
    digit_count = sum(c.isdigit() for c in url) / max(len(url), 1)

    # --- Feature 10: Path depth (number of '/' segments) ---
    path = parsed.path or ""
    path_depth = float(max(path.strip("/").count("/"), 0))

    return [
        url_length,
        has_at_symbol,
        has_double_slash,
        uses_ip_address,
        hyphen_count,
        has_https,
        subdomain_depth,
        query_param_count,
        digit_count,
        path_depth,
    ]


FEATURE_NAMES = [
    "url_length",
    "has_at_symbol",
    "has_double_slash",
    "uses_ip_address",
    "hyphen_count",
    "has_https",
    "subdomain_depth",
    "query_param_count",
    "digit_count",
    "path_depth",
]
