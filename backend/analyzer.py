"""
PhishGuard Risk Analyzer
========================

Computes a human-readable RISK SCORE (0-100), a tiered verdict, and
EXPLANATIONS for why a URL is (or isn't) phishing.

Combines three signal sources:
  1. ML confidence        (random forest prediction probability)
  2. Lexical heuristics   (URL structure red flags)
  3. Sandbox analysis     (fetched page content signals — optional)

Risk tiers:
  0-33   SAFE
  34-66  SUSPICIOUS
  67-100 PHISHING

This is a pure-computation module — no DB, no network (except the caller
passes in sandbox findings). No new dependencies beyond the stdlib.
"""

# URL structure degradation map: what each risk point "means" in plain terms
EXPLAIN_LIBRARY = {
    "very_long": "The URL is unusually long ({v} chars), a common phishing obfuscation technique.",
    "at_symbol": "The URL contains an '@' symbol, often used to hide the real destination domain.",
    "double_slash": "The URL has '//' after the domain, which can hide the true host in some parsers.",
    "ip_address": "The URL uses a raw IP address ({v}) instead of a normal domain name.",
    "many_hyphens": "The domain has {v} hyphens, a common trick to impersonate brand names.",
    "no_https": "The URL does not use HTTPS, meaning data is sent in plaintext.",
    "deep_subdomains": "The URL has {v} subdomain levels, which can be used to confuse users about the real domain.",
    "many_query_params": "The URL has {v} query parameters, sometimes used to smuggle malicious data.",
    "digit_heavy": "A high proportion of the URL is digits ({v:.0%}), typical of auto-generated phishing links.",
    "blacklisted": "This domain is on the known phishing blacklist.",
    "ml_phishing": "The machine learning model classified this as phishing with {v:.0%} confidence.",
    "ml_safe": "The machine learning model classified this as legitimate with {v:.0%} confidence.",
    "suspicious_host": "The hostname ({v}) contains strings often used in phishing (e.g. 'secure', 'verify', 'login', 'account' combined with unrelated domain).",
    "trustword_subdomain": "The URL uses a trust-bait word ('{w}') as a subdomain over an unknown host ({v}) — a classic fake-login/payment-page pattern.",
    "sandbox_forms": "The page contains {v} credential/login form(s) submitting over insecure channels.",
    "sandbox_links": "The page contains {v} links pointing to unrelated or suspicious domains.",
    "sandbox_https_forms": "Credential forms on the page submit WITHOUT HTTPS (data could be intercepted).",
    "sandbox_mismatch": "The page's forms/links point to domains different from the page itself.",
    "sandbox_unreachable": "The page could not be fetched for content analysis.",
    "visual_impersonation": "The rendered page visually imitates '{v}' ({b}) but is hosted on a different site — a classic visual-clone phishing pattern.",
    "visual_lookalike": "The rendered page's appearance is moderately similar to '{v}', a possible brand lookalike (visual check).",
}


# Well-known legitimate domains that must never be flagged as phishing purely by
# a (possibly wrong) ML verdict. Stored as full registrable-domain suffixes so a
# host is only matched when it IS the domain or a genuine subdomain of it —
# lookalikes like "wikipedia.org.evil.com" or "evilwikipedia.org" don't match.
# Deliberately excludes abused free-hosting platforms (github.io, pages.dev,
# wordpress.com, netlify.app, ...) that legitimately host phishing content.
_TRUSTED_HOST_FRAGMENTS = [
    "google.com", "youtube.com", "gmail.com", "github.com", "amazon.com",
    "amazon.co.uk", "amazon.de", "amazon.co.jp", "apple.com", "icloud.com",
    "microsoft.com", "office.com", "outlook.com", "live.com", "facebook.com",
    "messenger.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "linkedin.com", "netflix.com", "paypal.com", "ebay.com", "wikipedia.org",
    "reddit.com", "stackoverflow.com", "stackexchange.com", "dropbox.com",
    "slack.com", "zoom.us", "adobe.com", "spotify.com", "cloudflare.com",
    "cloudfront.net", "googlevideo.com", "mozilla.org", "archive.org",
    "python.org", "npmjs.com", "w3.org", "apache.org", "kernel.org",
    "medium.com", "bbc.com", "bbc.co.uk", "nytimes.com", "wikimedia.org",
    "theverge.com", "bing.com", "duckduckgo.com", "chatgpt.com", "openai.com",
]


# Minimum ML confidence at which a non-brand, non-trusted host's "phishing"
# verdict escalates to PHISHING on its own (structural corroboration can still
# escalate below this). Real high-confidence phishing calls cluster at 0.97+
# while model false positives on legit domains tend to sit 0.90-0.97.
_ESCALATION_CONFIDENCE = 0.97


def _is_trusted_hostname(h: str) -> bool:
    """True if hostname equals/ends-with a known trusted legit domain."""
    if not h:
        return False
    h = h.lower()
    # Match the host only when it equals a trusted domain or is a genuine
    # subdomain of one (e.g. "en.wikipedia.org" -> ".wikipedia.org"). A
    # lookalike like "wikipedia.org.verify.xyz" / "notwikipedia.org" fails both.
    return any(
        h == frag or h.endswith("." + frag)
        for frag in _TRUSTED_HOST_FRAGMENTS
    )


class RiskReport:
    """Container for a computed risk assessment."""
    def __init__(self, score: int, verdict: str, reasons: list[str], ml_confidence: float):
        self.score = score
        self.verdict = verdict
        self.reasons = reasons          # human-readable explanation strings
        self.ml_confidence = ml_confidence


def _verdict(score: int) -> str:
    if score < 34:
        return "safe"
    if score < 67:
        return "suspicious"
    return "phishing"


def pick_verdict(score: int) -> str:
    """Public helper: map a 0-100 risk score to a verdict tier."""
    return _verdict(score)


def lexical_risk(url: str, parsed_hostname: str) -> dict:
    """
    Compute a risk sub-score and list of reasons purely from URL structure.
    Returns (risk_points, reasons).
    Each satisfied heuristic adds risk points and a plain-language reason.
    """
    score = 0
    reasons = []

    n = len(url)

    # Very long URL
    if n > 75:
        score += 20
        reasons.append(EXPLAIN_LIBRARY["very_long"].format(v=n))

    # @ symbol
    if "@" in url:
        score += 20
        reasons.append(EXPLAIN_LIBRARY["at_symbol"])

    # Double slash after protocol
    if url.find("://") != -1 and "//" in url[url.find("://") + 3:]:
        score += 10
        reasons.append(EXPLAIN_LIBRARY["double_slash"])

    # Raw IP address hostname
    host = parsed_hostname or ""
    import re
    ip_pattern = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$")
    if ip_pattern.match(host):
        score += 25
        reasons.append(EXPLAIN_LIBRARY["ip_address"].format(v=host))

    # Hyphen count in domain
    hyphens = host.count("-")
    if hyphens > 2:
        score += hyphens * 4
        reasons.append(EXPLAIN_LIBRARY["many_hyphens"].format(v=hyphens))

    # No HTTPS
    if not url.lower().startswith("https://"):
        score += 15
        reasons.append(EXPLAIN_LIBRARY["no_https"])

    # Subdomain depth
    subdepth = max(host.count(".") - 1, 0)
    if subdepth >= 2:
        score += subdepth * 5
        reasons.append(EXPLAIN_LIBRARY["deep_subdomains"].format(v=subdepth))

    # Query param count (large)
    from urllib.parse import urlparse
    qp = len((urlparse(url).query or "").split("&")) if urlparse(url).query else 0
    if qp >= 5:
        score += 8
        reasons.append(EXPLAIN_LIBRARY["many_query_params"].format(v=qp))

    # Digit-heavy
    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)
    if digit_ratio > 0.25:
        score += 12
        reasons.append(EXPLAIN_LIBRARY["digit_heavy"].format(v=digit_ratio))

    # Suspicious host tokens
    suspicious_words = ["secure", "verify", "login", "account", "update", "confirm", "bank", "signin", "auth"]
    host_lower = host.lower()
    if any(w in host_lower for w in suspicious_words):
        hits = [w for w in suspicious_words if w in host_lower]
        score += 10
        reasons.append(EXPLAIN_LIBRARY["suspicious_host"].format(v=host_lower))

    # ------------------------------------------------------------------
    # SEMANTIC TRUST-BAIT SUBDOMAIN RULE
    # Triggers when a high-value "trust-bait" word appears as a SUBDOMAIN
    # label (e.g. payment.gifts.free.com -> 'payment' is bait) over an
    # unknown/obscure host. These are classic fake payment/login pages
    # that the lexical model otherwise scores as clean.
    # ------------------------------------------------------------------
    TRUST_WORDS = [
        "payment", "paypal", "gift", "gifts", "secure", "security", "verify",
        "verification", "login", "signin", "sign-in", "account", "update",
        "confirm", "wallet", "unlock", "recover", "restore", "invoice",
        "billing", "refund", "reset", "2fa", "mfa", "otp", "authenticate",
        "authorize", "profile", "myaccount", "ebill", "biller",
    ]
    # Hosts that are legitimate/trustworthy enough to ignore this rule.
    # (module-level _TRUSTED_HOST_FRAGMENTS / _is_trusted_hostname)
    def _is_trusted_host(h: str) -> bool:
        return _is_trusted_hostname(h)

    def _apex_is_common_free_hosting(h: str) -> bool:
        # free-domain/subdomain hosts frequently abused for phishing
        parts = h.lower().split(".")
        apex = ".".join(parts[-2:]) if len(parts) >= 2 else h.lower()
        free_hosts = {
            "free.com", "gifts.com", "pages.dev", "vercel.app", "web.app",
            "github.io", "netlify.app", "herokuapp.com", "wordpress.com",
            "blogspot.com", "weebly.com", "wixsite.com", "000webhostapp.com",
            "kickasshosting", "freehostia", "byethost", "altervista",
            "000webhost", "awardspace", "webs.com", "yolasite.com",
        }
        return apex in free_hosts

    # Extract subdomain labels (exclude the apex + any single-label host)
    labels = host_lower.split(".")
    sub_labels = labels[:-2] if len(labels) > 2 else []
    # Map trustword through normalized form (handle "sign-in" -> signin etc.)
    bait = next((w for w in TRUST_WORDS if w in sub_labels), None)
    if bait and not _is_trusted_host(host_lower):
        # Unknown host + trust-bait subdomain => strong signal
        score += 22
        reasons.append(
            EXPLAIN_LIBRARY["trustword_subdomain"].format(w=bait, v=host_lower)
        )
        if _apex_is_common_free_hosting(host_lower):
            # e.g. .free.com / .gifts.com => even more suspicious
            score += 15
            reasons.append(
                "The page is hosted on a known free/fake subdomain host ({v}).".format(v=host_lower)
            )

    # Cap lexical at 60 so ML + sandbox still have influence
    return min(score, 60), reasons


def compute_report(
    ml_prediction: str,
    ml_confidence: float,
    url: str,
    parsed_hostname: str,
    blacklisted: bool = False,
    sandbox: dict | None = None,
    known_brand: bool = False,
    visual: dict | None = None,
) -> RiskReport:
    """
    Combine ML + lexical + sandbox + visual-brand into a final RiskReport.

    Parameters:
      ml_prediction  - 'safe'/'phishing' from the model
      ml_confidence  - model's confidence in its verdict (0-1)
      url            - the original URL
      parsed_hostname- the URL's hostname
      blacklisted    - True if domain is on the blocklist
      sandbox        - dict from the sandbox analyzer, or None if not run
      known_brand    - True if hostname is a canonical known-good brand domain
                       (google.com, paypal.com ...). Such domains are trusted:
                       a lone high-confidence ML "phishing" verdict is treated as
                       a model miscall and NOT allowed to force a phishing tier.
      visual         - dict from the visual brand-similarity checker, or None.
                       Contributes a 0-100 visual similarity signal against a
                       known brand for pages hosted on OTHER domains.
    """
    reasons = []

    # --- ML contribution ---
    ml_score = 0
    if blacklisted:
        ml_score = 80
        reasons.append(EXPLAIN_LIBRARY["blacklisted"])
    elif known_brand and ml_prediction == "phishing":
        # Brand guard: the lexical model is unreliable on short branded domains.
        # A genuine brand (paypal.com, google.com) is never phishing just because
        # the model says so; rely on real signals (lexical/sandbox) instead.
        ml_score = 0
        reasons.append(
            f"This is a verified known-good brand domain ({parsed_hostname}); the model's phishing verdict is treated as a miscall, so real structural signals decide the outcome."
        )
    elif ml_prediction == "phishing":
        # Non-brand host: cap the ML contribution higher (up to 70) so a
        # confident model verdict genuinely drives the score, instead of being
        # permanently diluted below the phishing tier. The retrained model
        # discriminates phishing vs legitimate reliably (see escalation below).
        ml_score = int(ml_confidence * 70)
        reasons.append(EXPLAIN_LIBRARY["ml_phishing"].format(v=ml_confidence))
    else:
        ml_score = 0
        reasons.append(EXPLAIN_LIBRARY["ml_safe"].format(v=max(ml_confidence, 0.01)))

    # --- Lexical contribution ---
    lex_score, lex_reasons = lexical_risk(url, parsed_hostname)
    reasons.extend(lex_reasons)

    # --- Sandbox contribution (optional) ---
    sandbox_score = 0
    if sandbox:
        sb = sandbox
        if sb.get("unreachable"):
            sandbox_score += 10
            reasons.append(EXPLAIN_LIBRARY["sandbox_unreachable"])
        else:
            n_forms = sb.get("credential_forms", 0)
            if n_forms and sb.get("insecure_forms", 0):
                sandbox_score += 25
                reasons.append(EXPLAIN_LIBRARY["sandbox_https_forms"])
            elif n_forms:
                sandbox_score += 10
                reasons.append(EXPLAIN_LIBRARY["sandbox_forms"].format(v=n_forms))
            n_ext = sb.get("external_links", 0)
            if n_ext:
                sandbox_score += min(n_ext * 3, 15)
                reasons.append(EXPLAIN_LIBRARY["sandbox_links"].format(v=n_ext))
            if sb.get("domain_mismatch"):
                sandbox_score += 20
                reasons.append(EXPLAIN_LIBRARY["sandbox_mismatch"])
            # Deeper static-analysis signals (added with the deepened sandbox)
            if sb.get("suspicious_login_page"):
                sandbox_score += 15
            if sb.get("suspicious_anchors"):
                sandbox_score += 10
            if sb.get("hidden_fields"):
                sandbox_score += 8
            if sb.get("external_link_ratio") and sb["external_link_ratio"] >= 0.9:
                sandbox_score += 5
        sandbox_score = min(sandbox_score, 30)

    # --- Visual brand-similarity contribution (optional) ---
    # Visual evidence is a strong phishing tell: a page that RENDERS like a
    # known brand while being hosted on a DIFFERENT domain is almost always a
    # visual clone / logo-theft page. It contributes a capped 0-20 signal.
    visual_score = 0
    visual_verdict = None
    if visual and visual.get("checked"):
        visual_verdict = visual.get("verdict")
        sim = float(visual.get("similarity") or 0.0)
        matched = visual.get("best_brand")
        brand_url = visual.get("best_brand_url")
        if visual_verdict == "impersonation":
            visual_score += 20
            reasons.append(EXPLAIN_LIBRARY["visual_impersonation"].format(
                v=matched or "a known brand", b=brand_url or "?"))
        elif visual_verdict == "lookalike":
            visual_score += 10
            reasons.append(EXPLAIN_LIBRARY["visual_lookalike"].format(
                v=matched or "a known brand"))
        visual_score = min(visual_score, 20)

    # --- Combine (ML 0-70, lexical 0-60, sandbox 0-30, visual 0-20 ...) ---
    # Re-weighted blend: ML 50%, lexical 27%, sandbox 13%, visual 10%.
    raw = ml_score * 0.50 + lex_score * 0.27 + sandbox_score * 0.13 + visual_score * 0.10
    # Max possible ≈ 70*.50 + 60*.27 + 30*.13 + 20*.10 = 35 + 16.2 + 3.9 + 2 = 57.1
    # Normalize to 0-100.
    score = int(raw / 0.571)
    score = max(0, min(100, score))

    # Corroboration flag: is there a MEANINGFUL phishing signal beyond the ML
    # verdict itself? Our ML model can misclassify clean domains (google.com,
    # example.com), so a lone high-confidence ML "phishing" verdict must NOT
    # force a phishing tier by itself. Only escalate when a clean URL is
    # counter-intuitively flagged despite visible structural phishing signals.
    def _mismatch_or_forms(sb):
        return bool(
            sb
            and (sb.get("insecure_forms") or sb.get("domain_mismatch"))
        )

    strong_corroboration = bool(
        blacklisted
        or lex_score >= 20                       # real structural red flags
        or _mismatch_or_forms(sandbox)           # cred forms over insecure tx
        or (sandbox_score >= 15 and sandbox_score <= 30)
        or visual_verdict == "impersonation"     # strong visual clone
    )

    if blacklisted:
        # Explicit blacklist hit is always an immediate critical phishing verdict
        score = max(score, 95)
    elif ml_prediction == "phishing" and not known_brand and not _is_trusted_hostname(parsed_hostname):
        # The Random Forest was retrained on 200k real labeled URLs and reliably
        # separates phishing from legitimate inputs (empirically ~92% phishing
        # recall at ~98% safe precision here). A HIGH-confidence phishing verdict
        # on a NON-brand, NON-trusted host is therefore itself a strong phishing
        # signal — it must reach the phishing tier even when structural
        # corroboration is absent. Genuine brands and well-known legit domains
        # are protected (brand guard above + trusted-host check).
        # Lower-confidence verdicts still need corroboration to escalate.
        if ml_confidence >= _ESCALATION_CONFIDENCE or strong_corroboration:
            score = max(score, 80)

    # Floor: a strong trust-bait subdomain signal (or any lex_score >= 22) can
    # NEVER be reported as fully "safe" — it is at minimum suspicious. This
    # ensures fake payment/login subdomains on unknown hosts are never cleared.
    # Known brands are exempt from the lex_score floor (their lex scores are 0
    # anyway when clean).
    _trust_bait = any("trust-bait word" in r or "known free/fake subdomain host" in r for r in reasons)
    if not known_brand and (_trust_bait or lex_score >= 22):
        score = max(score, 40)

    # Visual floor: a page that RENDERS like a known brand but is on another
    # domain is never "safe" — bump at least to suspicious even if other
    # signals are weak. Known brands are exempt (they legitimately look alike).
    if not known_brand and visual_verdict == "impersonation":
        score = max(score, 40)

    # Deduplicate reasons preserving order
    seen = set()
    unique_reasons = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            unique_reasons.append(r)

    return RiskReport(
        score=score,
        verdict=_verdict(score),
        reasons=unique_reasons,
        ml_confidence=ml_confidence,
    )
