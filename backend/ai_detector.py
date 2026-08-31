"""
PhishGuard AI Detection Orchestrator
====================================

Auto-detection system that fuses an ever-growing set of signals into a single
risk assessment. This module decides HOW DEEP to analyze a URL based on its
risk profile, runs the appropriate signal sources in parallel where possible,
and produces a consolidated analysis result for the caller.

Analysis depths (auto-selected):
  - "fast":    ML + lexical only. Used for clearly safe URLs (< 100ms).
  - "deep":    ML + lexical + sandbox content.
  - "forensic": ML + lexical + sandbox + VISUAL BRAND SIMILARITY (screenshot).

Auto-detection logic:
  - If the URL carries obvious lexical red flags OR a high-risk brand lookalike
    hostname, the system automatically escalates to a deeper forensic pass
    (including the visual screenshot check) even if the client only asked for a
    fast scan. This is the "AI" auto-escalation on top of fixed config.

All heavy/network work is optional and degraded gracefully. This module never
raises — it returns structured results so the endpoint can always respond.
"""

import threading
import time
from urllib.parse import urlparse

from backend.analyzer import lexical_risk
from backend.brand_checker import is_known_brand_domain
from backend.config import settings
from backend.sandbox import analyze_url as sandbox_analyze_url
from backend.visual_brand import check_visual_brand

# Soft thread-level throttle so the local server doesn't melt under parallel
# deep/forensic scans (each uses a headless browser + network fetch).
_deep_slot = threading.Semaphore(2)


def _version() -> str:
    return settings.VERSION or "1.0.0"


def _decide_depth(url: str, hostname: str, requested_analysis: bool,
                  ml_prediction: str, lexical_score: dict) -> str:
    """
    Auto-select the analysis depth using an ensemble of heuristics.
    Returns 'fast' | 'deep' | 'forensic'.
    """
    lex = lexical_score.get("score", 0)

    # The user explicitly asked for deep content analysis -> at least deep.
    if requested_analysis:
        return "forensic" if settings.VISUAL_ANALYSIS_ENABLED else "deep"

    # High lexical risk -> escalate to forensic (visual check included).
    if lex >= 25:
        return "forensic" if settings.VISUAL_ANALYSIS_ENABLED else "deep"

    # ML says phishing with decent confidence -> deeper inspection warranted.
    if ml_prediction == "phishing":
        return "forensic" if settings.VISUAL_ANALYSIS_ENABLED else "deep"

    # Brand-lookalike hostname (e.g. paypal-secure-login.xyz) -> visual check.
    from backend.brand_checker import _brand_lookalike
    try:
        if _brand_lookalike(url) is not None:
            return "forensic" if settings.VISUAL_ANALYSIS_ENABLED else "deep"
    except Exception:
        pass

    # Lexical trust-word / login-page pattern -> deeper pass.
    trust_words = ("login", "verify", "signin", "account", "payment", "wallet",
                   "secure", "sign-in", "update", "confirm")
    host_l = hostname.lower()
    if any(w in host_l for w in trust_words):
        return "deep"

    return "fast"


def analyze_forensic(
    url: str,
    hostname: str,
    ml_prediction: str,
    ml_confidence: float,
    requested_analysis: bool = False,
) -> dict:
    """
    Run the auto-depth AI detection for a URL and return the fused payload:

      {
        "depth": "fast"|"deep"|"forensic",
        "sandbox": dict|None,
        "visual_brand": dict,
        "lexical": {"score": int, "reasons": [...]},
        "auto_escalated": bool,     # True when AI upgraded depth beyond request
      }
    """
    lexical = lexical_risk(url, hostname)
    lexical_payload = {"score": lexical[0], "reasons": lexical[1]}

    depth = _decide_depth(url, hostname, requested_analysis, ml_prediction, lexical_payload)
    auto_escalated = depth != ("deep" if requested_analysis else "fast")

    # Determine whether to run sandbox (network) and visual (browser+network).
    run_sandbox = depth in ("deep", "forensic") and requested_analysis or depth == "forensic"
    run_visual = depth == "forensic"

    sandbox = None
    visual = {
        "checked": False,
        "screenshot_taken": False,
        "similarity": 0.0,
        "best_brand": None,
        "best_brand_url": None,
        "verdict": "neutral",
        "reason": "Visual check not run at this depth.",
        "component_scores": {},
    }

    # Only spawn the heavier work when it won't exceed the throttle budget.
    if run_visual or run_sandbox:
        acquired = _deep_slot.acquire(blocking=False)
        if acquired:
            try:
                if run_sandbox:
                    sandbox = sandbox_analyze_url(url)
                if run_visual:
                    visual = check_visual_brand(
                        url,
                        target_host=hostname,
                        enabled=settings.VISUAL_ANALYSIS_ENABLED,
                    )
            finally:
                _deep_slot.release()
        else:
            # Throttled out — fall back gracefully (no visual/sandbox this round).
            run_sandbox = False
            run_visual = False
            depth = "fast"
            auto_escalated = False

    return {
        "depth": depth,
        "sandbox": sandbox,
        "visual_brand": visual,
        "lexical": lexical_payload,
        "auto_escalated": auto_escalated,
    }


def auto_depth_ftr(url: str, hostname: str, ml_prediction: str) -> str:
    """Cheap helper returning only the decided depth (no heavy work)."""
    lexical = lexical_risk(url, hostname)
    return _decide_depth(url, hostname, False, ml_prediction,
                         {"score": lexical[0], "reasons": lexical[1]})


__all__ = ["analyze_forensic", "auto_depth_ftr", "_decide_depth"]
