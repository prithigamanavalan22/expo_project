"""
PhishGuard Visual Brand Similarity Engine
=========================================

Detects phishing pages that visually impersonate a known brand by comparing
a live screenshot of the target URL against pre-built brand fingerprints.

Two layers of evidence are combined:

  1. STATIC color-palette signatures (shipped in brand_fingerprints.json).
     These capture the dominant brand colors that appear on the real site.
  2. LIVE perceptual/layout fingerprints, captured at runtime from the
     canonical brand homepage via a headless screenshot and cached on disk
     (brand_cache/) so we don't re-fetch on every scan.

The engine produces a 0-100 "visual similarity" score for the strongest
matching brand and a verdict:
   - "clean":          no meaningful visual match
   - "neutral":        no data (couldn't capture/fingerprint)
   - "lookalike":      moderate similarity to a brand it is NOT
   - "impersonation":  strong similarity to a brand it is NOT

Security / design:
  - Only compares the TARGET screenshot against the canonical brand homepage;
    the target host is SSRF-guarded via screenshot.py / sandbox._is_private_host.
  - Never executes code from the page; screenshots are rendered in a headless
    browser and processed as pixels only.
  - All failures degrade to a neutral result (never raises into the caller).
"""

import json
import os
import threading
from pathlib import Path
from urllib.parse import urlparse

from backend.config import settings
from backend.screenshot import screenshot_url_to_pil

# ---------------------------------------------------------------------------
# Load the static brand fingerprint DB
# ---------------------------------------------------------------------------
_FP_PATH = Path(__file__).resolve().parent / "brand_fingerprints.json"
_BRAND_DB = {}
try:
    with open(_FP_PATH, "r", encoding="utf-8") as _f:
        _BRAND_DB = json.load(_f).get("brands", {})
except Exception:
    _BRAND_DB = {}

_cache_lock = threading.Lock()
# Simple in-memory cache: key -> ("brand", similarity_score)
_mem_cache = {}


def _hex_to_rgb(hexstr: str):
    hexstr = hexstr.lstrip("#")
    try:
        return (int(hexstr[0:2], 16), int(hexstr[2:4], 16), int(hexstr[4:6], 16))
    except Exception:
        return (255, 255, 255)


def _palette_for(brand_entry: dict) -> list[list]:
    """Return [[r,g,b], fraction, ...] palette from a brand entry."""
    out = []
    for color, frac in brand_entry.get("palette", []):
        out.append([_hex_to_rgb(color), float(frac)])
    return out


def _hover_to_rgb_percent(pil_image, sample=40):
    """Compute a downsampled HSV color-hue histogram of an image as a dict."""
    from collections import Counter
    small = pil_image.resize((64, 64))
    pixels = list(small.getdata())
    counter = Counter()
    for r, g, b in pixels:
        # coarsely quantize to reduce noise
        key = (r // 32, g // 32, b // 32)
        counter[key] += 1
    total = sum(counter.values()) or 1
    hist = {k: v / total for k, v in counter.items()}
    return hist


def _color_hist_similarity(img, palette):
    """
    Compare an image's dominant colors against a brand palette.
    Returns a 0-100 score: how much of the page's visible color matches the
    brand's DISTINCTIVE (non-white) palette colors.

    White/near-black backgrounds are near-universal on the web, so they carry no
    brand identity. We therefore ignore white/black palette entries for matching
    and require the page to actually exhibit a distinctive brand color, or this
    returns ~0 (avoids flagging plain white text pages as brand impersonations).
    """
    if not palette:
        return 0.0
    small = img.resize((64, 64))
    pixels = list(small.getdata())
    if not pixels:
        return 0.0

    def _neutral(p):
        r, g, b = p
        # near-white or near-black
        return (r > 235 and g > 235 and b > 235) or (r < 25 and g < 25 and b < 25)

    # Count how much of the page is a "neutral" (white/dark) background.
    neutral_ratio = sum(1 for p in pixels if _neutral(p)) / len(pixels)
    # If the page is almost entirely background with no color identity, it
    # cannot be a visual clone — return 0.
    if neutral_ratio > 0.9:
        return 0.0

    # Distinctive palette colors = non-white, non-black brand colors only.
    distinctive = [
        tuple(row[0]) for row in palette
        if not _neutral(tuple(row[0])) and tuple(row[0]) != (0, 0, 0)
    ]
    if not distinctive:
        return 0.0

    hit = 0.0
    for r, g, b in pixels:
        if _neutral((r, g, b)):
            continue  # background pixels don't count toward a brand match
        best = min(
            ((r - pr) ** 2 + (g - pg) ** 2 + (b - pb) ** 2) ** 0.5
            for pr, pg, pb in distinctive
        )
        if best <= 55:
            hit += 1.0
    # Score based on the fraction of NON-NEUTRAL pixels that match a brand color.
    non_neutral = sum(1 for p in pixels if not _neutral(p))
    if non_neutral == 0:
        return 0.0
    ratio = hit / non_neutral
    return min(ratio * 100.0, 100.0)


def _edge_density_similarity(img):
    """Layout signature: 8x8 edge-density grid serialized for comparison."""
    try:
        import cv2
        import numpy as np
    except Exception:
        return None
    import io
    try:
        arr = np.array(img.convert("L"))
        edges = cv2.Canny(arr, 50, 150)
        small = cv2.resize(edges, (8, 8))
        # density 0..1 per cell
        grid = (small / 255.0).round(3).tolist()
        return grid
    except Exception:
        return None


def _hashes_for(img):
    """Perceptual hash (aHash) + color hash of an image, as hex strings."""
    try:
        import imagehash
        return {
            "ahash": str(imagehash.average_hash(img, hash_size=16)),
            "dhash": str(imagehash.dhash(img, hash_size=16)),
        }
    except Exception:
        return {}


def _hamming(a: str, b: str) -> float:
    """Normalized Hamming distance between two hex-hash strings (0..1)."""
    if not a or not b:
        return 0.5
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    diff = sum(1 for x, y in zip(a, b) if x != y)
    return diff / max_len


def _hash_similarity(h1: dict, h2: dict) -> float:
    """Combine aHash + dHash distances into a 0-100 similarity score."""
    if not h1 or not h2:
        return 50.0  # neutral when data missing
    a = _hamming(h1.get("ahash", ""), h2.get("ahash", ""))
    d = _hamming(h1.get("dhash", ""), h2.get("dhash", ""))
    # smaller distance = more similar
    return min(max((1.0 - (0.5 * a + 0.5 * d)) * 100.0, 0.0), 100.0)


# ---------------------------------------------------------------------------
# Live per-brand fingerprint cache (on-disk + memory)
# ---------------------------------------------------------------------------
def _live_cache_path(brand: str) -> Path:
    return Path(settings.BRAND_CACHE_DIR) / f"{brand}.json"


def _load_live_fingerprint(brand: str) -> dict | None:
    try:
        p = _live_cache_path(brand)
        if not p.exists():
            return None
        mtime = p.stat().st_mtime
        import time
        if time.time() - mtime > settings.BRAND_CACHE_TTL:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _store_live_fingerprint(brand: str, data: dict):
    try:
        Path(settings.BRAND_CACHE_DIR).mkdir(parents=True, exist_ok=True)
        fp = _live_cache_path(brand)
        tmp = fp.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(fp)
    except Exception:
        pass


def _capture_brand_fingerprint(brand: str, entry: dict) -> dict | None:
    """Screenshot the canonical brand homepage once and fingerprint it."""
    url = entry.get("homepage_url") or entry.get("canonical_url")
    if not url:
        return None
    img = screenshot_url_to_pil(url, timeout_ms=settings.SCREENSHOT_TIMEOUT_MS)
    if img is None:
        return None
    try:
        fp = {
            "brand": brand,
            "hashes": _hashes_for(img),
            "hist": _hover_to_rgb_percent(img),
            "edge": _edge_density_similarity(img),
            "palette": entry.get("palette"),
            "color_score": round(
                _color_hist_similarity(img, _palette_for(entry)), 1
            ),
        }
        _store_live_fingerprint(brand, fp)
        return fp
    except Exception:
        return None


def _get_live_fingerprint(brand: str, entry: dict) -> tuple:
    """
    Return (fingerprint, generated_now). If a fingerprint is missing/stale and
    this brand's homepage is unreachable, we cache a short 'failed' marker so
    we don't hammer unreachable brand homepages on every scan.
    """
    cached = _load_live_fingerprint(brand)
    if cached is not None:
        is_failed = cached.get("failed", False)
        return (None if is_failed else cached, False)
    fp = _capture_brand_fingerprint(brand, entry)
    if fp is None:
        # Cache the negative result briefly to avoid re-fetch spam.
        try:
            Path(settings.BRAND_CACHE_DIR).mkdir(parents=True, exist_ok=True)
            _store_live_fingerprint(brand, {"failed": True, "brand": brand})
        except Exception:
            pass
        return (None, False)
    return (fp, True)


# How many brand homepages we'll screenshot in a single check call (bounded so
# first-run doesn't hang or exhaust the throttle while the cache backfills).
_GENERATION_BUDGET_PER_CALL = 3


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def _strip_scheme_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "") or ""
    except Exception:
        return ""


def check_visual_brand(url: str, target_host: str | None = None, enabled: bool = True) -> dict:
    """
    Screenshot the given URL and compare it against known brand fingerprints.
    Returns a neutral dict on any failure or when disabled.

    Returns:
      {
        "checked": bool,
        "screenshot_taken": bool,
        "similarity": float,          # 0-100 for the best matching brand
        "best_brand": str | None,     # brand name
        "best_brand_url": str | None,
        "verdict": "clean"|"lookalike"|"impersonation"|"neutral",
        "reason": str,
        "component_scores": {...},    # color / layout / hash sub-scores
      }
    """
    neutral = {
        "checked": False,
        "screenshot_taken": False,
        "similarity": 0.0,
        "best_brand": None,
        "best_brand_url": None,
        "verdict": "neutral",
        "reason": "Visual brand similarity check unavailable.",
        "component_scores": {},
    }
    if not enabled or not settings.VISUAL_ANALYSIS_ENABLED or not _BRAND_DB:
        return neutral

    host = target_host or _strip_scheme_host(url)
    if not host:
        return dict(neutral, reason="No hostname to evaluate visually.")

    img = screenshot_url_to_pil(url, timeout_ms=settings.SCREENSHOT_TIMEOUT_MS)
    if img is None:
        return dict(neutral, reason="Could not render the target page for a screenshot.")

    target_hashes = _hashes_for(img)
    target_edge = _edge_density_similarity(img)

    best = {
        "similarity": 0.0,
        "structural": None,
        "brand": None,
        "brand_url": None,
        "components": {},
    }

    gen_budget = _GENERATION_BUDGET_PER_CALL
    for brand, entry in _BRAND_DB.items():
        # Static palette evidence (always available)
        color_score = _color_hist_similarity(img, _palette_for(entry))
        # Live fingerprint evidence (best-effort, budgeted)
        live = None
        if gen_budget > 0:
            live, _gen = _get_live_fingerprint(brand, entry)
            if _gen:
                gen_budget -= 1
        else:
            # Budget exhausted — use cached fingerprint only, or none.
            cached = _load_live_fingerprint(brand)
            live = None if (cached is None or cached.get("failed")) else cached

        # STRUCTURAL similarity = layout (edge) + perceptual hash from the live
        # brand fingerprint. This is the decisive evidence for a visual CLONE:
        # an impersonator reproduces the page's structure, not just its colors.
        edge_score = None
        hash_score = None
        if live and live.get("edge") and target_edge:
            edge_score = _edge_similarity_score(target_edge, live["edge"])
        if live and live.get("hashes"):
            hash_score = _hash_similarity(dict(target_hashes), live["hashes"])

        structural = None
        if edge_score is not None and hash_score is not None:
            structural = 0.55 * edge_score + 0.45 * hash_score
        elif edge_score is not None:
            structural = edge_score
        elif hash_score is not None:
            structural = hash_score

        # Overall similarity = structural 60% + color 40%. If no structural data
        # exists, similarity is undefined -> we never flag on color alone.
        if structural is None:
            sim = 0.0
        else:
            sim = round(0.60 * structural + 0.40 * color_score, 1)

        if sim > best["similarity"]:
            best = {
                "similarity": sim,
                "structural": structural,
                "brand": brand,
                "brand_url": entry.get("canonical_url"),
                "components": {
                    "color": round(color_score, 1) if color_score else 0.0,
                    "perceptual_hash": round(hash_score, 1) if hash_score is not None else None,
                    "layout_edge": round(edge_score, 1) if edge_score is not None else None,
                    "structural": round(structural, 1) if structural is not None else None,
                },
            }

    sim = best["similarity"]
    structural = best["structural"]
    hi = settings.VISUAL_HIGH_THRESHOLD
    mod = settings.VISUAL_MODERATE_THRESHOLD

    # Flagging requires structural (layout) evidence — a real clone, not just a
    # coincidental colour palette. When no brand structural fingerprint is
    # available, we report "clean" (no visual evidence) rather than guessing.
    if structural is not None and structural >= hi and sim >= hi:
        verdict = "impersonation"
        reason = (
            f"Visual layout strongly resembles '{best['brand']}' "
            f"({best['brand_url']}) but is a different site ({host})."
        )
    elif structural is not None and structural >= mod and sim >= mod:
        verdict = "lookalike"
        reason = (
            f"Visual appearance is similar to '{best['brand']}' — possible lookalike."
        )
    else:
        verdict = "clean"
        reason = "No strong visual brand similarity detected."

    return {
        "checked": True,
        "screenshot_taken": True,
        "similarity": sim,
        "best_brand": best["brand"],
        "best_brand_url": best["brand_url"],
        "verdict": verdict,
        "reason": reason,
        "component_scores": best["components"],
    }


def _edge_similarity_score(g1: list, g2: list) -> float:
    """Subtract two 8x8 edge-density grids into a 0-100 similarity score."""
    try:
        if not g1 or not g2:
            return 50.0
        n = min(len(g1), len(g2))
        mse = sum((a - b) ** 2 for a, b in zip(g1[:n], g2[:n])) / max(n, 1)
        return min(max((1.0 - mse) * 100.0, 0.0), 100.0)
    except Exception:
        return 50.0


__all__ = ["check_visual_brand", "_get_live_fingerprint", "_BRAND_DB"]
