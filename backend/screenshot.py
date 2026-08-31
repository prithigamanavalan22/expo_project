"""
PhishGuard Headless Screenshot Capture
======================================

Uses Playwright with a headless Chromium to capture a full-viewport page
screenshot WITHOUT executing on the user's machine — the page is rendered
in an isolated browser context on the server.

Design / Safety:
  - The captured image is processed in-memory (PIL) and either returned as
    bytes or converted to a feature vector. Nothing from the page is ever
    executed on a real user's browser.
  - Fetching is SSRF-guarded by the caller (screenshot.py only renders pages
    whose host has already passed the private-host check).
  - Non-essential: if Playwright is unavailable/not installed, this module
    gracefully returns None (callers treat it as 'visual analysis unavailable').

The module is lazy about the browser: we reuse a single persistent Chromium
instance across hot calls and only spin it up on first use.
"""

import io
import threading
from urllib.parse import urlparse

from backend.config import settings
from backend.sandbox import _is_private_host

# Playwright is an optional-but-expected dependency. Import lazily so the rest
# of the app still boots if the browser isn't installed yet.
_PLAYWRIGHT = None


def _pw():
    """Lazily import the playwright sync API (cached)."""
    global _PLAYWRIGHT
    if _PLAYWRIGHT is None:
        from playwright.sync_api import sync_playwright
        _PLAYWRIGHT = sync_playwright
    return _PLAYWRIGHT


# Module-level lock so concurrent scans don't race the single browser instance.
_browser_lock = threading.Lock()
_browser = None
_browser_creating = False


def _get_browser():
    """Return a shared Playwright browser, creating it on first use."""
    global _browser, _browser_creating
    if _browser is not None:
        return _browser
    with _browser_lock:
        if _browser is not None:
            return _browser
        if _browser_creating:
            return None  # another thread is creating it; skip this call
        _browser_creating = True
        try:
            # _pw() returns the sync_playwright() factory function; we must call
            # it to obtain the context object, then start() it.
            p = _pw()().start()
            _browser = p.chromium.launch(headless=True)
        except Exception:
            _browser = None
        finally:
            _browser_creating = False
    return _browser


def _close_browser():
    """Release the shared browser (for tests / cleanup)."""
    global _browser
    with _browser_lock:
        if _browser is not None:
            try:
                _browser.close()
            except Exception:
                pass
        _browser = None


def screenshot_url_to_png(url: str, timeout_ms=None) -> bytes | None:
    """
    Render a URL in headless Chromium and return the screenshot as PNG bytes.

    Returns None on any failure (page timeout, render error, missing browser)
    so callers can degrade gracefully to 'visual analysis unavailable'.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    # SSRF guard — never screenshot private/internal hosts.
    try:
        if _is_private_host(parsed.hostname):
            return None
    except Exception:
        pass

    if not settings.VISUAL_ANALYSIS_ENABLED:
        return None

    to = timeout_ms or settings.SCREENSHOT_TIMEOUT_MS

    # Playwright's Sync API must not run on an asyncio event-loop thread (it
    # raises "using Playwright Sync API inside the asyncio loop"). FastAPI's
    # async endpoints call this synchronously inside the loop, so we always
    # dispatch the actual rendering onto a dedicated worker thread.
    try:
        from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
    except Exception:
        return None
    _exec = ThreadPoolExecutor(max_workers=1)
    try:
        fut = _exec.submit(_render_shot, url, to)
        return fut.result(timeout=(to / 1000.0) + 10.0)
    except FutureTimeout:
        return None
    except Exception:
        return None
    finally:
        _exec.shutdown(wait=False)


def _render_shot(url: str, timeout_ms: int) -> bytes | None:
    """Execute the Playwright render on a dedicated thread (never the asyncio
    event-loop thread)."""
    browser = _get_browser()
    if browser is None:
        return None
    context = None
    try:
        context = browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36 PhishGuard/1.0"
            ),
            ignore_https_errors=False,
        )
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        # Give JS a small chance to lay out the page (logos, hero images).
        page.wait_for_timeout(1500)
        shot = page.screenshot(type="png", full_page=False)
        return shot
    except Exception:
        return None
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass


def screenshot_url_to_pil(url: str, timeout_ms=None):
    """
    Render a URL and return the screenshot as a PIL Image, or None on failure.
    """
    try:
        from PIL import Image
    except Exception:
        return None
    png = screenshot_url_to_png(url, timeout_ms)
    if not png:
        return None
    try:
        return Image.open(io.BytesIO(png)).convert("RGB")
    except Exception:
        return None


__all__ = [
    "screenshot_url_to_png",
    "screenshot_url_to_pil",
    "_close_browser",
    "_get_browser",
]
