"""
PhishGuard Logging Setup
========================

Configures a single rotating file logger so every scan request (and backend
event) is written to a persistent log even when the server runs as a hidden
background process (where stdout/stderr would otherwise be discarded).

Log file: <backend dir>/phishguard-server.log (max 5 MB, keeps 3 backups)
"""

import logging
import logging.handlers
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent
LOG_FILE = LOG_DIR / "phishguard-server.log"

_logger = None


def get_logger() -> logging.Logger:
    """Return the process-wide PhishGuard server logger (idempotent)."""
    global _logger
    if _logger is not None:
        return _logger

    logger = logging.getLogger("phishguard")
    if logger.handlers:
        _logger = logger
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s.%(msecs)03d | %(levelname)-7s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(handler)
    _logger = logger
    return logger


def log_scan(url: str, prediction: str, risk_score, confidence, ip: str = "") -> None:
    """Write a concise per-scan line. Never raises — logging must not break scans."""
    try:
        get_logger().info(
            "SCAN  url=%s | verdict=%s | risk=%s | conf=%.2f | ip=%s",
            url, prediction, risk_score, float(confidence or 0), ip or "-",
        )
    except Exception:
        pass
