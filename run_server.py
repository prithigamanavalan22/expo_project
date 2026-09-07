"""PhishGuard backend launcher — routes uvicorn + app logs to a file.

Runs the FastAPI app on 127.0.0.1:8000 with all logging (uvicorn access,
uvicorn error, and the app's own scan logs) written to
backend/phishguard-server.log so activity is visible even when the server
runs as a hidden/minimized background process.

Includes a single-instance guard: only one backend instance is allowed. If a
PhishGuard backend is already serving on port 8000, or another process already
owns the pid file and is alive, this launcher exits immediately instead of
starting a duplicate.
"""
import datetime
import logging
import logging.handlers
import os
import sys
import urllib.request
from pathlib import Path

import uvicorn

BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "backend" / "phishguard-server.log"
PID_FILE = BASE_DIR / "backend" / "phishguard.pid"
HEALTH_URL = "http://127.0.0.1:8000/health"


def _log(msg: str) -> None:
    line = f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} | {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def _backend_already_serving() -> bool:
    """True if a PhishGuard backend already responds on the health endpoint."""
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=2) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _acquire_single_instance() -> bool:
    """Claim the pid file. Returns True if WE should run, False to exit."""
    try:
        fd = os.open(str(PID_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:
            old_pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except Exception:
            old_pid = None
        if old_pid and _pid_alive(old_pid):
            return False
        # Stale pid file left by a crashed instance — overwrite it.
        PID_FILE.unlink(missing_ok=True)
        try:
            fd = os.open(str(PID_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
    os.write(fd, str(os.getpid()).encode("utf-8"))
    os.close(fd)
    return True


def _release_single_instance() -> None:
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        pid = None
    if pid == os.getpid():
        PID_FILE.unlink(missing_ok=True)


def _file_handler():
    return logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )


if __name__ == "__main__":
    if _backend_already_serving():
        _log("SINGLE-INSTANCE  backend already serving on port 8000 — exiting.")
        sys.exit(0)
    if not _acquire_single_instance():
        _log("SINGLE-INSTANCE  another backend instance owns the pid file — exiting.")
        sys.exit(0)
    _log(f"AUTOSTART  launching PhishGuard backend (pid={os.getpid()})")
    try:
        uvicorn.run(
            "backend.main:app",
            host="127.0.0.1",
            port=8000,
            log_level="info",
            log_config={
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {
                    "default": {
                        "format": "%(asctime)s.%(msecs)03d | %(levelname)-7s | %(message)s",
                        "datefmt": "%Y-%m-%d %H:%M:%S",
                    },
                },
                "handlers": {
                    "file": {
                        "class": "logging.handlers.RotatingFileHandler",
                        "filename": str(LOG_FILE),
                        "maxBytes": 5 * 1024 * 1024,
                        "backupCount": 3,
                        "encoding": "utf-8",
                        "formatter": "default",
                    },
                },
                "root": {"handlers": ["file"], "level": "INFO"},
                "loggers": {
                    "uvicorn": {"handlers": ["file"], "level": "INFO", "propagate": False},
                    "uvicorn.error": {"level": "INFO"},
                    "uvicorn.access": {
                        "handlers": ["file"],
                        "level": "INFO",
                        "propagate": False,
                    },
                },
            },
        )
    finally:
        _release_single_instance()
        _log("SHUTDOWN  PhishGuard backend stopped.")