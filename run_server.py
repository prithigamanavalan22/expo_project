"""PhishGuard backend launcher — routes uvicorn + app logs to a file.

Runs the FastAPI app on 127.0.0.1:8000 with all logging (uvicorn access,
uvicorn error, and the app's own scan logs) written to
backend/phishguard-server.log so activity is visible even when the server
runs as a hidden/minimized background process.
"""
import logging
import logging.handlers
from pathlib import Path

import uvicorn

LOG_FILE = Path(__file__).resolve().parent / "backend" / "phishguard-server.log"


def _file_handler():
    return logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )


if __name__ == "__main__":
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
