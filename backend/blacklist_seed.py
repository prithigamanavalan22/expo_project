"""
Seed the BlacklistedDomain table from the known-phishing URL dataset.

The training dataset (`ml_model/data/phishing_url_dataset.csv`) is derived from
PhishTank. Its label convention is: Label 0 = phishing, Label 1 = legitimate
(verified empirically: avg URL length of Label 0 is ~3x that of Label 1).
Rows that a phishing domain no longer resolves via DNS would otherwise never
reach the blacklist check (the DNS validation gate allows well-formed URLs
through, and dead domains simply fall to the ML engine). Seeding the dataset's
phishing hosts at startup means even dead/taken-down phishing domains from
PhishTank are recognized instantly.

SECURITY:
- Hostnames are parsed with urllib.parse, never executed or contacted.
- All DB access uses parameterized ORM queries (no raw SQL).
- Seeding is idempotent: existing `domain` rows (UNIQUE constraint) are skipped.
"""

import ipaddress
import os
from pathlib import Path

from sqlalchemy.orm import Session

from backend.models import BlacklistedDomain

DEFAULT_DATASET_REL = Path("ml_model") / "data" / "phishing_url_dataset.csv"
PHISHING_LABEL = "0"  # this dataset: 0 = phishing, 1 = legitimate
_INSERT_BATCH = 5000


def dataset_path() -> Path:
    """Resolve the phishtank CSV path (env override wins, else repo-relative)."""
    env = os.getenv("PHISHTANK_CSV_PATH")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / DEFAULT_DATASET_REL


def hostname_of(raw_url: str) -> str | None:
    """Extract a normalized hostname from a URL/domain, or None if unusable."""
    from urllib.parse import urlparse

    text = (raw_url or "").strip()
    if not text:
        return None
    if "://" not in text:
        text = "http://" + text
    try:
        host = urlparse(text).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    if not host or any(ch.isspace() for ch in host):
        return None
    # A pure IP address is not a meaningful "domain" blacklist entry.
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    return host


def run_blacklist_seed(db: Session, path: Path | None = None) -> int:
    """
    Insert all known-phishing hosts from the dataset into BlacklistedDomain.
    Returns the number of new rows inserted. Idempotent and cheap to re-run.
    """
    csv_path = path or dataset_path()
    if not csv_path.is_file():
        print(f"[!] Blacklist seed skipped: dataset not found at {csv_path}")
        return 0

    hosts: set[str] = set()
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        import csv as _csv

        reader = _csv.reader(fh)
        try:
            next(reader)  # header row
        except StopIteration:
            return 0
        for row in reader:
            if len(row) < 2 or row[1].strip() != PHISHING_LABEL:
                continue
            host = hostname_of(row[0])
            if host:
                hosts.add(host)

    # Skip hosts already present (idempotent; UNIQUE constraint on `domain`).
    existing = {
        d  # type: ignore[misc]
        for (d,) in db.query(BlacklistedDomain.domain).all()
    }
    missing = [h for h in hosts if h not in existing]

    inserted = 0
    for i in range(0, len(missing), _INSERT_BATCH):
        chunk = missing[i : i + _INSERT_BATCH]
        for host in chunk:
            db.add(
                BlacklistedDomain(
                    domain=host,
                    reason="Known phishing host from PhishTank-derived URL dataset (phishing_url_dataset.csv)",
                )
            )
        db.commit()
        inserted += len(chunk)

    return inserted