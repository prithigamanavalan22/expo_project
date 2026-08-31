"""
Train a Random Forest Classifier for URL Phishing Detection.

This script can train on:
  (A) A REAL labeled CSV dataset you provide (recommended for production).
  (B) A built-in synthetic generator (demo-only, for exercising the pipeline).

CSV dataset formats supported (auto-detected by column name):
  - Column named 'url' OR first column = the URL string
  - Label column named one of:
        'label', 'type', 'is_phishing', 'status', 'phishing', 'class'
  Labels are normalized: phishing-like -> 1, benign/legit -> 0.

Pipeline: StandardScaler + RandomForestClassifier, exported via joblib to .pkl

Usage:
    # Train on a real dataset (recommended)
    python ml_model/train_model.py --csv path/to/dataset.csv

    # Train on the demo synthetic dataset
    python ml_model/train_model.py
"""

import argparse
import os
import random
import warnings
from collections import Counter

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from feature_extractor import extract_features

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# 1. REAL CSV DATASET LOADING
# ---------------------------------------------------------------------------


def _detect_columns(df: pd.DataFrame) -> tuple[str, str]:
    """Find which columns are the URL and the label (case-insensitive)."""
    # Build a case-insensitive map from lowercase -> actual column name
    lower_to_actual = {str(c).lower(): c for c in df.columns}

    # URL column
    url_col = None
    for cand in ("url", "webpage_url", "domain", "host", "address"):
        if cand in lower_to_actual:
            url_col = lower_to_actual[cand]
            break
    if url_col is None:
        url_col = df.columns[0]  # fallback: first column

    # Label column
    label_col = None
    for cand in ("label", "type", "is_phishing", "status", "phishing", "class", "result"):
        if cand in lower_to_actual:
            label_col = lower_to_actual[cand]
            break
    if label_col is None:
        label_col = df.columns[-1]  # fallback: last column

    print(f"[*] Detected URL column: '{url_col}', label column: '{label_col}'")
    return url_col, label_col


def load_csv_dataset(csv_path: str) -> tuple[list[str], list[int]]:
    """
    Load a labeled URL CSV and return (urls, labels) normalized to 0/1.

    Handles the two common numeric-label conventions automatically by
    inspecting which numeric value is MORE frequent (the majority class).
      Convention A: 0 = phishing, 1 = legitimate   (PhiUSIIL-derived)
      Convention B: 1 = phishing, 0 = legitimate   (others)
    Text labels ('phishing'/'benign'/'malicious'/'good') are also supported.
    """
    df = pd.read_csv(csv_path, dtype=str, on_bad_lines="skip")
    print(f"[*] Loaded {len(df)} rows from {csv_path}")

    url_col, label_col = _detect_columns(df)

    # --- Determine the label convention from the data ---
    # Many public datasets disagree on what 0/1 means. We auto-detect using
    # a robust content-based heuristic: phishing URLs are typically longer,
    # contain more digits / @ symbols / suspicious tokens than legitimate ones.
    # We measure the "suspiciousness" of each label group and assign the more
    # suspicious group to phishing (1). This works even on balanced datasets
    # where a simple majority check would tie.
    value_counts = df[label_col].astype(str).str.strip().str.lower().value_counts()

    def _suspiciousness(urls_series) -> float:
        """Higher = more likely phishing. Uses distinctive phishing markers."""
        if urls_series.empty:
            return 0.0
        total = 0.0
        n = max(len(urls_series), 1)
        for u in urls_series:
            u = str(u).lower()
            total += (len(u) > 60)                 # very long URL
            total += ("@" in u)                    # credential spoofing
            total += (".org.ru" in u or "duckdns" in u
                      or "pages.dev" in u or "github.io" in u
                      or "login" in u and "facebook" in u)  # common phishing hosts/paths
            total += (sum(c.isdigit() for c in u) > 6)      # digit-heavy
            total += (u.count("-") > 3)                     # hyphen-heavy brand impersonation
        return total / n

    distinct = set(value_counts.index)
    has_text = bool(distinct & {"phishing", "benign", "legitimate", "malicious", "good", "safe"})
    has_zero = "0" in distinct
    has_one = "1" in distinct

    if has_text:
        # Text labels: confident mapping
        def norm_label(s: str) -> int | None:
            return 1 if s in {"1", "phishing", "malicious", "bad", "attack", "phish", "yes", "true", "-1"} else 0

    elif has_zero and has_one:
        # Both 0 and 1 present. Measure which group is more suspicious.
        group0 = df.loc[df[label_col].astype(str).str.strip().str.lower() == "0", url_col]
        group1 = df.loc[df[label_col].astype(str).str.strip().str.lower() == "1", url_col]
        susp0 = _suspiciousness(group0)
        susp1 = _suspiciousness(group1)
        print(f"[*] Suspiciousness score: label-0={susp0:.3f}, label-1={susp1:.3f}")

        if susp0 >= susp1:
            # label 0 is the phishing group
            print("[*] Convention detected: 0=phishing, 1=legitimate")
            def norm_label(s: str) -> int | None:
                return 0 if s == "1" else 1  # 1=legit -> safe(0), 0=phishing -> phishing(1)
        else:
            # label 1 is the phishing group
            print("[*] Convention detected: 1=phishing, 0=legitimate")
            def norm_label(s: str) -> int | None:
                return 1 if s == "1" else 0  # 1=phishing -> phishing(1), 0=legit -> safe(0)

    else:
        # Single-valued or unusual; default to 1=phishing, 0=legit
        def norm_label(s: str) -> int | None:
            if s in {"1", "phishing", "malicious", "bad", "attack", "phish", "yes", "true"}:
                return 1
            if s in {"0", "benign", "legitimate", "good", "safe", "no", "false"}:
                return 0
            return None

    # --- Load rows ---
    urls, labels = [], []
    for _, row in df.iterrows():
        raw_url = row[url_col]
        raw_label = row[label_col]
        if not isinstance(raw_url, str) or not raw_url.strip():
            continue

        url = raw_url.strip()
        label_str = str(raw_label).strip().lower()

        norm = norm_label(label_str)
        if norm is None:
            continue  # unknown label -> skip (can't trust it)

        urls.append(url)
        labels.append(norm)

    if not urls:
        raise ValueError("No valid rows found in CSV. Check column names / format.")

    counts = Counter(labels)
    print(f"[*] Class balance: safe={counts[0]}, phishing={counts[1]}")
    return urls, labels


# ---------------------------------------------------------------------------
# 2. SYNTHETIC GENERATOR (DEMO FALLBACK)
# ---------------------------------------------------------------------------

PHISHING_TEMPLATES = [
    "http://{domain}/login.php?user=bank&session={token}",
    "http://{ip}/secure/update?id={token}",
    "http://www.{domain}-verify.com/account/signin?ref={token}",
    "https://{domain}.malicious-site.net/payload?cmd={token}",
    "http://{domain}@evil.com/login?redirect={token}",
    "http://{domain}/wp-admin/{token}/install.php",
    "http://192.168.{oct1}.{oct2}/admin/{token}",
    "http://{domain}-secure.account-verify.com/{token}/login",
    "http://{domain}/cgi-bin/{token}?password=1234",
    "https://login.{domain}.phish.org/auth?user=admin&pw={token}",
    "http://{domain}.com//double//slash/{token}/login",
    "http://{domain}.net:8080/{token}/verify?email=test@test.com&pass=abc",
    "http://{domain}-bank.secure-login.com/{token}/update?redirect=evil.com",
    "http://10.0.0.{oct1}/admin/{token}/config",
    "https://{domain}.fake.com/pay?amount={token}&cc=4111",
]

LEGITIMATE_TEMPLATES = [
    "https://www.google.com/search?q={query}",
    "https://github.com/{user}/{repo}",
    "https://docs.python.org/3/library/{module}.html",
    "https://stackoverflow.com/questions/{id}/{slug}",
    "https://www.youtube.com/watch?v={token}",
    "https://en.wikipedia.org/wiki/{topic}",
    "https://www.amazon.com/dp/{product}",
    "https://cdn.jsdelivr.net/npm/package@{version}/dist/bundle.js",
    "https://developer.mozilla.org/en-US/docs/Web/{topic}",
    "https://news.ycombinator.com/item?id={id}",
    "https://www.reddit.com/r/{subreddit}/comments/{id}/",
    "https://mail.google.com/mail/u/0/?tab=wm",
    "https://drive.google.com/file/d/{id}/view",
    "https://calendar.google.com/calendar/r",
    "https://play.google.com/store/apps/details?id={package}",
]

SAFE_DOMAINS = [
    "google.com", "github.com", "python.org", "stackoverflow.com",
    "youtube.com", "wikipedia.org", "amazon.com", "mozilla.org",
    "reddit.com", "gmail.com", "drive.google.com", "apple.com",
    "microsoft.com", "linkedin.com", "twitter.com",
]

PHISH_DOMAINS = [
    "paypa1-secure.com", "bankofamerlca-verify.net", "apple-id-verify.org",
    "amaz0n-login.com", "microsft365-login.net", "goog1e-docs.com",
    "faceb00k-secure.org", "netf1ix-billing.com", "uberp-ay.com",
    "chase-secure-login.net", "wellsfarg0-verify.com", "dhl-parcel-tracking.com",
    "usps-shipping-confirm.org", "fedex-delivery-notice.com", "coinbase-wallet-verify.com",
]


def _random_token(length: int = 8) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=length))


def _random_slug(length: int = 12) -> str:
    return "-".join(
        "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(3, 7)))
        for _ in range(random.randint(2, 4))
    )


def generate_phishing_url() -> str:
    template = random.choice(PHISHING_TEMPLATES)
    return template.format(
        domain=random.choice(PHISH_DOMAINS),
        ip=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
        token=_random_token(random.randint(6, 16)),
        oct1=random.randint(1, 254),
        oct2=random.randint(1, 254),
    )


def generate_legitimate_url() -> str:
    template = random.choice(LEGITIMATE_TEMPLATES)
    return template.format(
        domain=random.choice(SAFE_DOMAINS),
        query="+".join(random.choices(["python", "tutorial", "news", "weather", "recipe"], k=3)),
        user=random.choice(["torvalds", "gvanrossum", "fabpot", "tj"]),
        repo=random.choice(["linux", "cpython", "laravel", "express"]),
        module=random.choice(["os", "sys", "json", "re"]),
        id=random.randint(1000000, 9999999),
        slug=_random_slug(),
        token=_random_token(),
        topic=random.choice(["URL", "API", "Web_browser", "HTML", "JavaScript"]),
        product="B0" + _random_token(8),
        version=f"{random.randint(1,5)}.{random.randint(0,9)}.{random.randint(0,20)}",
        subreddit=random.choice(["programming", "python", "webdev", "javascript"]),
        package="com." + _random_token(8),
    )


def generate_dataset(n_samples: int = 2000) -> tuple[list[str], list[int]]:
    """Generate a balanced synthetic dataset (demo only)."""
    urls, labels = [], []
    half = n_samples // 2
    for _ in range(half):
        urls.append(generate_phishing_url())
        labels.append(1)
    for _ in range(half):
        urls.append(generate_legitimate_url())
        labels.append(0)
    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)


# ---------------------------------------------------------------------------
# 3. MODEL TRAINING
# ---------------------------------------------------------------------------

def train_and_export(
    urls: list[str],
    labels: list[int],
    output_dir: str = "model",
    n_estimators: int = 100,
) -> str:
    """Train the pipeline on provided data and export to .pkl."""
    print(f"[*] Extracting features from {len(urls)} URLs...")
    X = np.array([extract_features(url) for url in urls])
    y = np.array(labels)

    # Stratified split (safe when both classes present)
    stratify = y if len(set(labels)) > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=stratify
    )

    print("[*] Building Random Forest pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=12,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    print("[*] Training model...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\n[+] Model Accuracy: {accuracy * 100:.2f}%")
    print("\n[+] Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "phishing_model.pkl")
    joblib.dump(pipeline, model_path)
    print(f"\n[+] Model saved to: {model_path}")
    return model_path


def main():
    parser = argparse.ArgumentParser(description="Train PhishGuard URL phishing model.")
    parser.add_argument("--csv", type=str, default=None,
                        help="Path to a labeled URL CSV dataset (recommended). "
                             "Leave out to use the synthetic demo generator.")
    parser.add_argument("--n-estimators", type=int, default=100,
                        help="Number of Random Forest trees.")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_directory = os.path.join(script_dir, "model")

    if args.csv:
        print(f"[*] Training on REAL dataset: {args.csv}")
        urls, labels = load_csv_dataset(args.csv)
        print(f"[*] Dataset size: {len(urls)} URLs")
    else:
        print("[*] No --csv provided. Using SYNTHETIC demo dataset (NOT production-grade).")
        print("[*] For real detection, download a dataset and pass --csv path/to/data.csv")
        urls, labels = generate_dataset(n_samples=2000)

    train_and_export(urls, labels, output_dir=output_directory, n_estimators=args.n_estimators)
    print("\n[+] Done. Restart the backend to load the new model.")


if __name__ == "__main__":
    main()
