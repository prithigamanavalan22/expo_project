"""
Train a Random Forest Classifier for URL Phishing Detection.

This script:
  1. Generates a synthetic training dataset of phishing and legitimate URLs.
  2. Extracts lexical features via feature_extractor.
  3. Trains a Random Forest pipeline (scaler + classifier).
  4. Evaluates the model and saves it as a .pkl file via joblib.

Usage:
    python ml_model/train_model.py
"""

import os
import random
import re
import warnings

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from feature_extractor import extract_features

warnings.filterwarnings("ignore")

# ---------------------------------------------------------------------------
# Synthetic Dataset Generation
# ---------------------------------------------------------------------------
# In production you would use a real dataset (e.g., PhishTank, Kaggle URLs).
# This synthetic generator creates labelled samples to exercise the pipeline.

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
    """
    Generate a balanced synthetic dataset of phishing (1) and legitimate (0) URLs.
    """
    urls = []
    labels = []

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
# Model Training
# ---------------------------------------------------------------------------

def train_and_export(output_dir: str = "model") -> str:
    """
    Generate data, train a Random Forest pipeline, evaluate, and export to .pkl.
    Returns the path to the saved model file.
    """
    print("[*] Generating synthetic dataset (2000 samples)...")
    urls, labels = generate_dataset(n_samples=2000)

    print("[*] Extracting features...")
    X = np.array([extract_features(url) for url in urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[*] Building Random Forest pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
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

    # Export model
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "phishing_model.pkl")
    joblib.dump(pipeline, model_path)
    print(f"\n[+] Model saved to: {model_path}")

    return model_path


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_directory = os.path.join(script_dir, "model")
    train_and_export(output_dir=output_directory)
