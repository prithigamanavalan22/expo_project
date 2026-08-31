"""
Download a real URL phishing dataset and train the PhishGuard model on it.

This script downloads a clean, balanced dataset of 200,000 URLs
(100k legitimate + 100k phishing) from a public GitHub repository,
then trains the Random Forest pipeline and exports the .pkl model.

Usage:
    python ml_model/download_and_train.py

The downloaded CSV is cached in the data/ directory so you only
download it once. Re-run any time to retrain.

Dataset: RajaMuhammadAwais/phishing-url-dataset
  - Columns: URL (string), Label (1 = legitimate, 0 = phishing)
  - Sources: UCI PhiUSIIL + Phishing.Database (PhishTank feeds)
"""

import os
import sys
import urllib.request

# ---------------------------------------------------------------------------
# Path setup so we can import feature_extractor
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, SCRIPT_DIR)

# Import the training module
from train_model import load_csv_dataset, train_and_export  # noqa: E402

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATASET_URL = (
    "https://raw.githubusercontent.com/RajaMuhammadAwais/"
    "phishing-url-dataset/master/phishing_url_dataset.csv"
)
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "model")
CSV_PATH = os.path.join(DATA_DIR, "phishing_url_dataset.csv")


def download_dataset(url: str, dest: str):
    """Download the dataset to dest if it doesn't already exist (caching)."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    if os.path.exists(dest):
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"[*] Using cached dataset: {dest} ({size_mb:.1f} MB)")
        return dest

    print(f"[*] Downloading dataset from {url}")
    print("[*] This is ~10 MB and may take a moment...")

    try:
        urllib.request.urlretrieve(url, dest)
    except Exception as e:
        print(f"[!] Download failed: {e}")
        print("[!] Check your internet connection, or download the CSV manually and")
        print("[!] place it at:", dest)
        sys.exit(1)

    size_mb = os.path.getsize(dest) / (1024 * 1024)
    print(f"[+] Downloaded {size_mb:.1f} MB to {dest}")
    return dest


def main():
    print("\n=== PhishGuard: Real Dataset Download & Train ===")
    print("-" * 50)

    # 1. Download (cached)
    csv_path = download_dataset(DATASET_URL, CSV_PATH)

    # 2. Load and inspect
    print("\n[*] Loading dataset...")
    urls, labels = load_csv_dataset(csv_path)
    print(f"[*] Total usable URLs: {len(urls)}")

    # 3. Train and export
    model_path = train_and_export(urls, labels, output_dir=OUTPUT_DIR)

    print("\n" + "-" * 50)
    print(f"[+] Model saved to: {model_path}")
    print("[+] Restart the backend to load this new model:")
    print("    Windows:  stop the server, then run  python run_server.py")


if __name__ == "__main__":
    main()
