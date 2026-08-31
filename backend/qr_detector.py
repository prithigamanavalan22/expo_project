"""
PhishGuard QR Code Phishing Detector
====================================

Accepts an uploaded image containing a QR code, decodes it with OpenCV,
extracts the embedded URL(s), and analyzes them for phishing.

SECURITY / SAFETY:
  - OpenCV's QRCodeDetector is used (pure decode, no code execution).
  - Only image bytes are processed in-memory; nothing is persisted unless routed.
  - The decoded URL is fed through the same risk engine as normal scans.
  - Image size is capped to prevent memory abuse.

Dependency: opencv-python (cv2)
"""

import io

import cv2
import numpy as np

MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB


class QRDecodeError(Exception):
    """Raised when a QR code cannot be decoded from the upload."""


def _try_decode(img):
    """Attempt QR decode on a BGR image; returns (data, success)."""
    detector = cv2.QRCodeDetector()
    try:
        data, points, _ = detector.detectAndDecode(img)
        if data:
            return data, True
    except Exception:
        pass
    return "", False


def decode_qr_from_bytes(image_bytes: bytes) -> list[str]:
    """
    Decode QR code(s) from raw image bytes.
    Returns the list of decoded payload strings (usually one per QR).
    Raises QRDecodeError if no QR / decode failure.
    """
    if not image_bytes:
        raise QRDecodeError("Empty image upload.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise QRDecodeError("Image too large (max 10 MB).")

    # Convert bytes -> numpy array -> BGR image (OpenCV format)
    try:
        np_arr = np.frombuffer(image_bytes, dtype=np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    except Exception:
        raise QRDecodeError("Could not read the image (corrupt or unsupported format).")

    if img is None:
        raise QRDecodeError("Could not read the image (corrupt or unsupported format).")

    # Try a series of preprocessing strategies to handle real camera photos
    # (blur, perspective distortion, low contrast) as well as clean screenshots.
    candidates = [img]
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Downscale very large photos (helps the detector converge & speeds up)
    h, w = gray.shape[:2]
    largest = max(h, w)
    if largest > 1200:
        scale = 1200.0 / largest
        gray_small = cv2.resize(gray, (int(w * scale), int(h * scale)))
        candidates.append(cv2.cvtColor(gray_small, cv2.COLOR_GRAY2BGR))
    else:
        candidates.append(cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR))

    # Threshold variants to boost contrast for faded camera captures
    _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    candidates.append(cv2.cvtColor(thresh, cv2.COLOR_GRAY2BGR))

    # Adaptive threshold for uneven lighting
    try:
        adap = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY, 31, 15,
        )
        candidates.append(cv2.cvtColor(adap, cv2.COLOR_GRAY2BGR))
    except Exception:
        pass

    decoded_items = []
    for cand in candidates:
        data, ok = _try_decode(cand)
        if ok:
            for piece in data.split():
                piece = piece.strip()
                if piece and piece not in decoded_items:
                    decoded_items.append(piece)

    # Fall back to rotating the original image for slightly rotated QR codes
    if not decoded_items:
        for angle in (90, 180, 270):
            rows, cols = img.shape[:2]
            m = cv2.getRotationMatrix2D((cols / 2, rows / 2), angle, 1)
            rotated = cv2.warpAffine(img, m, (cols, rows))
            data, ok = _try_decode(rotated)
            if ok:
                for piece in data.split():
                    piece = piece.strip()
                    if piece and piece not in decoded_items:
                        decoded_items.append(piece)

    if not decoded_items:
        raise QRDecodeError(
            "No QR code could be decoded. Ensure the QR is clearly visible, "
            "well-lit, and not blurry or tilted."
        )

    return decoded_items


def extract_urls(qr_data: list[str]) -> list[str]:
    """
    Filter decoded QR payload strings down to actual http/https URLs.
    Phishing QR codes almost always embed a malicious URL.
    """
    urls = []
    for d in qr_data:
        d = d.strip()
        if d.lower().startswith(("http://", "https://")):
            urls.append(d)
    return urls
