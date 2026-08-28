"""
Generate simple placeholder PNG icons for the Chrome extension.
Run this once to create the icon files needed by manifest.json.

Usage:
    python extension/generate_icons.py
"""

import os
import struct
import zlib


def create_simple_png(size: int, color_rgb: tuple[int, int, int], filepath: str):
    """
    Create a minimal valid PNG file with a solid color shield icon.
    Uses only stdlib — no PIL/Pillow dependency required.
    """
    width = size
    height = size
    r, g, b = color_rgb

    # Build raw pixel data (RGBA)
    raw_data = b""
    for y in range(height):
        raw_data += b"\x00"  # Filter byte (None)
        for x in range(width):
            # Create a simple circular shield shape
            cx, cy = width / 2, height / 2
            radius = min(width, height) / 2 - 1
            dx = x - cx
            dy = y - cy
            dist = (dx * dx + dy * dy) ** 0.5

            if dist <= radius:
                # Inside circle — full color with slight gradient
                alpha = 255
                # Add a simple highlight on the top-left
                highlight = max(0, 1 - (dist / radius) * 0.3)
                pixel_r = min(255, int(r * highlight + 30))
                pixel_g = min(255, int(g * highlight + 30))
                pixel_b = min(255, int(b * highlight + 30))
                raw_data += struct.pack("BBBB", pixel_r, pixel_g, pixel_b, alpha)
            else:
                # Outside circle — transparent
                raw_data += struct.pack("BBBB", 0, 0, 0, 0)

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        chunk = chunk_type + data
        return struct.pack(">I", len(data)) + chunk + struct.pack(">I", zlib.crc32(chunk) & 0xFFFFFFFF)

    # PNG signature
    signature = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr = make_chunk(b"IHDR", ihdr_data)

    # IDAT chunk (compressed pixel data)
    compressed_data = zlib.compress(raw_data)
    idat = make_chunk(b"IDAT", compressed_data)

    # IEND chunk
    iend = make_chunk(b"IEND", b"")

    with open(filepath, "wb") as f:
        f.write(signature + ihdr + idat + iend)


if __name__ == "__main__":
    icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
    os.makedirs(icons_dir, exist_ok=True)

    # Blue shield color for the icon
    shield_color = (59, 130, 246)  # #3B82F6

    sizes = [16, 48, 128]
    for size in sizes:
        filepath = os.path.join(icons_dir, f"icon{size}.png")
        create_simple_png(size, shield_color, filepath)
        print(f"[+] Created {filepath}")

    print("\n[+] All icons generated successfully!")
