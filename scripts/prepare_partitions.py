#!/usr/bin/env python3
"""Verify original super.img and unpack it without modifying any partition."""
import hashlib
from pathlib import Path
import re
import subprocess
import sys

def main():
    original, work, expected = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    if not original.is_file() or original.stat().st_size == 0:
        raise ValueError("Missing input super.img")
    if original.stat().st_size > 18 * 1024 ** 3:
        raise ValueError("Input image exceeds size limit")
    digest = hashlib.sha256()
    with original.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(part)
    print("Downloaded SHA-256:", digest.hexdigest(), flush=True)
    if expected and (not re.fullmatch(r"[0-9a-fA-F]{64}", expected)
                     or expected.lower() != digest.hexdigest()):
        raise ValueError("SHA-256 does not match")
    with original.open("rb") as f:
        sparse = f.read(4) == bytes.fromhex("3aff26ed")
    raw = work / "super_raw.img" if sparse else original
    if sparse:
        subprocess.run(["simg2img", str(original), str(raw)], check=True)
    parts = work / "partitions"
    parts.mkdir(parents=True, exist_ok=True)
    subprocess.run(["lpunpack", str(raw), str(parts)], check=True)
    print("Extracted:", ", ".join(p.name for p in sorted(parts.glob("*.img"))), flush=True)

if __name__ == "__main__":
    main()
