#!/usr/bin/env python3
"""Read-only sparse super and EXT filesystem inspection for RMP2106."""
import csv
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOTS = ["/app", "/priv-app", "/system/app", "/system/priv-app",
         "/product/app", "/product/priv-app", "/system_ext/app",
         "/system_ext/priv-app", "/vendor/app", "/vendor/priv-app",
         "/system/product/app", "/system/product/priv-app"]

def call(*args, output=None):
    subprocess.run(args, check=True, stdout=output, stderr=subprocess.PIPE)

def listdir(image, path):
    p = subprocess.run(["debugfs", "-R", "ls -p " + path, str(image)],
                       capture_output=True, text=True)
    if p.returncode:
        return []
    names = []
    for line in p.stdout.splitlines():
        columns = line.split("/")
        if len(columns) >= 6 and columns[1].isdigit():
            name = columns[5]
            if name not in (".", "..", ""):
                names.append(name)
    return names

def is_ext(image):
    if image.stat().st_size < 1082:
        return False
    with image.open("rb") as stream:
        stream.seek(1080)
        return stream.read(2) == bytes.fromhex("53ef")

def main(src, work, report, expected):
    work, report, src = Path(work), Path(report), Path(src)
    report.mkdir(parents=True, exist_ok=True)
    if not src.is_file() or not src.stat().st_size:
        raise ValueError("Download missing")
    if src.stat().st_size > 18 * 1024 ** 3:
        raise ValueError("Input too large")
    h = hashlib.sha256()
    with src.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    checksum = h.hexdigest()
    if expected and (not re.fullmatch(r"[a-fA-F0-9]{64}", expected) or checksum != expected.lower()):
        raise ValueError("SHA-256 mismatch")
    with src.open("rb") as stream:
        sparse = stream.read(4) == bytes.fromhex("3aff26ed")
    raw = work / "super_raw.img" if sparse else src
    if sparse:
        call("simg2img", str(src), str(raw))
    with (report / "lpdump.txt").open("wb") as output:
        call("lpdump", str(raw), output=output)
    out = work / "partitions"
    out.mkdir(exist_ok=True)
    call("lpunpack", str(raw), str(out))
    parts, apps = [], []
    for image in sorted(out.glob("*.img")):
        ext = is_ext(image)
        parts.append({"name": image.name, "size": image.stat().st_size,
                      "filesystem": "ext-family" if ext else "unknown/empty"})
        if ext:
            for root in ROOTS:
                for folder in listdir(image, root):
                    if not re.fullmatch(r"[A-Za-z0-9_.+@ -]+", folder):
                        continue
                    for name in listdir(image, root + "/" + folder):
                        if name.endswith(".apk"):
                            apps.append([image.name, root + "/" + folder, name])
    (report / "partitions.json").write_text(json.dumps({
        "sha256": checksum, "sparse": sparse, "partitions": parts}, indent=2))
    with (report / "apps.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["partition", "directory", "apk"])
        writer.writerows(apps)
    (report / "summary.txt").write_text(
        f"Read-only inspection: {len(parts)} partitions; {len(apps)} APKs. No modifications made.\n")

if __name__ == "__main__":
    try:
        main(*sys.argv[1:5])
    except Exception as exc:
        print("Inspection failed:", type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
