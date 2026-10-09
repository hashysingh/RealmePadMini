#!/usr/bin/env python3
"""Read-only, filesystem-wide APK discovery for EXT-family super partitions.

Uses debugfs without mounting or modifying images. Candidate matches are NOT
automatic deletion instructions.
"""
import argparse
import csv
import json
import re
import subprocess
from collections import deque
from pathlib import Path

KEYWORDS = {
    "assistant": "Assistant",
    "facebook": "Facebook",
    "book": "Google Books / bookmark",
    "maps": "Maps",
    "kid": "Kids Space / YouTube Kids",
    "youtube": "YouTube / YouTube Kids / YouTube Music",
    "ytmusic": "YouTube Music",
    "music": "Music",
    "pay": "Payments",
    "gpay": "Google Pay",
    "googleone": "Google One",
    "google_one": "Google One",
    "gmail": "Gmail",
    "chrome": "Chrome",
    "realme": "Realme OEM app",
    "oppo": "OEM app",
}
# Avoid irrelevant inode-heavy trees, but DO NOT skip realme/preload directories.
SKIP_NAMES = {"lost+found", ".snapshot"}
MAX_DEPTH = 20
MAX_DIRECTORIES = 15000


def ls(image, directory):
    result = subprocess.run(
        ["debugfs", "-R", "ls -p " + directory, str(image)],
        capture_output=True, text=True, timeout=40,
    )
    if result.returncode:
        return [], result.stderr.strip()[:180]
    entries = []
    for line in result.stdout.splitlines():
        fields = line.split("/")
        if len(fields) < 6 or not fields[1].isdigit():
            continue
        name, mode = fields[5], fields[2]
        if name in ("", ".", "..") or "/" in name or "\x00" in name:
            continue
        try:
            mode_num = int(mode, 8)
        except ValueError:
            continue
        entries.append((name, (mode_num & 0o170000) == 0o040000,
                        (mode_num & 0o170000) == 0o100000))
    return entries, None


def ext_magic(path):
    if path.stat().st_size < 1082:
        return False
    with path.open("rb") as f:
        f.seek(1080)
        return f.read(2) == bytes.fromhex("53ef")


def scan(image, maxdirs):
    queue = deque([("/", 0)])
    seen = set()
    matches, findings = [], []
    errors, count, truncated = [], 0, False
    while queue:
        directory, depth = queue.popleft()
        if directory in seen:
            continue
        if count >= maxdirs:
            truncated = True
            break
        seen.add(directory)
        count += 1
        entries, err = ls(image, directory)
        if err:
            errors.append({"directory": directory, "message": err})
            continue
        for name, is_dir, is_file in entries:
            path = directory.rstrip("/") + "/" + name
            if is_dir and depth < MAX_DEPTH and name not in SKIP_NAMES:
                queue.append((path, depth + 1))
            if is_file and name.lower().endswith(".apk"):
                record = {"partition": image.name, "apk_path": path,
                          "app_directory": directory}
                matches.append(record)
                text = path.lower().replace("-", "").replace(" ", "")
                tags = sorted({value for key, value in KEYWORDS.items()
                               if key in text})
                if tags:
                    findings.append({**record, "matched_keywords": ", ".join(tags)})
        if count % 1000 == 0:
            print(f"{image.name}: scanned {count} directories; {len(matches)} APKs", flush=True)
    return matches, findings, {
        "partition": image.name, "directories_scanned": count,
        "truncated": truncated, "unvisited_directories": len(queue),
        "directory_errors": errors[:30], "directory_error_count": len(errors),
    }


def write_csv(path, columns, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--partitions", type=Path, required=True)
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--max-directories", type=int, default=MAX_DIRECTORIES)
    args = ap.parse_args()
    if not 100 <= args.max_directories <= 30000:
        ap.error("--max-directories must be between 100 and 30000")
    args.report.mkdir(parents=True, exist_ok=True)
    apk_rows, candidate_rows, stats = [], [], []
    for image in sorted(args.partitions.glob("*.img")):
        if not ext_magic(image):
            stats.append({"partition": image.name, "status": "empty/non-EXT"})
            continue
        apk, candidates, stat = scan(image, args.max_directories)
        apk_rows.extend(apk)
        candidate_rows.extend(candidates)
        stats.append(stat)
    write_csv(args.report / "all-apks.csv",
              ["partition", "apk_path", "app_directory"], apk_rows)
    write_csv(args.report / "debloat-candidates.csv",
              ["partition", "apk_path", "app_directory", "matched_keywords"],
              candidate_rows)
    (args.report / "scan-statistics.json").write_text(
        json.dumps({"statistics": stats, "apk_count": len(apk_rows),
                    "candidate_count": len(candidate_rows),
                    "automatic_removal": False}, indent=2) + "\n")
    incomplete = [s for s in stats if s.get("truncated") or s.get("directory_error_count")]
    print(f"Read-only scan: {len(apk_rows)} APKs, {len(candidate_rows)} possible candidates")
    if incomplete:
        print("WARNING: directory scan had limitations; review scan-statistics.json")
    else:
        print("Directory scan completed without reported traversal errors.")


if __name__ == "__main__":
    main()
