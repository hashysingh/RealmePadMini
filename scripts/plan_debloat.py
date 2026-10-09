#!/usr/bin/env python3
"""Validate an exact-path debloat manifest against scanned APK inventory.

Read-only: emits a plan; never modifies images or device partitions.
"""
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

def normalize_dir(value):
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("Directory must be an absolute POSIX path")
    if "//" in value or "\\" in value or value.endswith("/"):
        raise ValueError("Malformed directory: " + value)
    pieces = PurePosixPath(value).parts[1:]
    if not pieces or any(x in (".", "..") for x in pieces):
        raise ValueError("Unsafe directory: " + value)
    return value

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("mode") != "dry-run-only":
        raise ValueError("Manifest must explicitly set mode=dry-run-only")
    rows = list(csv.DictReader(args.inventory.open(newline="", encoding="utf-8")))
    expected_columns = {"partition", "apk_path", "app_directory"}
    if not rows or not expected_columns.issubset(rows[0]):
        raise ValueError("APK inventory missing or invalid")
    inventory = defaultdict(list)
    for row in rows:
        key = (row["partition"], normalize_dir(row["app_directory"]))
        ap = normalize_dir(row["apk_path"])
        if not ap.startswith(key[1] + "/"):
            raise ValueError("APK file outside declared directory")
        inventory[key].append(ap)
    protected = set(manifest.get("protected_directory_names", []))
    candidates = manifest.get("targets", [])
    if not candidates:
        raise ValueError("Manifest must have at least one target")
    seen = set()
    plan = []
    blocked = []
    for target in candidates:
        partition, directory = target["partition"], normalize_dir(target["directory"])
        key = (partition, directory)
        if key in seen:
            raise ValueError("Duplicate target: " + str(key))
        seen.add(key)
        if not partition.endswith("_a.img"):
            raise ValueError("Only A-slot targets supported by this manifest: " + partition)
        if directory.split("/")[-1] in protected:
            raise ValueError("Protected directory in removal targets: " + directory)
        matches = inventory.get(key, [])
        status = "MATCHED" if matches else "NOT_FOUND"
        entry = {"partition": partition, "directory": directory,
                 "description": target["description"],
                 "status": status, "apk_count": len(matches),
                 "apks": sorted(matches)}
        plan.append(entry)
        if status != "MATCHED":
            blocked.append(entry)
    for review in manifest.get("review_only", []):
        directory = normalize_dir(review["directory"])
        if (review["partition"], directory) in seen:
            raise ValueError("Review-only entry also targeted for removal")
    # A plan is a preview, never a command list for an image editor.
    summary = {
        "device": manifest.get("device"),
        "build": manifest.get("build"),
        "mode": "DRY RUN - NO MODIFICATIONS",
        "targets": len(plan),
        "matched": len(plan) - len(blocked),
        "not_found": len(blocked),
        "inventory_apk_count": len(rows),
        "safe_to_proceed_automatically": False,
        "note": "Candidate matching is not proof that removing each app is boot-safe."
    }
    (args.out / "debloat-plan.json").write_text(
        json.dumps({"summary": summary, "plan": plan,
                    "review_only": manifest.get("review_only", [])},
                   indent=2) + "\n", encoding="utf-8")
    with (args.out / "debloat-plan.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "partition", "directory", "description", "status", "apk_count"])
        writer.writeheader()
        writer.writerows(plan)
    print(json.dumps(summary, indent=2))
    if blocked:
        raise SystemExit("Dry-run manifest has missing directories; see debloat-plan.json")

if __name__ == "__main__":
    main()
