#!/usr/bin/env python3
"""Independently validate an EXPERIMENTAL generated Android sparse super image.

Read-only verification; cannot establish that AVB accepts the modified image,
that the bootloader permits it, or that the tablet will boot.
"""
import argparse
import csv
import hashlib
import json
import re
import subprocess
from scan_all_apks import scan, MAX_DIRECTORIES
from pathlib import Path

def cmd(*args):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True)

def dir_present(image, path):
    r = subprocess.run(["debugfs", "-R", "stat " + path, str(image)],
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("debugfs execution failed: " + r.stderr[-300:])
    if re.search(r"(File not found|not found|No such file)", r.stderr, re.I):
        return False
    if "Inode:" not in r.stdout:
        raise RuntimeError("Indeterminate debugfs stat for " + path +
                           ": " + (r.stdout + r.stderr)[-300:])
    return True

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--expected-sha256", default="")
    args = p.parse_args()
    args.report.mkdir(parents=True, exist_ok=True)
    if args.image.stat().st_size < 1024:
        raise ValueError("Output image is unexpectedly small")
    with args.image.open("rb") as f:
        if f.read(4) != bytes.fromhex("3aff26ed"):
            raise ValueError("Output is not an Android sparse image")
    digest = hashlib.sha256()
    with args.image.open("rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            digest.update(block)
    actual = digest.hexdigest()
    if args.expected_sha256 and actual != args.expected_sha256:
        raise ValueError("Output SHA-256 mismatch")
    raw = args.report / "validated_super_raw.img"
    subprocess.run(["simg2img", str(args.image), str(raw)], check=True)
    metadata = cmd("lpdumps", str(raw)).stdout
    (args.report / "validated-lp-metadata.txt").write_text(metadata)
    # Check known RMP2106 partition names as printed by the same lpdumps
    required = ["system_a", "product_a", "system_ext_a", "vendor_a",
                "system_b", "product_b", "system_ext_b", "vendor_b"]
    all_names = re.findall(r"^\s*Name: (\S+)\s*$", metadata, re.M)
    # lpdumps also displays partition-group names as "Name:" entries.
    # These are not extractable partitions; validate them separately.
    expected_groups = {"default", "group_unisoc_a", "group_unisoc_b"}
    groups_present = sorted(name for name in all_names if name in expected_groups)
    present = sorted(name for name in all_names if name not in expected_groups)
    if present != sorted(required) or groups_present != sorted(expected_groups):
        raise ValueError("Unexpected LP partition/group names: " + str(all_names))
    partitions = args.report / "extracted"
    partitions.mkdir(exist_ok=True)
    subprocess.run(["lpunpack", str(raw), str(partitions)], check=True)
    manifest = json.loads(args.manifest.read_text())
    targets = manifest["targets"]
    by_partition = {}
    for t in targets:
        by_partition.setdefault(t["partition"], []).append(t["directory"])
    checks = []
    fsck = {}
    all_apks = []
    scan_stats = []
    for part in required:
        image = partitions / (part + ".img")
        if not image.exists():
            raise ValueError("Missing partition image " + image.name)
        if image.stat().st_size == 0:
            if not part.endswith("_b"):
                raise ValueError("Unexpected empty populated partition " + part)
            continue
        with image.open("rb") as f:
            f.seek(1080)
            if f.read(2) != bytes.fromhex("53ef"):
                raise ValueError("Partition is not EXT-family: " + part)
        result = subprocess.run(["e2fsck", "-fn", str(image)],
                                text=True, capture_output=True)
        fsck[part] = result.returncode
        (args.report / (part + "-fsck.txt")).write_text(result.stdout + "\n" + result.stderr)
        if result.returncode != 0:
            raise ValueError(f"Filesystem check failed for {part}: exit {result.returncode}")
        for directory in by_partition.get(part + ".img", []):
            is_present = dir_present(image, directory)
            checks.append({"partition": part, "directory": directory,
                           "removed": not is_present})
            if is_present:
                raise ValueError("Debloat target still exists: " + part + ":" + directory)
        # Search the ENTIRE remaining EXT filesystem, not just known directories.
        # This catches duplicate APK filenames in unexpected system folders.
        apk_rows, _, scan_stat = scan(image, MAX_DIRECTORIES)
        all_apks.extend(apk_rows)
        scan_stats.append(scan_stat)
        if scan_stat["truncated"] or scan_stat["directory_error_count"]:
            raise ValueError("Incomplete full-partition APK scan: " + part +
                             " " + json.dumps(scan_stat))
    if len(checks) != len(targets):
        raise ValueError("Not all manifest targets were checked")
    expected_filenames = {
        target["directory"].rstrip("/").rsplit("/", 1)[-1].lower() + ".apk"
        for target in targets
    }
    unexpected_apks = [
        row for row in all_apks
        if row["apk_path"].rsplit("/", 1)[-1].lower() in expected_filenames
    ]
    with (args.report / "remaining-apks.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["partition", "apk_path", "app_directory"])
        writer.writeheader()
        writer.writerows(all_apks)
    with (args.report / "removal-proof.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["partition", "directory", "removed"])
        writer.writeheader()
        writer.writerows(checks)
    (args.report / "apk-scan-statistics.json").write_text(
        json.dumps(scan_stats, indent=2) + "\n")
    if unexpected_apks:
        raise ValueError("APK copies with targeted filenames still exist: " +
                         json.dumps(unexpected_apks, indent=2))
    summary = {"phase": "4 - OFFLINE VALIDATION ONLY",
               "avb_verified": False, "boot_verified": False,
               "safe_to_flash": False,
               "image_sha256": actual, "partition_names": required,
               "removed_directories_verified": len(checks),
               "full_partition_apk_scan_complete": True,
               "remaining_apk_count": len(all_apks),
               "target_filename_copies_found": len(unexpected_apks),
               "user_data_partition_checked": False,
               "filesystem_checks": fsck,
               "target_checks": checks}
    (args.report / "validation-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "target_checks"}, indent=2),
          flush=True)
    # Keep only small report files in upload, never extracted 8GB of partitions.
    for item in partitions.glob("*.img"):
        item.unlink()
    partitions.rmdir()
    raw.unlink()

if __name__ == "__main__":
    main()
