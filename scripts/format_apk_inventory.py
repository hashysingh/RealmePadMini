#!/usr/bin/env python3
"""Produce readable A-Z APK inventories from the read-only partition scanner."""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = args.report
    with (report / "all-apks.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    stats = json.loads((report / "scan-statistics.json").read_text(encoding="utf-8"))
    scanned = stats["statistics"]
    if any(s.get("truncated") or s.get("directory_error_count") for s in scanned):
        raise RuntimeError("Cannot certify A-Z listing: one or more scans were incomplete.")
    rows.sort(key=lambda r: (
        Path(r["apk_path"]).name.casefold(), r["partition"].casefold(), r["apk_path"].casefold()
    ))
    by_partition = defaultdict(list)
    for row in rows:
        by_partition[row["partition"]].append(row)
    header = [
        "REALME PAD MINI - ALL APK FILES A-Z",
        "=" * 66,
        "Source: supplied super.img, read-only extraction",
        "Alphabetical order: APK filename (A-Z), then partition and full path.",
        "Each entry is an APK file, not necessarily a distinct installed app.",
        "Only EXT-family partitions inside super.img are scanned; /data is not included.",
        f"Total APK files found: {len(rows)}",
        "",
        "FORMAT: APK filename | logical partition | full filesystem path",
        "-" * 66,
    ]
    for index, row in enumerate(rows, 1):
        header.append(
            f'{index:03d}. {Path(row["apk_path"]).name} | '
            f'{row["partition"].removesuffix(".img")} | {row["apk_path"]}'
        )
    (report / "ALL_APKS_A_TO_Z.txt").write_text(
        "\n".join(header) + "\n", encoding="utf-8"
    )
    summary = [
        "APK FILES GROUPED BY PARTITION",
        "=" * 66,
        "Source: supplied super.img (not modified)",
        "",
    ]
    for part_stat in sorted(scanned, key=lambda r: r["partition"].casefold()):
        part = part_stat["partition"]
        entries = sorted(by_partition.get(part, []),
                         key=lambda r: (r["apk_path"].casefold(), Path(r["apk_path"]).name.casefold()))
        summary.append(f'[{part.removesuffix(".img")}] - {len(entries)} APK files')
        if part_stat.get("status"):
            summary.append("  Status: " + part_stat["status"])
        for row in entries:
            summary.append("  " + row["apk_path"])
        summary.append("")
    (report / "APKS_BY_PARTITION.txt").write_text(
        "\n".join(summary) + "\n", encoding="utf-8"
    )
    print(f"Created ALL_APKS_A_TO_Z.txt and APKS_BY_PARTITION.txt ({len(rows)} APK files).",
          flush=True)


if __name__ == "__main__":
    main()
