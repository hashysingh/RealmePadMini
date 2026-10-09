#!/usr/bin/env python3
"""Read-only independent stock vs delivered super image block and APK audit."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

PARTS = ("system_a", "product_a", "system_ext_a", "vendor_a",
         "system_b", "product_b", "system_ext_b", "vendor_b")
TARGETS = {"product_a": ("/app/YouTube", "/app/Maps", "/app/Chrome"),
           "system_a": ("/system/preloadapp/YTMusic", "/system/preloadapp/YouTubeKids")}

def cmd(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()

def extent_digest(raw, start, size):
    h = hashlib.sha256()
    with raw.open("rb") as f:
        f.seek(start)
        while size:
            block = f.read(min(4 * 1024 * 1024, size))
            if not block:
                raise ValueError("Unexpected EOF while hashing LP extent")
            h.update(block)
            size -= len(block)
    return h.hexdigest()

def partition_extents(metadata):
    current = None
    result = {}
    for line in metadata.splitlines():
        name = re.fullmatch(r"\s*Name: (\S+)\s*", line)
        if name:
            current = name.group(1)
            if current in PARTS:
                result[current] = []
        extent = re.fullmatch(r"\s*(\d+) \.\. (\d+) linear super (\d+)\s*", line)
        if extent and current in PARTS:
            lo, hi, sector = map(int, extent.groups())
            result[current].append((sector * 512, (hi-lo+1) * 512))
    if set(result) != set(PARTS):
        raise ValueError("Partition metadata incomplete: " + str(sorted(result)))
    return result

def present(image, path):
    p = subprocess.run(["debugfs", "-R", "stat " + path, str(image)],
                       text=True, capture_output=True)
    if p.returncode or (not re.search("Inode:", p.stdout)
                        and not re.search("not found|No such file", p.stderr, re.I)):
        raise RuntimeError("Could not inspect " + path + ": " + p.stderr[-250:])
    return "Inode:" in p.stdout

def main():
    a = argparse.ArgumentParser()
    a.add_argument("--stock", type=Path, required=True)
    a.add_argument("--debloated", type=Path, required=True)
    a.add_argument("--work", type=Path, required=True)
    a.add_argument("--report", type=Path, required=True)
    args = a.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    args.report.mkdir(parents=True, exist_ok=True)
    raw = {}
    sections = {}
    extracted = {}
    for key, source in (("stock", args.stock), ("debloated", args.debloated)):
        raw[key] = args.work / (key + "-super-raw.img")
        with source.open("rb") as f:
            magic = f.read(4)
        if magic == bytes.fromhex("3aff26ed"):
            subprocess.run(["simg2img", str(source), str(raw[key])], check=True)
        else:
            raise ValueError(key + " input must be an Android sparse image")
        sections[key] = cmd("lpdumps", str(raw[key]))
        extracted[key] = args.work / (key + "-partitions")
        extracted[key].mkdir(exist_ok=True)
        subprocess.run(["lpunpack", str(raw[key]), str(extracted[key])], check=True)
    if raw["stock"].stat().st_size != raw["debloated"].stat().st_size:
        raise ValueError("Super raw sizes differ")
    same_metadata = sections["stock"] == sections["debloated"]
    stock_extents = partition_extents(sections["stock"])
    new_extents = partition_extents(sections["debloated"])
    if stock_extents != new_extents or not same_metadata:
        raise ValueError("LP partition extents or metadata changed")
    results = []
    failures = []
    for partition in PARTS:
        old = extracted["stock"] / (partition + ".img")
        new = extracted["debloated"] / (partition + ".img")
        if not old.is_file() or not new.is_file():
            raise ValueError("lpunpack output missing for " + partition)
        oldhash, newhash = digest(old), digest(new)
        extents = stock_extents[partition]
        new_size = new.stat().st_size
        if extents:
            if len(extents) != 1 or extents[0][1] != new_size:
                raise ValueError("Unexpected partition extent geometry " + partition)
            physical_hash = extent_digest(raw["debloated"], *extents[0])
            if physical_hash != newhash:
                failures.append(partition + ": unpacked bytes differ from raw LP extent")
        elif new_size != 0:
            failures.append(partition + ": populated image has no extent")
        changed = oldhash != newhash
        if partition in ("system_a", "product_a") and not changed:
            failures.append(partition + ": expected modifications, but image identical to stock")
        if partition not in ("system_a", "product_a") and changed:
            failures.append(partition + ": unexpected changed partition")
        targets = []
        for path in TARGETS.get(partition, ()):
            stock_present = present(old, path)
            output_present = present(new, path)
            targets.append({"path":path, "stock_present":stock_present,
                            "output_present":output_present})
            if not stock_present or output_present:
                failures.append(partition + ":" + path + " fails before/after removal test")
        results.append({"partition":partition, "bytes":new_size,
                        "stock_sha256":oldhash, "debloated_sha256":newhash,
                        "changed":changed, "sample_target_checks":targets})
    report = {"source":"stock image versus exact delivered build artifact",
              "stock_sparse_sha256":digest(args.stock),
              "debloated_sparse_sha256":digest(args.debloated),
              "raw_bytes":raw["stock"].stat().st_size,
              "metadata_identical":same_metadata,
              "partition_findings":results,"failures":failures,
              "device_flash_verified":False}
    (args.report / "partition-block-audit.json").write_text(json.dumps(report, indent=2)+"\n")
    lines = ["READ-ONLY SUPER.IMG STOCK/DEBLOATED BLOCK AUDIT", "="*64,
             "Compares independently re-extracted partitions and actual RAW extents.",
             "This cannot confirm what was written/mounted on the tablet.",
             "Debloated image SHA256: "+report["debloated_sparse_sha256"],
             "RAW image bytes: "+str(report["raw_bytes"]),
             "LP metadata identical: "+str(same_metadata)," "]
    for entry in results:
        lines += [entry["partition"]+": "+("CHANGED" if entry["changed"] else "IDENTICAL"),
                  "  stock SHA256: "+entry["stock_sha256"],
                  "  output SHA256: "+entry["debloated_sha256"]]
        for target in entry["sample_target_checks"]:
            lines.append("  "+target["path"]+" stock="+str(target["stock_present"])+
                         " output="+str(target["output_present"]))
    lines += ["", "FAILURES: "+(str(failures) if failures else "none"),
              "DEVICE CONTENTS: NOT CHECKED"]
    (args.report / "READ_ME_BLOCK_AUDIT.txt").write_text("\n".join(lines)+"\n")
    print("\n".join(lines), flush=True)
    if failures:
        raise SystemExit("Independent block audit FAILED, see report")

if __name__ == "__main__":
    main()
