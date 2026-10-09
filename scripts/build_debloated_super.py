#!/usr/bin/env python3
"""Offline RMP2106 ext4 debloat build. No flashing, no AVB bypass.

Edits only the listed app directories, inside extracted images, then overwrites
their EXACT original extents in a RAW super image. LP metadata stays untouched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

SUPPORTED = {"system_a": "system_a.img", "product_a": "product_a.img"}
SECTOR = 512

def run(*args, capture=False, check=True):
    return subprocess.run(args, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)

def info(raw):
    output = run("lpdumps", str(raw), capture=True).stdout
    partitions = {}
    current = None
    for line in output.splitlines():
        m = re.match(r"\s*Name: ([\w]+)\s*$", line)
        if m:
            current = m.group(1)
            partitions[current] = []
        m = re.match(r"\s*\d+ \.\. \d+ linear super (\d+)\s*$", line)
        if m and current:
            # Extent length is parsed from the immediately preceding range.
            extent = re.search(r"(\d+) \.\. (\d+) linear super (\d+)", line)
            lo, hi, offset = map(int, extent.groups())
            partitions[current].append((offset * SECTOR, (hi - lo + 1) * SECTOR))
    return output, partitions

def validate_manifest(file):
    cfg = json.loads(Path(file).read_text())
    if cfg.get("mode") != "dry-run-only":
        raise ValueError("Unexpected manifest mode")
    targets = {}
    protected = set(cfg.get("protected_directory_names", []))
    review = {(t["partition"], t["directory"]) for t in cfg.get("review_only", [])}
    for entry in cfg["targets"]:
        p, d = entry["partition"], entry["directory"]
        if p not in SUPPORTED.values() or not isinstance(d, str):
            raise ValueError("Unsupported partition/path")
        if not d.startswith("/") or "//" in d or "\\" in d or d.endswith("/"):
            raise ValueError("Unsafe target path")
        if any(x in (".", "..") for x in d.split("/")):
            raise ValueError("Unsafe path components")
        if d.rsplit("/", 1)[-1] in protected or (p,d) in review:
            raise ValueError("Protected target path")
        targets.setdefault(p, []).append(d)
    if sum(len(v) for v in targets.values()) != 22:
        raise ValueError("Expected 22 reviewed targets")
    if len({(p, d) for p, dirs in targets.items() for d in dirs}) != 22:
        raise ValueError("Duplicate targets")
    return targets

def debug(image, instruction, write=False):
    args = ["debugfs"]
    if write:
        args.append("-w")
    args += ["-R", instruction, str(image)]
    p = run(*args, capture=True, check=False)
    # debugfs sometimes returns 0 for per-command errors.
    if p.returncode or re.search(r"(not found|File not found|No such file|not empty|Operation not permitted|error:)", p.stderr, re.I):
        raise RuntimeError("debugfs failed: " + instruction + " / " + p.stderr[-400:])
    return p.stdout

def entries(image, folder):
    content = debug(image, "ls -p " + folder)
    out = []
    for line in content.splitlines():
        items = line.split("/")
        if len(items) < 6 or not items[1].isdigit():
            continue
        name = items[5]
        if name in ("", ".", "..") or not re.fullmatch(r"[A-Za-z0-9_.+@ -]+", name):
            raise ValueError("Unexpected filename in target tree")
        mode = int(items[2], 8) & 0o170000
        out.append((name, mode == 0o040000))
    return out

def erase_tree(image, directory, stats):
    # Collect bottom-up commands BEFORE mutation: fail safely on unsupported names.
    folders = [(directory, 0)]
    commands = []
    inspected = 0
    while folders:
        current, depth = folders.pop()
        if depth > 20 or inspected >= 1500:
            raise ValueError("Target directory too deep/large")
        inspected += 1
        children = entries(image, current)
        for name, is_dir in children:
            child = current.rstrip("/") + "/" + name
            if is_dir:
                folders.append((child, depth + 1))
            else:
                commands.append(("rm", child, depth+1))
        commands.append(("rmdir", current, depth))
    # Deepest files/directories first. Files before containing dirs.
    commands.sort(key=lambda x: (-x[2], 0 if x[0] == "rm" else 1))
    for op, path, _ in commands:
        debug(image, op + " " + path, write=True)
    # Existence check: debugfs stat should now say not found.
    p = run("debugfs", "-R", "stat " + directory, str(image), capture=True, check=False)
    if "not found" not in p.stderr.lower() and "File not found" not in p.stderr:
        raise RuntimeError("Target still exists: " + directory)
    stats.append({"directory": directory, "commands": len(commands)})

def build(args):
    work = args.work
    work.mkdir(parents=True, exist_ok=True)
    args.report.mkdir(parents=True, exist_ok=True)
    raw = work / "super_raw.img"
    if not raw.is_file():
        raise ValueError("Raw super image missing")
    original_dump, extents = info(raw)
    targets = validate_manifest(args.manifest)
    # First-party metadata is unchanged: enforce this layout's single contiguous extent
    # and avoid reconstructing metadata using potentially lossy guessed lpmake flags.
    for p in SUPPORTED:
        if len(extents.get(p, [])) != 1:
            raise ValueError("Expected exactly one contiguous extent for " + p)
        start, length = extents[p][0]
        if start + length > raw.stat().st_size:
            raise ValueError("Invalid out-of-bounds extent")
    image_dir = work / "edits"
    image_dir.mkdir(exist_ok=True)
    report = {"mode": "OFFLINE BUILD - NOT FLASH VALIDATED", "modified": {},
              "raw_size": raw.stat().st_size,
              "initial_lp_metadata_sha256": hashlib.sha256(original_dump.encode()).hexdigest()}
    for p, image_name in SUPPORTED.items():
        if image_name not in targets:
            continue
        run("lpunpack", "-p", p, str(raw), str(image_dir))
        file = image_dir / image_name
        if not file.exists():
            raise ValueError("lpunpack did not create " + image_name)
        start, length = extents[p][0]
        if file.stat().st_size != length:
            raise ValueError("Unexpected partition byte length")
        with file.open("rb") as f:
            f.seek(1080)
            if f.read(2) != bytes.fromhex("53ef"):
                raise ValueError("Expected ext filesystem for " + p)
        stats = []
        for directory in targets[image_name]:
            debug(file, "stat " + directory)  # must exist before write
        for directory in targets[image_name]:
            erase_tree(file, directory, stats)
        # Fail on detectable corruption; never auto-repair stock filesystem silently.
        check = run("e2fsck", "-fn", str(file), capture=True, check=False)
        (args.report / (p + "-e2fsck.txt")).write_text(check.stdout + "\n" + check.stderr)
        if check.returncode not in (0,):
            raise ValueError(f"e2fsck reported errors for {p} (exit {check.returncode})")
        with raw.open("r+b") as out, file.open("rb") as src:
            out.seek(start)
            shutil.copyfileobj(src, out, 4 * 1024 * 1024)
        file.unlink()
        report["modified"][p] = stats
        print("Modified " + p + ": " + str(len(stats)) + " targets", flush=True)
    updated_dump, updated_extents = info(raw)
    if original_dump != updated_dump or extents != updated_extents:
        raise ValueError("LP metadata changed unexpectedly")
    report["lp_metadata_unchanged"] = True
    report["removed_target_count"] = sum(len(x) for x in report["modified"].values())
    (args.report / "build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    args.output.parent.mkdir(exist_ok=True, parents=True)
    run("img2simg", str(raw), str(args.output))
    sparse = args.output.open("rb").read(4)
    if sparse != bytes.fromhex("3aff26ed"):
        raise ValueError("Invalid sparse output")
    print("Rebuilt sparse super image: " + str(args.output), flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    build(parser.parse_args())
