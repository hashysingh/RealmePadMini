#!/usr/bin/env python3
"""Audit original PAC dm-verity descriptors against unchanged and debloated LP images.

Read-only: never changes PAC, super image, vbmeta, or tablet.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

PAC_HEADER = "<44sII512s512sIIIIIII200sIII800sIHH"
PAC_ENTRY = "<I512s512s504sIIIIIIII5I996s"
PINNED_PAC = "381c295640947371b604ab830da04dc6d90be4b3c99b9c9c409c73dd51320c0b"
PINNED_MODIFIED = "d1266658821f587a273e139841f861c7ae1557d3415dde8fc8990aa1e62d74f3"
PARTITIONS = {"system": "VBMETA_SYSTEM", "product": "VBMETA_PRODUCT"}

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

def decoded(b):
    return b.decode("utf-16le", errors="replace").split("\x00", 1)[0]

def pac_descriptors(pac, directory):
    items = {}
    with pac.open("rb") as stream:
        header = struct.unpack(PAC_HEADER, stream.read(struct.calcsize(PAC_HEADER)))
        count, offset = header[5:7]
        length = struct.calcsize(PAC_ENTRY)
        if not 1 <= count <= 1024 or offset < struct.calcsize(PAC_HEADER) or offset + count * length > pac.stat().st_size:
            raise ValueError("Invalid PAC file table")
        stream.seek(offset)
        for _ in range(count):
            record = struct.unpack(PAC_ENTRY, stream.read(length))
            if record[0] != length:
                raise ValueError("Unrecognized PAC record size")
            ident = decoded(record[1])
            if ident in PARTITIONS.values():
                items[ident] = ((record[5] << 32) | record[9], (record[4] << 32) | record[6])
        if set(items) != set(PARTITIONS.values()):
            raise ValueError("PAC missing expected AVB descriptors")
        files = {}
        for ident, (position, size) in items.items():
            if not 0 < size <= 65536 or position + size > pac.stat().st_size:
                raise ValueError("PAC vbmeta payload size/offset invalid")
            stream.seek(position)
            output = directory / (ident.lower() + ".img")
            output.write_bytes(stream.read(size))
            if output.read_bytes()[:4] != b"AVB0":
                raise ValueError("AVB0 header missing in " + ident)
            files[ident] = output
    return files

def avb_info(tool, vbmeta):
    result = subprocess.run(["python3", str(tool), "info_image", "--image", str(vbmeta)], text=True, capture_output=True)
    if result.returncode:
        raise ValueError("avbtool info_image failed: " + result.stderr[-1000:])
    text = result.stdout
    desc = re.findall(r"Hashtree descriptor:\s+(.*?)(?=\n\s*(?:Hashtree|Hash|Chain Partition|Kernel Cmdline|Prop) descriptor:|\Z)", text, re.S)
    parsed = []
    for d in desc:
        fields = dict(re.findall(r"^\s*(Image Size|Tree Offset|Tree Size|Data Block Size|Hash Block Size|FEC offset|FEC size|Hash Algorithm|Partition Name|Root Digest|Salt|Flags):\s*(.*?)\s*$", d, re.M))
        parsed.append(fields)
    return text, parsed

def verify_partition(tool, image, vbmeta):
    proc = subprocess.run(
        ["python3", str(tool), "verify_image", "--image", str(image),
         "--expected_chain_partition", "unused:0:unused"],
        text=True, capture_output=True)
    # Do not rely on verify_image: it expects AVB footer and chain context on an image;
    # authoritative direct hashtree comparison is calculated below.
    return {"not_used": True, "reason": "Actual check computes dm-verity Merkle root against signed vbmeta root digest"}

def merkle_root(image, descriptor):
    # dm-verity AVB layout: salted hash of each data block, padded digests to
    # hash-block boundaries, recursively salted hash of each hash-block.
    algorithm = descriptor["Hash Algorithm"]
    if algorithm not in ("sha1", "sha256"):
        raise ValueError("Unsupported dm-verity digest algorithm: " + algorithm)
    hfunc = getattr(hashlib, algorithm)
    salt = bytes.fromhex(descriptor["Salt"])
    image_size = int(descriptor["Image Size"].split()[0])
    data_block = int(descriptor["Data Block Size"].split()[0])
    hash_block = int(descriptor["Hash Block Size"].split()[0])
    if data_block != 4096 or hash_block != 4096:
        raise ValueError("Only 4096-byte AVB hashtree layouts are supported")
    if not image_size or image_size % data_block or image_size > image.stat().st_size:
        raise ValueError("Invalid hashtree image size for " + str(image))
    digest_len = hfunc().digest_size
    capacity = hash_block // digest_len
    if capacity < 2:
        raise ValueError("Invalid Merkle fan-out")
    current = []
    with image.open("rb") as stream:
        for _ in range(image_size // data_block):
            data = stream.read(data_block)
            if len(data) != data_block:
                raise ValueError("Short read in " + str(image))
            current.append(hfunc(salt + data).digest())
    # The level's root is the salted hash of its padded hash block. A root digest
    # with one data block still hashes the block of leaf hashes.
    while True:
        next_level = []
        for start in range(0, len(current), capacity):
            joined = b"".join(current[start:start + capacity]).ljust(hash_block, b"\x00")
            next_level.append(hfunc(salt + joined).digest())
        if len(next_level) == 1:
            return next_level[0].hex()
        current = next_level

def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--pac", type=Path, required=True)
    cli.add_argument("--modified", type=Path, required=True)
    cli.add_argument("--avbtool", type=Path, required=True)
    cli.add_argument("--work", type=Path, required=True)
    cli.add_argument("--report", type=Path, required=True)
    args = cli.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    args.report.mkdir(parents=True, exist_ok=True)
    if sha256(args.pac) != PINNED_PAC:
        raise ValueError("PAC hash differs from previously verified stock PAC")
    if sha256(args.modified) != PINNED_MODIFIED:
        raise ValueError("Modified image differs from exact delivered debloat artifact")
    vbmeta = pac_descriptors(args.pac, args.work)
    # Extract stock sparse directly from verified PAC.
    with args.pac.open("rb") as f:
        head = struct.unpack(PAC_HEADER, f.read(struct.calcsize(PAC_HEADER)))
        f.seek(head[6])
        for _ in range(head[5]):
            r = struct.unpack(PAC_ENTRY, f.read(struct.calcsize(PAC_ENTRY)))
            if decoded(r[1]) == "Super":
                offset, length = (r[5] << 32) | r[9], (r[4] << 32) | r[6]
                break
        else:
            raise ValueError("Missing original super.img in PAC")
        stock_sparse = args.work / "original-super.img"
        f.seek(offset)
        with stock_sparse.open("wb") as out:
            remaining = length
            while remaining:
                chunk = f.read(min(remaining, 4 * 1024 * 1024))
                if not chunk:
                    raise ValueError("Short original PAC super payload")
                out.write(chunk)
                remaining -= len(chunk)
    if sha256(stock_sparse) != "4dbf410905fe93e4e04563c5cc3e97864541af1f7dd2c68ef107830c8236afe1":
        raise ValueError("PAC super payload changed")
    extracted = {}
    for name, sparse in (("stock", stock_sparse), ("modified", args.modified)):
        raw = args.work / (name + "-raw.img")
        subprocess.run(["simg2img", str(sparse), str(raw)], check=True)
        directory = args.work / (name + "-partitions")
        directory.mkdir()
        subprocess.run(["lpunpack", str(raw), str(directory)], check=True)
        extracted[name] = directory
        raw.unlink()
    results = []
    for partition, vbmeta_name in PARTITIONS.items():
        text, descriptors = avb_info(args.avbtool, vbmeta[vbmeta_name])
        (args.report / (partition + "-avb-descriptor.txt")).write_text(text)
        matches = [d for d in descriptors if d.get("Partition Name") == partition]
        if len(matches) != 1:
            raise ValueError("Expected exactly one hashtree descriptor for " + partition)
        descriptor = matches[0]
        expected = descriptor["Root Digest"].lower()
        result = {"partition": partition, "expected_signed_root_digest": expected,
                  "verity_algorithm": descriptor["Hash Algorithm"],
                  "verity_image_bytes": descriptor["Image Size"],
                  "checks": {}}
        for label in ("stock", "modified"):
            path = extracted[label] / (partition + "_a.img")
            calculated = merkle_root(path, descriptor)
            result["checks"][label] = {"computed_root_digest": calculated,
                                       "matches_signed_original": calculated == expected,
                                       "partition_sha256": sha256(path)}
        results.append(result)
        print(json.dumps(result, indent=2), flush=True)
    summary = {"method": "SHA1/SHA256 salted dm-verity Merkle root recomputation from original signed PAC hashtree descriptors",
               "source_pac_sha256": PINNED_PAC,
               "modified_super_sha256": PINNED_MODIFIED,
               "results": results,
               "all_stock_match": all(r["checks"]["stock"]["matches_signed_original"] for r in results),
               "all_modified_match": all(r["checks"]["modified"]["matches_signed_original"] for r in results),
               "device_write_status": "unknown: read-only offline inspection only"}
    (args.report / "dm-verity-comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.report / "READ_ME.txt").write_text(
        "READ-ONLY ORIGINAL STOCK VS DELIVERED DEBLOATED AVB HASHTREE AUDIT\n\n"+
        json.dumps(summary, indent=2)+"\n\nNo device flashing or AVB changes.\n")
    if not summary["all_stock_match"]:
        raise ValueError("Stock partition failed its own signed AVB descriptor: Merkle algorithm/layout must be reviewed")
    print("STOCK VALIDATION PASSED; MODIFIED MATCH = ", summary["all_modified_match"], flush=True)

if __name__ == "__main__":
    main()
