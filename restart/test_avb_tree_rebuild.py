#!/usr/bin/env python3
"""Offline AVB Merkle-tree reconstruction test. No signing, FEC, or flashing.

Rebuilds salted SHA-1 hashtree blocks from the disposable edited ext4 partitions.
The original stock vbmeta descriptor is the source of truth for geometry and salt.
"""
import hashlib, json, re, subprocess
from pathlib import Path
from audit_debloated_avb_hashtree import merkle_root

def desc(avbtool, vbmeta, part):
    p=subprocess.run(["python3",str(avbtool),"info_image","--image",str(vbmeta)],
                     capture_output=True,text=True,check=True)
    sections=re.findall(r"Hashtree descriptor:\s+(.*?)(?=\n\s*(?:Hashtree|Hash|Chain Partition|Kernel Cmdline|Prop) descriptor:|\Z)",p.stdout,re.S)
    matches=[]
    for section in sections:
        obj=dict(re.findall(r"^\s*(Image Size|Tree Offset|Tree Size|FEC offset|FEC size|Hash Algorithm|Data Block Size|Hash Block Size|FEC num roots|Root Digest|Partition Name|Salt):\s*(.*?)\s*$",section,re.M))
        if obj.get("Partition Name")==part:matches.append(obj)
    if len(matches)!=1:raise ValueError("Cannot identify original "+part+" AVB hashtree")
    d=matches[0]
    if d["Hash Algorithm"]!="sha1" or any(int(d[x].split()[0])!=4096 for x in ("Data Block Size","Hash Block Size")):
        raise ValueError("Unexpected SHA1/4096 original AVB layout")
    return d

def chunks_to_level(hashes, salt):
    """AVB verity tree: SHA1 digest padded to SHA1's 32-byte slot, hash blocks 4096B."""
    bs=4096
    stride=32
    padded=[x.ljust(stride,b"\x00") for x in hashes]
    nodes=[]
    roots=[]
    for start in range(0,len(padded),bs//stride):
        blob=b"".join(padded[start:start+bs//stride]).ljust(bs,b"\x00")
        nodes.append(blob)
        roots.append(hashlib.sha1(salt+blob).digest())
    return nodes,roots

def tree(image,d):
    size=int(d["Image Size"].split()[0])
    if size%4096:raise ValueError("AVB data block alignment")
    salt=bytes.fromhex(d["Salt"])
    leaves=[]
    with image.open("rb") as f:
        for _ in range(size//4096):
            block=f.read(4096)
            if len(block)!=4096:raise EOFError(image)
            leaves.append(hashlib.sha1(salt+block).digest())
    all_levels=[]
    current=leaves
    while True:
        nodes,higher=chunks_to_level(current,salt)
        all_levels.append(nodes)
        if len(higher)==1:
            # AVB serializes the smallest level first, then subsequent levels.
            generated=b"".join(block for level in reversed(all_levels) for block in level)
            return generated,higher[0].hex()
        current=higher

def validate(avbtool, original_dir, modified_dir):
    report={}
    for part in ("product","system"):
        d=desc(avbtool,original_dir/("vbmeta_"+part+".img"),part)
        image=modified_dir/(part+"_a.img")
        root=merkle_root(image,d)
        rebuilt,derived=tree(image,d)
        expected_size=int(d["Tree Size"].split()[0])
        expected_offset=int(d["Tree Offset"].split()[0])
        fec_offset=int(d["FEC offset"].split()[0])
        image_size=int(d["Image Size"].split()[0])
        if root!=derived:raise ValueError("Independent SHA1 root algorithms disagree for "+part)
        if len(rebuilt)!=expected_size:raise ValueError("Rebuilt tree size mismatch for "+part)
        if expected_offset!=image_size or expected_offset+expected_size>fec_offset:
            raise ValueError("Tree would overlap data or original FEC region")
        if fec_offset>image.stat().st_size:raise ValueError("Original FEC offset exceeds partition")
        if derived==d["Root Digest"].lower():raise ValueError("Debloated image unexpectedly has original digest: "+part)
        # Write only to a scratch partition, never to original PAC/super. FEC still stale.
        with image.open("r+b") as f:
            f.seek(expected_offset)
            f.write(rebuilt)
            f.flush()
        reread=hashlib.sha256()
        with image.open("rb") as f:
            f.seek(expected_offset)
            left=len(rebuilt)
            while left:
                b=f.read(min(left,4*1024*1024))
                if not b:raise EOFError("Written tree truncated")
                reread.update(b)
                left-=len(b)
        checksum=hashlib.sha256(rebuilt).hexdigest()
        if reread.hexdigest()!=checksum:raise ValueError("Tree writeback SHA mismatch")
        report[part]={"stock_signed_root":d["Root Digest"].lower(),"modified_root":derived,
                      "merkle_computation":"two independent implementations agree",
                      "tree_offset":expected_offset,"tree_bytes":len(rebuilt),
                      "written_tree_sha256":checksum,"FEC":"NOT REGENERATED",
                      "OEM_signature":"NOT VALID FOR MODIFIED ROOT"}
        print("AVB TREE REBUILT "+part+" "+json.dumps(report[part]),flush=True)
    print("OFFLINE MERKLE TREE TEST PASSED; FEC AND OEM SIGNATURES REMAIN INVALID. DO NOT FLASH.",flush=True)
    return report
