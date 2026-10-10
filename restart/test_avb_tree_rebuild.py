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


def regenerate_fec_with_veritysetup(image,descriptor,expected_root,expected_tree_digest,part,work):
    """Check FEC generation using cryptsetup veritysetup on disposable images."""
    work.mkdir(exist_ok=True,parents=True)
    tree_offset=int(descriptor["Tree Offset"].split()[0])
    tree_size=int(descriptor["Tree Size"].split()[0])
    fec_offset=int(descriptor["FEC offset"].split()[0])
    fec_size=int(descriptor["FEC size"].split()[0])
    data_blocks=int(descriptor["Image Size"].split()[0])//4096
    if tree_offset+tree_size!=fec_offset:
        raise ValueError("Unexpected gap before FEC: "+part)
    if fec_offset+fec_size>image.stat().st_size:
        raise ValueError("FEC does not fit original logical partition: "+part)
    with image.open("rb") as f:
        f.seek(tree_offset)
        prior=hashlib.sha256(f.read(tree_size)).hexdigest()
    if prior!=expected_tree_digest:
        raise ValueError("Hashtree changed before FEC: "+part)
    parity=work/(part+"-scratch-fec.bin")
    command=["veritysetup","--no-superblock","--format=1","--hash=sha1",
             "--data-block-size=4096","--hash-block-size=4096",
             "--data-blocks="+str(data_blocks),"--hash-offset="+str(tree_offset),
             "--salt="+descriptor["Salt"],"--fec-roots=2",
             "--fec-device="+str(parity),"format",str(image),str(image)]
    print("FEC START "+part+" (veritysetup, scratch image)",flush=True)
    proc=subprocess.run(command,capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError("veritysetup format failed on "+part+" exit="+str(proc.returncode)+
                           "\nstdout: "+proc.stdout[-1600:]+"\nstderr: "+proc.stderr[-1600:])
    got=re.search(r"(?mi)^\s*Root hash:\s*([0-9a-f]+)\s*$",proc.stdout)
    if not got or got.group(1).lower()!=expected_root:
        raise ValueError("Independent veritysetup root mismatch for "+part+": "+
                         str(got.group(1) if got else "missing")+" != "+expected_root)
    if not parity.is_file() or parity.stat().st_size==0:
        raise ValueError("No FEC parity data created for "+part)
    actual_size=parity.stat().st_size
    if actual_size!=fec_size:
        raise ValueError("FEC size differs from original descriptor "+part+
                         ": new="+str(actual_size)+" original="+str(fec_size))
    with image.open("rb") as f:
        f.seek(tree_offset)
        after=hashlib.sha256(f.read(tree_size)).hexdigest()
    if prior!=after:
        raise ValueError("veritysetup hashtree bytes disagree with our original layout: "+part)
    checksum=hashlib.sha256()
    with image.open("r+b") as dest,parity.open("rb") as src:
        dest.seek(fec_offset)
        remaining=actual_size
        while remaining:
            block=src.read(min(4*1024*1024,remaining))
            if not block:raise EOFError("Short FEC parity "+part)
            dest.write(block)
            checksum.update(block)
            remaining-=len(block)
    with image.open("rb") as f:
        f.seek(fec_offset)
        h=hashlib.sha256()
        left=actual_size
        while left:
            b=f.read(min(4*1024*1024,left))
            if not b:raise EOFError("FEC writeback truncated")
            h.update(b);left-=len(b)
    if h.hexdigest()!=checksum.hexdigest():raise ValueError("FEC writeback hash mismatch")
    print("FEC GENERATED "+part+" bytes="+str(actual_size)+" SHA256="+checksum.hexdigest(),flush=True)
    parity.unlink()
    return {"bytes":actual_size,"sha256":checksum.hexdigest(),
            "hash_tree_unchanged":True,"veritysetup_root_matches_modified_root":True}

def validate(avbtool, original_dir, modified_dir):
    report={}
    scratch=modified_dir.parent/"parity-temp"
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
        fec=regenerate_fec_with_veritysetup(image,d,derived,checksum,part,scratch)
        report[part]={"FEC":fec,"stock_signed_root":d["Root Digest"].lower(),"modified_root":derived,
                      "merkle_computation":"two independent implementations agree",
                      "tree_offset":expected_offset,"tree_bytes":len(rebuilt),
                      "written_tree_sha256":checksum,
                      "OEM_signature":"NOT VALID FOR MODIFIED ROOT"}
        print("AVB TREE REBUILT "+part+" "+json.dumps(report[part]),flush=True)
    print("OFFLINE MERKLE TREE AND FEC GENERATION PASSED; OEM AVB SIGNATURES REMAIN INVALID. DO NOT FLASH.",flush=True)
    return report
