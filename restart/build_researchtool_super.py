#!/usr/bin/env python3
"""Build a Researchtool replacement *Super* payload, not a PAC or flashable package.

Only the 73 checked APKs are removed; verified hashtrees/FEC are written to
system_a/product_a. All other bytes and LP metadata must remain byte-identical.
OEM vbmeta is NOT modified; the resulting Super is NOT boot-verified.
"""
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_stock_pac_removal import EXPECTED_PAC,EXPECTED_SUPER,REQUIRED_AVB,sha,extract_pac,list_targets,check
from test_avb_tree_rebuild import validate

CHUNK=4*1024*1024
EXPECTED_RAW_BYTES=7864320000
TARGETS=("product_a","system_a")

def run(*args):
    print("$ "+" ".join(map(str,args)),flush=True)
    subprocess.run([str(x) for x in args],check=True)

def geometry(raw):
    p=subprocess.run(["lpdumps",str(raw)],text=True,capture_output=True,check=True)
    result={}
    current=None
    for line in p.stdout.splitlines():
        match=re.match(r"^\s*Name:\s*([A-Za-z0-9_]+)\s*$",line)
        if match:
            current=match.group(1)
            result.setdefault(current,[])
            continue
        match=re.search(r"(\d+)\s*\.\.\s*(\d+)\s+linear\s+super\s+(\d+)\b",line)
        if match and current:
            lo,hi,offset=map(int,match.groups())
            if hi<lo:raise ValueError("Bad linear extent")
            result[current].append((offset*512,(hi-lo+1)*512))
    for part in TARGETS:
        if len(result.get(part,[]))!=1:
            raise ValueError("Target must have exactly one contiguous LP extent: "+part+
                             "; found "+str(result.get(part)))
    ranges=sorted([result[p][0] for p in TARGETS])
    if ranges[0][0]<0 or ranges[0][0]+ranges[0][1]>ranges[1][0] or ranges[1][0]+ranges[1][1]>raw.stat().st_size:
        raise ValueError("Overlapping/out of bounds extents")
    return p.stdout,result

def protected_sha(raw,excluded):
    hasher=hashlib.sha256()
    cursor=0
    size=raw.stat().st_size
    with raw.open("rb") as src:
        for start,length in sorted(excluded)+[(size,0)]:
            if start<cursor or start>size or start+length>size:raise ValueError("Invalid ranges")
            src.seek(cursor)
            left=start-cursor
            while left:
                block=src.read(min(CHUNK,left))
                if not block:raise EOFError(raw)
                hasher.update(block);left-=len(block)
            cursor=start+length
    return hasher.hexdigest()

def compare_extent(raw,partfile,offset,size):
    hasher=hashlib.sha256()
    with raw.open("rb") as src:
        src.seek(offset)
        remaining=size
        while remaining:
            buf=src.read(min(CHUNK,remaining))
            if not buf:raise EOFError(raw)
            hasher.update(buf)
            remaining-=len(buf)
    if hasher.hexdigest()!=sha(partfile):raise ValueError("Written LP extent differs: "+partfile.name)

def main():
    a=argparse.ArgumentParser()
    for name in ("pac","targets","avbtool","work","output"):
        a.add_argument("--"+name,required=True,type=Path)
    x=a.parse_args()
    if x.output.exists():raise ValueError("Refuse to overwrite output")
    target=list_targets(x.targets)
    if sha(x.pac)!=EXPECTED_PAC:raise ValueError("Wrong original PAC digest")
    x.work.mkdir(parents=True,exist_ok=True)
    pac_dir=x.work/"pac"
    metadata=extract_pac(x.pac,pac_dir)
    if set(metadata)!={"Super"}|REQUIRED_AVB:raise ValueError("Missing stock entries")
    raw=x.work/"super-raw.img"
    run("simg2img",pac_dir/"super-stock-sparse.img",raw)
    if raw.stat().st_size!=EXPECTED_RAW_BYTES:raise ValueError("Unexpected raw super size")
    original_dump,parts=geometry(raw)
    extents=[parts[p][0] for p in TARGETS]
    immutable_before=protected_sha(raw,extents)
    images=x.work/"parts"
    images.mkdir(exist_ok=True)
    results={}
    for part in TARGETS:
        run("lpunpack","-p",part,raw,images)
        img=images/(part+".img")
        start,length=parts[part][0]
        if img.stat().st_size!=length:raise ValueError("Original LP size mismatch "+part)
        previous=sha(img)
        checked=check(img,target[part],writes=True)
        fsck=subprocess.run(["e2fsck","-fn",str(img)],text=True,capture_output=True)
        if fsck.returncode:raise ValueError("Edited ext4 fsck failed "+part+" "+fsck.stdout[-1400:])
        if sha(img)==previous:raise ValueError("Image not changed "+part)
        results[part]={"deleted":len(checked),"ext4_fsck":"PASS","bytes":length}
    avb=validate(x.avbtool,pac_dir,images)
    for part in TARGETS:
        start,length=parts[part][0]
        img=images/(part+".img")
        if img.stat().st_size!=length:raise ValueError("Modified LP size changed")
        with raw.open("r+b") as dst,img.open("rb") as src:
            dst.seek(start)
            left=length
            while left:
                block=src.read(min(CHUNK,left))
                if not block:raise EOFError(img)
                dst.write(block);left-=len(block)
        compare_extent(raw,img,start,length)
        results[part]["sha256"]=sha(img)
        print("REINJECT "+part+" into ORIGINAL untouched LP extent",flush=True)
    if raw.stat().st_size!=EXPECTED_RAW_BYTES:raise ValueError("raw size changed")
    immutable_after=protected_sha(raw,extents)
    if immutable_after!=immutable_before:raise ValueError("Non-target partitions or LP metadata CHANGED")
    updated_dump,updated_parts=geometry(raw)
    if updated_dump!=original_dump or updated_parts!=parts:raise ValueError("LP geometry changed")
    x.output.parent.mkdir(exist_ok=True,parents=True)
    run("img2simg",raw,x.output)
    with x.output.open("rb") as fh:
        if fh.read(4)!=bytes.fromhex("3aff26ed"):raise ValueError("Not sparse")
    # Independently convert the final sparse file and re-check layout and targets.
    roundtrip=x.work/"super-roundtrip.img"
    run("simg2img",x.output,roundtrip)
    if roundtrip.stat().st_size!=EXPECTED_RAW_BYTES:raise ValueError("Sparse roundtrip size mismatch")
    if sha(raw)!=sha(roundtrip):raise ValueError("Sparse roundtrip content mismatch")
    _,rechecked=geometry(roundtrip)
    if rechecked!=parts:raise ValueError("Sparse roundtrip LP geometry mismatch")
    for part in TARGETS:
        verify_dir=x.work/("verify-"+part)
        verify_dir.mkdir(parents=True,exist_ok=True)
        run("lpunpack","-p",part,roundtrip,verify_dir)
        verified=verify_dir/(part+".img")
        if not verified.is_file() or sha(verified)!=sha(images/(part+".img")):
            raise ValueError("Sparse roundtrip unpacked "+part+" differs from validated modified partition")
        from test_stock_pac_removal import stat_exists
        for apk in target[part]:
            if stat_exists(verified,apk):raise ValueError("Roundtrip restored unwanted APK: "+apk)
        print("ROUNDTRIP PASS "+part+" APKs absent and partition SHA256 identical",flush=True)
    summary={"status":"RESEARCHTOOL SUPER COMPONENT BUILD PASSED (NOT BOOT VERIFIED)",
             "source_pac_sha256":EXPECTED_PAC,"source_sparse_super_sha256":EXPECTED_SUPER,
             "changed_partitions":results,"avb_rebuilt":avb,
             "non_target_regions_byte_identical":True,"lp_metadata_unchanged":True,
             "raw_super_bytes":EXPECTED_RAW_BYTES,
             "output_sparse_super_sha256":sha(x.output),
             "output_sparse_super_bytes":x.output.stat().st_size,
             "avb_oem_signatures":"NOT UPDATED; ORIGINAL VBMETA IS INCOMPATIBLE",
             "complete_avb_chain_verified":False,"device_bootability_verified":False,
             "pac_repacked":False}
    print(json.dumps(summary,indent=2),flush=True)
    print("WARNING: SUPER COMPONENT IS NOT VERIFIED BOOTABLE. DO NOT ASSUME STOCK VBMETA MATCHES.",flush=True)

if __name__=="__main__":main()
