#!/usr/bin/env python3
"""OFFLINE ONLY: rebuild development AVB hashtrees/FEC for known RMP2106 debloat.

No PAC repacking, no OEM keys, no flashing, no device trust assertions.
"""
import argparse,hashlib,json,re,shutil,subprocess
from pathlib import Path

PINNED="d1266658821f587a273e139841f861c7ae1557d3415dde8fc8990aa1e62d74f3"
def execute(*args):
    print("$ "+" ".join(map(str,args)),flush=True)
    return subprocess.run(list(map(str,args)),check=True,text=True,capture_output=True)
def digest(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b""):h.update(chunk)
    return h.hexdigest()
def properties(p):
    raw=p.read_text()
    blocks=re.findall(r"Hashtree descriptor:\s+(.*?)(?=\n\s*(?:Hashtree|Hash|Chain Partition|Kernel Cmdline|Prop) descriptor:|\Z)",raw,re.S)
    if len(blocks)!=1:raise ValueError("Exactly one stock hashtree descriptor required: "+str(p))
    return dict(re.findall(r"^\s*(Image Size|Tree Offset|Tree Size|FEC offset|FEC size|Hash Algorithm|Data Block Size|Hash Block Size|FEC num roots|Root Digest|Partition Name|Salt):\s*(.*?)\s*$",blocks[0],re.M))
def integer(x):return int(x.split()[0])
def main():
    ap=argparse.ArgumentParser()
    for name in ("image","stock_reports","avbtool","work","report"):
        ap.add_argument("--"+name.replace("_","-"),required=True,type=Path)
    a=ap.parse_args()
    a.work.mkdir(parents=True,exist_ok=True)
    a.report.mkdir(parents=True,exist_ok=True)
    outcome={"mode":"DEVELOPMENT-KEY OFFLINE TEST; NOT INSTALLABLE","image_generated_for_device":False,
             "original_pac_repacked":False,"oem_key_available":False,
             "device_acceptance_of_custom_signatures":"NOT PROVEN","parts":{}}
    try:
        print("[1/6] Verify exact previously reviewed debloated image",flush=True)
        if digest(a.image)!=PINNED:raise ValueError("Input super SHA256 differs from pinned artifact")
        print("[2/6] Check all 5 original stock AVB images/reports",flush=True)
        names=["vbmeta","vbmeta_system","vbmeta_product","vbmeta_system_ext","vbmeta_vendor"]
        for n in names:
            blob=a.stock_reports/(n+".img")
            report=a.stock_reports/(n+"-avbtool.txt")
            if not blob.exists() or blob.open("rb").read(4)!=b"AVB0" or not report.is_file():
                raise ValueError("Required original stock vbmeta and report missing: "+n)
            print("  stock AVB: "+n+" "+digest(blob),flush=True)
        for part in ("system","product"):
            desc=properties(a.stock_reports/("vbmeta_"+part+"-avbtool.txt"))
            if desc.get("Partition Name")!=part or desc.get("Hash Algorithm")!="sha1":
                raise ValueError("Stock AVB descriptor mismatch: "+part)
        print("[3/6] Prepare development-only RSA4096 signing key (ephemeral)",flush=True)
        key=a.work/"DEV_ONLY_PRIVATE_KEY.pem"
        execute("openssl","genrsa","-out",key,"4096")
        print("[4/6] Expand super and extract target logical partitions",flush=True)
        raw=a.work/"super.raw"
        execute("simg2img",a.image,raw)
        unpack=a.work/"unpack";unpack.mkdir(exist_ok=True)
        execute("lpunpack",raw,unpack)
        raw.unlink()
        print("[5/6] Rebuild partition verity trees and FEC, sign temporary standalone vbmeta",flush=True)
        print("NOTE: FEC regeneration deferred until compatible Android fec host utility is available",flush=True)
        outcome["fec_regenerated"]=False
        for part in ("system","product"):
            stock=properties(a.stock_reports/("vbmeta_"+part+"-avbtool.txt"))
            orig=unpack/(part+"_a.img")
            logical=orig.stat().st_size
            image_bytes=integer(stock["Image Size"])
            if image_bytes>=logical or integer(stock["Tree Offset"])!=image_bytes:
                raise ValueError("Unexpected stock AVB partition geometry: "+part)
            if integer(stock["Data Block Size"])!=4096 or integer(stock["Hash Block Size"])!=4096:
                raise ValueError("Unexpected stock block size "+part)
            test=a.work/(part+"-dev.img")
            with orig.open("rb") as source,test.open("wb") as out:
                left=image_bytes
                while left:
                    chunk=source.read(min(left,4*1024*1024))
                    if not chunk:raise EOFError(part)
                    out.write(chunk);left-=len(chunk)
            vb=a.work/(part+"-development-vbmeta.img")
            execute("python3",a.avbtool,"add_hashtree_footer",
                    "--image",test,"--partition_name",part,"--partition_size",logical,
                    "--algorithm","SHA256_RSA4096","--key",key,
                    "--hash_algorithm","sha1","--salt",stock["Salt"],
                    "--block_size","4096","--fec_num_roots","2",
                    "--output_vbmeta_image",vb,"--do_not_append_vbmeta_image",
                    "--do_not_generate_fec")
            if test.stat().st_size>logical:
                raise ValueError("Regenerated tree+FEC exceeds logical partition: "+part)
            devinfo=execute("python3",a.avbtool,"info_image","--image",vb).stdout
            (a.report/(part+"-dev-avbtool.txt")).write_text(devinfo)
            devdesc=properties(a.report/(part+"-dev-avbtool.txt"))
            if devdesc.get("Partition Name")!=part or devdesc.get("Hash Algorithm")!="sha1":
                raise ValueError("Generated descriptor mismatch: "+part)
            if integer(devdesc["Image Size"])!=image_bytes:
                raise ValueError("AVB protected data bytes changed: "+part)
            outcome["parts"][part]={
                "dev_partition_size":test.stat().st_size,
                "logical_partition_size":logical,
                "regenerated_vbmeta_sha256":digest(vb),
                "regenerated_root_digest":devdesc.get("Root Digest"),
                "stock_root_digest":stock["Root Digest"],
                "root_changed":devdesc.get("Root Digest")!=stock["Root Digest"],
                "recomputed_fec_size":devdesc.get("FEC size"),
                "fec_rebuild_completed":False,
                "within_partition_size":test.stat().st_size<=logical}
            print("  completed "+part+": "+json.dumps(outcome["parts"][part]),flush=True)
        print("[6/6] Write report; delete ephemeral key and temporary images",flush=True)
        outcome["offline_generation_finished"]=True
    except Exception as exc:
        outcome["error"]=str(exc)
        raise
    finally:
        (a.report/"development-avb-results.json").write_text(json.dumps(outcome,indent=2)+"\n")
        note=["# RMP2106 offline development AVB test","",
              "**Not flashable. NOT an installable PAC.**","",
              "The previously debloated super image is the input (original PAC is not redownloaded).",
              "**FEC regeneration is NOT done; do not use the output image as firmware.**",
              "All five previously extracted original AVB binaries must be present.",
              "Temporary development signing keys and image files are NOT uploaded.",
              "An offline development signature is not an OEM signature.",
              "Whether MRST and the device accept a modified PAC/custom key is NOT ESTABLISHED.",
              "","## Results","", "```json",json.dumps(outcome,indent=2),"```"]
        (a.report/"REPORT.md").write_text("\n".join(note)+"\n")
        if (a.work/"DEV_ONLY_PRIVATE_KEY.pem").exists():
            (a.work/"DEV_ONLY_PRIVATE_KEY.pem").unlink()
if __name__=="__main__":main()
