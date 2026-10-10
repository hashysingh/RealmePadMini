#!/usr/bin/env python3
"""Offline, fail-closed inspection of all five STOCK AVB images.

No signature changes, disable flags, PAC edits, or deployable vbmeta output.
Establish exactly which branches protect changed system/product partitions.
"""
import argparse,json,re,struct,subprocess,hashlib
from pathlib import Path

NAMES=("vbmeta","vbmeta_system","vbmeta_product","vbmeta_system_ext","vbmeta_vendor")
CHILDREN={"vbmeta_system":"system","vbmeta_product":"product",
          "vbmeta_system_ext":"system_ext","vbmeta_vendor":"vendor"}
HEADER_LABELS=("Algorithm","Flags","Rollback Index","Rollback Index Location")
DESCRIPTOR=re.compile(r"(?m)^\s*(Hashtree|Hash|Chain Partition|Kernel Cmdline|Prop) descriptor:\s*$")
FIELD=re.compile(r"(?m)^\s*([^:\n]+?):\s*(.*?)\s*$")

def parse(report):
    lines=list(DESCRIPTOR.finditer(report))
    first=report[:lines[0].start()] if lines else report
    top=dict(FIELD.findall(first))
    descriptors=[]
    for i,m in enumerate(lines):
        body=report[m.end():lines[i+1].start() if i+1<len(lines) else len(report)]
        descriptors.append({"type":m.group(1),"fields":dict(FIELD.findall(body))})
    return top,descriptors

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--stock",required=True,type=Path)
    ap.add_argument("--avbtool",required=True,type=Path)
    a=ap.parse_args()
    inventory={}
    for name in NAMES:
        path=a.stock/(name+".img")
        if not path.is_file():raise ValueError("Missing signed PAC entry "+name)
        with path.open("rb") as f:head=f.read(256)
        if len(head)<256 or head[:4]!=b"AVB0" or struct.unpack_from(">I",head,28)[0]!=2:
            raise ValueError("Invalid RSA4096 AVB header "+name)
        call=subprocess.run(["python3",str(a.avbtool),"info_image","--image",str(path)],
                            capture_output=True,text=True)
        if call.returncode:raise ValueError("AVB inspection failed "+name+" "+call.stderr[-400:])
        top,desc=parse(call.stdout)
        if not desc:raise ValueError("No stock AVB descriptors "+name)
        if top.get("Algorithm")!="SHA256_RSA4096":
            raise ValueError("Unsupported stock AVB algorithm "+name)
        if top.get("Flags") not in ("0","0x0"):
            raise ValueError("Unexpected original AVB verification flags "+name)
        if not top.get("Rollback Index"):
            raise ValueError("Missing rollback index "+name)
        inventory[name]={"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),
                         "algorithm":top["Algorithm"],"flags":top["Flags"],
                         "rollback_index":top["Rollback Index"],
                         "rollback_index_location":top.get("Rollback Index Location"),
                         "descriptors":desc}
        print("STOCK AVB "+name+" descriptors="+str(len(desc))+" flags="+top["Flags"],flush=True)
    root=inventory["vbmeta"]["descriptors"]
    for child,partition in CHILDREN.items():
        links=[x for x in root if x["type"]=="Chain Partition" and
               x["fields"].get("Partition Name")==child]
        if len(links)!=1:raise ValueError("Root AVB chain does not link exactly once to "+child)
        if not links[0]["fields"].get("Public key (sha1)") or not links[0]["fields"].get("Rollback Index Location"):
            raise ValueError("Stock chain lacks key or rollback location "+child)
        trees=[x for x in inventory[child]["descriptors"]
               if x["type"]=="Hashtree" and x["fields"].get("Partition Name")==partition]
        if len(trees)!=1:raise ValueError("Stock AVB hashtree missing for "+partition)
        if trees[0]["fields"].get("Hash Algorithm")!="sha1":
            raise ValueError("Unexpected AVB hash algorithm "+partition)
    result={"status":"STOCK FIVE-FILE AVB CHAIN STRUCTURE VALIDATED",
            "stock":inventory,
            "changed_partitions":["system_a","product_a"],
            "affected_child_vbmeta":["vbmeta_system","vbmeta_product"],
            "root_vbmeta_chains_to_children":list(CHILDREN),
            "original_oem_signatures_valid_for_modified_partitions":False,
            "replacements_created":False,"bootloader_acceptance":"NOT TESTED",
            "researchtool_pac_repack":"NOT DONE"}
    print("AVB CHAIN AUDIT PASSED (STRUCTURE ONLY; OEM SIGNATURES INCOMPATIBLE WITH MODIFIED PARTITIONS)",flush=True)
    print("AVB CHAIN SUMMARY "+json.dumps({k:v for k,v in result.items() if k!="stock"},sort_keys=True),flush=True)

if __name__=="__main__":main()
