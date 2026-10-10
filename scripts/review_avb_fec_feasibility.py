#!/usr/bin/env python3
"""Read-only AVB/FEC geometry feasibility review of the *existing* debloated super.

This intentionally does not construct, sign, or advertise a flashable image.
"""
import argparse, hashlib, json, math, subprocess
from pathlib import Path
from audit_debloated_avb_hashtree import merkle_root, sha256

def stock_specs(descriptor_dir):
    import re
    refs={}
    for part in ("system_a","product_a"):
        filename=descriptor_dir/(part[:-2]+"-avb-descriptor.txt")
        data=filename.read_text()
        block=re.search(r"Hashtree descriptor:(.*?)(?:\\n\\s*(?:Hashtree|Hash|Chain Partition|Prop) descriptor:|\\Z)",data,re.S)
        if not block:raise ValueError("Signed stock hashtree not found: "+str(filename))
        body=block.group(1)
        vals=dict(re.findall(r"^\\s*(Image Size|Tree Offset|Tree Size|FEC offset|FEC size|Partition Name):\\s*(.*?)\\s*$",body,re.M))
        if vals.get("Partition Name")!=part[:-2]:raise ValueError("Wrong descriptor partition "+part)
        needed={"Image Size","Tree Offset","Tree Size","FEC offset","FEC size"}
        if not needed<=vals.keys():raise ValueError("Stock descriptor missing geometry "+part)
        refs[part]={"data_bytes":int(vals["Image Size"].split()[0]),
                    "tree_offset":int(vals["Tree Offset"].split()[0]),
                    "tree_bytes":int(vals["Tree Size"].split()[0]),
                    "fec_offset":int(vals["FEC offset"].split()[0]),
                    "fec_bytes":int(vals["FEC size"].split()[0])}
    return refs

def read_ext_metadata(path):
    with path.open("rb") as f:
        f.seek(1024)
        sb=f.read(1024)
    if sb[56:58]!=b"\x53\xef":
        raise ValueError("Not ext4: "+str(path))
    blocks=int.from_bytes(sb[4:8],"little")
    block_log=int.from_bytes(sb[24:28],"little")
    block_size=1024<<block_log
    return {"filesystem_blocks":blocks,"filesystem_block_size":block_size,
            "filesystem_bytes":blocks*block_size,"filesystem_uses_bytes":blocks*block_size}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--stock-descriptors",type=Path,required=True)
    p.add_argument("--work",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    a=p.parse_args()
    a.work.mkdir(parents=True,exist_ok=True)
    a.report.mkdir(parents=True,exist_ok=True)
    expect="d1266658821f587a273e139841f861c7ae1557d3415dde8fc8990aa1e62d74f3"
    print("[1/5] Pin exact historical debloat-only image",flush=True)
    if sha256(a.image)!=expect:raise ValueError("Unexpected input super")
    raw=a.work/"super.raw"
    print("[2/5] Expand and unpack exact logical partitions",flush=True)
    subprocess.run(["simg2img",str(a.image),str(raw)],check=True)
    lp=subprocess.run(["lpdumps",str(raw)],capture_output=True,text=True,check=True).stdout
    (a.report/"lp-metadata.txt").write_text(lp)
    out=a.work/"partitions";out.mkdir()
    subprocess.run(["lpunpack",str(raw),str(out)],check=True)
    raw.unlink()
    print("[3/5] Inspect sizes and ext4 geometry without mutation",flush=True)
    results=[]
    for name, spec in stock_specs(a.stock_descriptors).items():
        file=out/(name+".img")
        size=file.stat().st_size
        fs=read_ext_metadata(file)
        # Never assume the static stock hashtree geometry is accurate without comparing.
        expected_tree_start=spec["tree_offset"]
        tree_end=expected_tree_start+spec["tree_bytes"]
        fec_end=spec["fec_offset"]+spec["fec_bytes"]
        d={"partition":name,"partition_bytes":size,
           "stock_avb_reference_geometry":spec,
           "stock_layout_geometry_fits_partition":fec_end<=size and tree_end<=size and spec["fec_offset"]>=tree_end,
           "filesystem":fs,
           "filesystem_extends_beyond_data_region":fs["filesystem_bytes"]>spec["data_bytes"],
           "filesystem_extends_into_tree_region":fs["filesystem_bytes"]>spec["tree_offset"],
           "remaining_bytes_after_stock_data":size-spec["data_bytes"],
           "signed_metadata": "OEM signature cannot be reproduced using public verification key"}
        print(name, json.dumps(d,indent=2),flush=True)
        results.append(d)
    print("[4/5] Record previously validated AVB mismatch and trust-chain limitations",flush=True)
    conclusion={
      "goal":"Determine whether current debugfs-edited ext4 images can be verified as-is",
      "source_sha256":expect,"stock_avb_references":"Run 38021089885 independently matched stock hashtrees",
      "existing_debloat_mismatch":"Run 38021089885 confirmed both modified partitions mismatch signed stock digests",
      "partitions":results,
      "open_questions":[
        "Root reference reports are from stock PAC and contain the stock AVB descriptor geometry.",
        "Whether modified ext4 filesystem metadata overlaps reserved hashtree/FEC regions.",
        "How AVB chain-of-trust authentication would accept modified vbmeta signatures.",
        "Which on-device policies apply to unlocked bootloader (not inferred from orange state)."
      ],
      "output_image_created":False,"flash_safe":False,"modifications_performed":False
    }
    print("[5/5] Write review artifacts",flush=True)
    (a.report/"feasibility.json").write_text(json.dumps(conclusion,indent=2)+"\n")
    md=["# AVB/FEC feasibility review","", "**Read-only, no flashable output.**",
        "","Known from prior successful independent audit: stock image verifies against OEM vbmeta, modified image does not.",
        "","| Image | Logical partition size | ext4 declared bytes | Stock AVB data bytes | Tree/FEC geometry fits* |",
        "|---|---:|---:|---:|---|"]
    for r in results:
        md.append(f'| {r["partition"]} | {r["partition_bytes"]} | {r["filesystem"]["filesystem_bytes"]} | {r["stock_avb_reference_geometry"]["data_bytes"]} | {r["stock_layout_geometry_fits_partition"]} |')
    md+=["","*Geometry is parsed from the previously extracted original PAC vbmeta descriptors; do not interpret as an AVB-valid build.",
         "","**BLOCKER:** Original OEM AVB signatures cannot be reproduced using its public keys. Unlocked does not establish trusted acceptance.",
         "","No Google PAC download, no signing, no verification bypass and no firmware flashing."]
    (a.report/"REPORT.md").write_text("\n".join(md)+"\n")
if __name__=="__main__":main()
