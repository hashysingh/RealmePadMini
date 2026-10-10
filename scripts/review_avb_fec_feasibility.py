#!/usr/bin/env python3
"""Read-only AVB/FEC geometry feasibility review of the *existing* debloated super.

This intentionally does not construct, sign, or advertise a flashable image.
"""
import argparse, hashlib, json, math, subprocess
from pathlib import Path
from audit_debloated_avb_hashtree import merkle_root, sha256

SPECS={
  "system_a":{"data_bytes":1964515328,"tree_offset":1964515328,"tree_bytes":15466496,
              "fec_offset":1979981824,"fec_bytes":16117760,
              "stock_digest":"7f93c504b53550a2bf806107bd01169b19700589"},
  "product_a":{"data_bytes":1780375552,"tree_offset":1780375552,"tree_bytes":14024704,
               "fec_offset":1794400256,"fec_bytes":14188544,
               "stock_digest":"ebb5a3f21a7d6a85156389b5255027465048ef54"}
}
# system geometry above needs to be independently checked against actual AVB.
# Do not accept an unchecked embedded number as proof of feasibility.
SALT="0e085d174808fe2ee4104f60d59a331b1a5a45c471975837c01ff602f0932096"

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
    for name, spec in SPECS.items():
        file=out/(name+".img")
        size=file.stat().st_size
        fs=read_ext_metadata(file)
        # Never assume the static stock hashtree geometry is accurate without comparing.
        expected_tree_start=spec["tree_offset"]
        tree_end=expected_tree_start+spec["tree_bytes"]
        fec_end=spec["fec_offset"]+spec["fec_bytes"]
        d={"partition":name,"partition_bytes":size,
           "stock_avb_reference_geometry_UNCONFIRMED":spec,
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
        "The stock AVB geometry must be confirmed from authentic vbmeta descriptors before layout planning.",
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
        md.append(f'| {r["partition"]} | {r["partition_bytes"]} | {r["filesystem"]["filesystem_bytes"]} | {r["stock_avb_reference_geometry_UNCONFIRMED"]["data_bytes"]} | {r["stock_layout_geometry_fits_partition"]} |')
    md+=["","*Some embedded geometry fields still require confirmation against original vbmeta; do not interpret as an AVB-valid build.",
         "","**BLOCKER:** Original OEM AVB signatures cannot be reproduced using its public keys. Unlocked does not establish trusted acceptance.",
         "","No Google PAC download, no signing, no verification bypass and no firmware flashing."]
    (a.report/"REPORT.md").write_text("\n".join(md)+"\n")
if __name__=="__main__":main()
