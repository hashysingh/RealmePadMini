#!/usr/bin/env python3
"""Single-run, read-only audit against previously verified signed stock references.

Reference stock root digests came from successful GitHub Actions run 38021089885.
This tool checks artifacts only; it does not confirm device flash persistence.
"""
import argparse, hashlib, json, subprocess, re, zipfile
from pathlib import Path
from audit_debloated_avb_hashtree import merkle_root, sha256

REF={
 "system":{"Root Digest":"7f93c504b53550a2bf806107bd01169b19700589","Image Size":"1964515328 bytes"},
 "product":{"Root Digest":"ebb5a3f21a7d6a85156389b5255027465048ef54","Image Size":"1780375552 bytes"}
}
for d in REF.values():
    d.update({"Hash Algorithm":"sha1","Salt":"0e085d174808fe2ee4104f60d59a331b1a5a45c471975837c01ff602f0932096","Data Block Size":"4096 bytes","Hash Block Size":"4096 bytes"})
EXPECTED_SUPER="d1266658821f587a273e139841f861c7ae1557d3415dde8fc8990aa1e62d74f3"
EXPECTED_STOCK_BOOT_ANIM="e5bde8240542c1f8b0249772d4099f45a37db33dc78fba2845d023d3c2014472"
PARTS=("system_a","product_a","system_ext_a","vendor_a","system_b","product_b","system_ext_b","vendor_b")
TARGETS={"product_a":("/app/YouTube","/app/Maps","/app/Chrome"),"system_a":("/system/preloadapp/YTMusic","/system/preloadapp/YouTubeKids")}
def cmd(*a):return subprocess.run(a,check=True,text=True,capture_output=True).stdout
def fs_stat(image,path):
    p=subprocess.run(["debugfs","-R","stat "+path,str(image)],capture_output=True,text=True)
    if p.returncode or ("Inode:" not in p.stdout and not re.search(r"not found|No such file",p.stderr,re.I)):
        raise RuntimeError("Could not query "+str(image)+":"+path+" "+p.stderr[-500:])
    return "Inode:" in p.stdout
def boot_animation_info(image):
    path="/system/media/bootanimation.zip"
    if not fs_stat(image,path):return {"path":path,"present":False}
    p=subprocess.run(["debugfs","-R","dump -p "+path+" /dev/stdout",str(image)],capture_output=True)
    # stdout dump is not universally supported; use a temporary file instead.
    return {"path":path,"present":True}
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--image",type=Path,required=True)
    a.add_argument("--work",type=Path,required=True)
    a.add_argument("--report",type=Path,required=True)
    args=a.parse_args()
    args.work.mkdir(parents=True,exist_ok=True)
    args.report.mkdir(parents=True,exist_ok=True)
    print("[1/6] Confirm exact historical image SHA-256",flush=True)
    actual=sha256(args.image)
    if actual!=EXPECTED_SUPER:raise ValueError("Image hash mismatch: "+actual)
    print("[2/6] Unpack sparse super once",flush=True)
    raw=args.work/"super-raw.img"
    subprocess.run(["simg2img",str(args.image),str(raw)],check=True)
    meta=cmd("lpdumps",str(raw))
    (args.report/"logical-partition-metadata.txt").write_text(meta)
    extracted=args.work/"partitions"
    extracted.mkdir()
    subprocess.run(["lpunpack",str(raw),str(extracted)],check=True)
    raw.unlink()
    print("[3/6] Audit LP partitions, filesystem read-only, and removed app directories",flush=True)
    records=[]; notes=[]
    for partition in PARTS:
        path=extracted/(partition+".img")
        if not path.exists():raise ValueError("Missing logical partition "+partition)
        record={"name":partition,"bytes":path.stat().st_size,"sha256":sha256(path)}
        if path.stat().st_size:
            result=subprocess.run(["e2fsck","-fn",str(path)],capture_output=True,text=True)
            record["e2fsck_exit"]=result.returncode
            if result.returncode not in (0,):notes.append(partition+" e2fsck exit "+str(result.returncode))
            if partition in TARGETS:
                record["removed_app_paths"]={t:not fs_stat(path,t) for t in TARGETS[partition]}
                if not all(record["removed_app_paths"].values()):notes.append(partition+" targeted path remains")
        records.append(record)
        print("  "+partition+": "+str(path.stat().st_size)+" bytes",flush=True)
    print("[4/6] Compare system/product data to stock signed AVB hashtrees",flush=True)
    verity=[]
    for part,d in REF.items():
        image=extracted/(part+"_a.img")
        result=merkle_root(image,d)
        verity.append({"partition":part,"signed_stock_root":d["Root Digest"],"modified_root":result,"matches_stock_signed_root":result==d["Root Digest"]})
    print("[5/6] Inspect boot animation file extracted from modified system",flush=True)
    system=extracted/"system_a.img"
    boot_target=args.work/"bootanimation.zip"
    dump=subprocess.run(["debugfs","-R",f"dump -p /system/media/bootanimation.zip {boot_target}",str(system)],capture_output=True,text=True)
    animation={"debugfs_exit":dump.returncode,"debugfs_stdout":dump.stdout[-400:],"debugfs_stderr":dump.stderr[-400:]}
    if boot_target.exists() and boot_target.stat().st_size:
        animation.update({"sha256":sha256(boot_target),"matches_device_stock_sha256":sha256(boot_target)==EXPECTED_STOCK_BOOT_ANIM,"zip_valid":zipfile.is_zipfile(boot_target)})
    else:
        notes.append("Unable to extract boot animation (the image may use a different location)")
    print("[6/6] Prepare unified final findings",flush=True)
    report={
        "source":"Existing exact delivered image, original stock baselines already independently confirmed in run 38021089885",
        "google_downloads":0,
        "verified_super_sha256":actual,
        "parts":records,
        "signed_stock_verity_comparison":verity,
        "boot_animation":animation,
        "warnings":notes,
        "flash_persistence":"NOT VERIFIED - requires separate read-only on-device evidence",
        "signing_or_avb_fix":"NOT PERFORMED - stock OEM private signing keys are unavailable",
        "image_safe_to_flash":"NOT ESTABLISHED"
    }
    (args.report/"one-shot-diagnostic.json").write_text(json.dumps(report,indent=2)+"\n")
    lines=["# One-shot Realme Pad Mini super image inspection","","No PAC download was needed; reused cryptographic stock AVB reference values independently confirmed in run 38021089885.","","| Partition | Matches stock signed hashtree |","|---|---|"]
    for v in verity:lines.append("| "+v["partition"]+" | "+("YES" if v["matches_stock_signed_root"] else "NO")+" |")
    lines.extend(["","Boot animation: "+json.dumps(animation),"","Warnings: "+json.dumps(notes),"","This cannot show which super bytes the tablet actually mounted. The OEM AVB private keys are not available. No flashing or security bypass performed."])
    (args.report/"REPORT.md").write_text("\n".join(lines)+"\n")
    print("\n".join(lines),flush=True)

if __name__=="__main__":
    main()
