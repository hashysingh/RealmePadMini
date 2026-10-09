#!/usr/bin/env python3
"""Read-only extraction of boot-animation archives from a supplied sparse super.img."""
import argparse, hashlib, json, re, subprocess, zipfile
from pathlib import Path

PARTITIONS = ("system_a","product_a","system_ext_a","vendor_a")
CANDIDATE_DIRS = (
    "/system/media", "/media", "/product/media", "/system/product/media",
    "/system_ext/media", "/vendor/media", "/oem/media",
)
NAME_PATTERN = re.compile(r"(?:bootanimation|shutdownanimation)[^/]*\.(?:zip|qmg)$", re.I)
def debugfs(image, command):
    return subprocess.run(["debugfs", "-R", command, str(image)],
                          text=True, capture_output=True, check=False)
def entries(image, path):
    result = debugfs(image, "ls -p " + path)
    if "File not found" in result.stderr or "not found" in result.stderr.lower():
        return []
    if result.returncode:
        return []
    ans = []
    for ln in result.stdout.splitlines():
        fields = ln.split("/")
        if len(fields) >= 6 and fields[1].isdigit():
            name = fields[5]
            if name and name not in (".", ".."):
                ans.append(name)
    return ans
def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--image",type=Path,required=True)
    a.add_argument("--work",type=Path,required=True)
    a.add_argument("--output",type=Path,required=True)
    args=a.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    args.output.mkdir(parents=True, exist_ok=True)
    with args.image.open("rb") as f:
        if f.read(4)!=bytes.fromhex("3aff26ed"):
            raise ValueError("Expected Android sparse image")
    raw=args.work/"super_raw.img"
    subprocess.run(["simg2img",str(args.image),str(raw)],check=True)
    images=args.work/"partitions";images.mkdir(exist_ok=True)
    for name in PARTITIONS:
        subprocess.run(["lpunpack","-p",name,str(raw),str(images)],check=True)
    found=[]
    for name in PARTITIONS:
        part=images/(name+".img")
        if not part.is_file():
            raise RuntimeError("Missing partition "+name)
        for folder in CANDIDATE_DIRS:
            for filename in entries(part,folder):
                if not NAME_PATTERN.fullmatch(filename):
                    continue
                source=folder.rstrip("/")+"/"+filename
                destination=args.output/(name+"__"+filename)
                if destination.exists():
                    destination=args.output/(name+"__"+folder.strip("/").replace("/","_")+"__"+filename)
                result=debugfs(part,"dump -p "+source+" "+str(destination))
                if result.returncode or not destination.is_file() or destination.stat().st_size==0:
                    raise RuntimeError("Could not extract "+name+":"+source+" "+result.stderr)
                info={"partition":name,"source":source,"file":destination.name,
                      "bytes":destination.stat().st_size,"sha256":sha256(destination)}
                if zipfile.is_zipfile(destination):
                    with zipfile.ZipFile(destination) as z:
                        info["archive_files"]=len(z.namelist())
                        desc=next((x for x in z.namelist() if x=="desc.txt"),None)
                        if desc:
                            data=z.read(desc)
                            info["desc_txt"]=data.decode("utf-8","replace")[:2000]
                            (args.output/(destination.name+".desc.txt")).write_bytes(data)
                        else:
                            info["warning"]="No root desc.txt found"
                found.append(info)
                print("EXTRACTED",name,source,destination.name,flush=True)
    report={"reference_image_sha256":sha256(args.image),
            "expected_display_landscape":"1340x800",
            "expected_display_portrait":"800x1340",
            "files":found,
            "note":"Read-only: this examines the downloaded GitHub firmware artifact, not tablet storage."}
    (args.output/"bootanimation-inventory.json").write_text(json.dumps(report,indent=2)+"\n")
    summary=["Boot animation archive extraction from EXACT debloated super.img",
             "Reference SHA256: "+report["reference_image_sha256"],
             "Display: 1340 x 800 landscape / 800 x 1340 portrait",""]
    if not found:
        summary.append("No boot animation found at common dynamic-partition media paths.")
        summary.append("This does not rule out animations in separate OEM partitions or alternate filenames.")
    for it in found:
        summary += [it["partition"]+": "+it["source"],
                    "  Extracted: "+it["file"],"  SHA256: "+it["sha256"],
                    "  desc.txt: "+str(it.get("desc_txt","not found"))]
    summary += ["","No firmware image was changed. Do not flash extracted ZIPs as firmware."]
    (args.output/"README.txt").write_text("\n".join(summary)+"\n")
    print("\n".join(summary),flush=True)
if __name__=="__main__":
    main()
