#!/usr/bin/env python3
"""Offline-only bootanimation swap into an existing debloated sparse super image."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

EXPECTED_IMAGE = "d1266658821f587a273e139841f861c7ae1557d3415dde8fc8990aa1e62d74f3"
EXPECTED_ANIMATION = "fc9221074afb9d40404bf1d1b9fd73925406f5911a0db7842462a3c060d75283"
ANIM_PATH = "/system/media/bootanimation.zip"

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b""):h.update(chunk)
    return h.hexdigest()

def run(*args, ok=(0,)):
    p=subprocess.run(args,capture_output=True,text=True)
    if p.returncode not in ok:
        raise RuntimeError("Command failed: "+repr(args)+"\n"+p.stderr[-1200:])
    return p

def debug(image, instruction, write=False):
    args=["debugfs"]+(["-w"] if write else [])+["-R",instruction,str(image)]
    p=run(*args)
    if re.search(r"(?i)(file not found|no such file|no space|error:)",p.stderr):
        raise RuntimeError("debugfs error: "+instruction+" "+p.stderr[-900:])
    return p.stdout

def layout(raw):
    out=run("lpdumps",str(raw)).stdout
    current=None
    extents={}
    for line in out.splitlines():
        name=re.fullmatch(r"\s*Name: (\w+)\s*",line)
        if name:
            current=name.group(1)
            extents[current]=[]
        match=re.fullmatch(r"\s*(\d+) \.\. (\d+) linear super (\d+)\s*",line)
        if match and current:
            first,last,start=map(int,match.groups())
            extents[current].append((512*start,512*(last-first+1)))
    return out,extents

def checked_zip(path):
    with zipfile.ZipFile(path) as z:
        if z.testzip() is not None:raise ValueError("Boot animation ZIP CRC failure")
        if z.read("desc.txt").splitlines()[0]!=b"800 1340 18":
            raise ValueError("Unexpected animation resolution or frame rate")
        files=[name for name in z.namelist() if name.endswith(".png")]
        if len(files)!=111:raise ValueError("Unexpected animation frame count")
    return len(files)

def main():
    ap=argparse.ArgumentParser()
    for arg in ("image","animation","work","output","report"):
        ap.add_argument("--"+arg,required=True,type=Path)
    a=ap.parse_args()
    a.work.mkdir(parents=True,exist_ok=True)
    a.output.mkdir(parents=True,exist_ok=True)
    a.report.mkdir(parents=True,exist_ok=True)
    if sha(a.image)!=EXPECTED_IMAGE:
        raise ValueError("Input must be the exact verified debloated super")
    if sha(a.animation)!=EXPECTED_ANIMATION:
        raise ValueError("Input animation differs from adapted RMP2106 test ZIP")
    count=checked_zip(a.animation)
    raw=a.work/"diagnostic_raw.img"
    run("simg2img",str(a.image),str(raw))
    old_meta,ex=layout(raw)
    if len(ex.get("system_a",[]))!=1:
        raise ValueError("Expected single system_a extent")
    start,size=ex["system_a"][0]
    if start+size>raw.stat().st_size:raise ValueError("Extent outside super")
    extracted=a.work/"original_system";extracted.mkdir(exist_ok=True)
    run("lpunpack","-p","system_a",str(raw),str(extracted))
    system=extracted/"system_a.img"
    if system.stat().st_size!=size:raise ValueError("system_a partition size mismatch")
    before_sys_sha=sha(system)
    original=a.report/"original-bootanimation.zip"
    debug(system,"dump -p "+ANIM_PATH+" "+str(original))
    if not original.is_file():raise ValueError("Original animation missing")
    old_anim_sha=sha(original)
    debug(system,"rm "+ANIM_PATH,write=True)
    debug(system,"write "+str(a.animation)+" "+ANIM_PATH,write=True)
    extracted_new=a.work/"filesystem-animation-check.zip"
    debug(system,"dump -p "+ANIM_PATH+" "+str(extracted_new))
    if sha(extracted_new)!=EXPECTED_ANIMATION:
        raise ValueError("Modified filesystem animation does not match source ZIP")
    fsck=run("e2fsck","-fn",str(system),ok=(0,))
    (a.report/"system_a-e2fsck.txt").write_text(fsck.stdout+"\n"+fsck.stderr)
    if sha(system)==before_sys_sha:raise ValueError("system_a still identical")
    with raw.open("r+b") as out,system.open("rb") as src:
        out.seek(start)
        shutil.copyfileobj(src,out,4*1024*1024)
    new_meta,new_ex=layout(raw)
    if old_meta!=new_meta or ex!=new_ex:
        raise ValueError("LP metadata changed")
    final=a.output/"super_debloated_Gemini_TEST_sparse.img"
    run("img2simg",str(raw),str(final))
    raw_recheck=a.work/"recheck_raw.img"
    run("simg2img",str(final),str(raw_recheck))
    if raw_recheck.stat().st_size!=raw.stat().st_size:
        raise ValueError("Raw super size changed")
    partition_dir=a.work/"recheck_system";partition_dir.mkdir(exist_ok=True)
    run("lpunpack","-p","system_a",str(raw_recheck),str(partition_dir))
    verified=a.work/"from_final_super.zip"
    debug(partition_dir/"system_a.img","dump -p "+ANIM_PATH+" "+str(verified))
    if sha(verified)!=EXPECTED_ANIMATION:
        raise ValueError("Final repacked super contains the wrong boot animation")
    report={"diagnostic_image":final.name,"original_image_sha256":sha(a.image),
            "animation_sha256":EXPECTED_ANIMATION,
            "original_animation_sha256":old_anim_sha,
            "output_image_sha256":sha(final),
            "animation_path":ANIM_PATH,"frames":count,
            "system_a_size":size,"lp_metadata_unchanged":True,
            "ext4_check":"passed",
            "final_image_reextraction":"passed",
            "device_boot_verified":False}
    (a.report/"validation.json").write_text(json.dumps(report,indent=2)+"\n")
    (a.report/"READ_BEFORE_USE.txt").write_text(
      "EXPERIMENTAL OFFLINE DIAGNOSTIC IMAGE. NOT DEVICE/BOOT VERIFIED.\n"
      "Based on existing debloated super image; replaces only the bootanimation file in system_a.\n"
      "Android Verified Boot compatibility has not been established. Do not flash without review.\n")
    print(json.dumps(report,indent=2),flush=True)

if __name__=="__main__":
    main()
