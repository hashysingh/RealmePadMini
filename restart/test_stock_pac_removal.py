#!/usr/bin/env python3
"""RMP2106 clean-start, offline-only PAC and 73-target app removal test.

Produces no installable firmware, never repacks a PAC, flashes, or signs AVB.
All modifications are to disposable extracted partition copies on CI runner.
"""
import argparse, hashlib, json, re, struct, subprocess
from pathlib import Path
from collections import Counter
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'scripts'))

from inspect_pac_avb import PAC_FMT, FILE_FMT, PAC_SIZE, FILE_SIZE, decode
from build_debloated_super import debug, erase_tree

EXPECTED_PAC="381c295640947371b604ab830da04dc6d90be4b3c99b9c9c409c73dd51320c0b"
EXPECTED_SUPER="4dbf410905fe93e4e04563c5cc3e97864541af1f7dd2c68ef107830c8236afe1"
REQUIRED_AVB={"VBMETA","VBMETA_SYSTEM","VBMETA_PRODUCT","VBMETA_SYSTEM_EXT","VBMETA_VENDOR"}
DANGEROUS={"GooglePackageInstaller","ExternalStorageProvider","FusedLocation","InputDevices",
           "BlockedNumberProvider","CallLogBackup","MmsService","GoogleContactsSyncAdapter"}

def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(4*1024*1024),b""):h.update(block)
    return h.hexdigest()

def cmd(*args):
    print("$ "+" ".join(map(str,args)),flush=True)
    return subprocess.run([str(a) for a in args],check=True)

def list_targets(file):
    target={"product_a":[],"system_a":[]}
    current=None
    for line in file.read_text().splitlines():
        line=line.strip()
        if line.startswith("product_a ("): current="product_a"
        elif line.startswith("system_a ("): current="system_a"
        elif line.startswith("/"):
            if not current or not line.endswith(".apk") or "//" in line or "\\" in line:
                raise ValueError("Unsafe manifest APK path "+line)
            components=line.split("/")
            if any(x in (".","..") for x in components):
                raise ValueError("Traversal in manifest")
            target[current].append(line)
    if [len(target[x]) for x in ("product_a","system_a")]!=[25,48]:
        raise ValueError("Manifest must contain exactly 25 product + 48 system APKs")
    names=[(p,x) for p,entries in target.items() for x in entries]
    if len(set(names))!=73:raise ValueError("Duplicate entries in list")
    manifest_digest=hashlib.sha256("\n".join(sorted(p+":"+x for p,items in target.items() for x in items)).encode()).hexdigest()
    if manifest_digest!="fdad53aa9f0665ae4bb1b3309303296596d29a55e08093e346a8c125d5923834":
        raise ValueError("Manifest differs from user uploaded revised 73-APK list")
    return target

def extract_pac(pac,output):
    output.mkdir(exist_ok=True,parents=True)
    with pac.open("rb") as fd:
        h=struct.unpack(PAC_FMT,fd.read(PAC_SIZE))
        count,offset=h[5:7]
        if not 1<=count<=1024 or offset<PAC_SIZE or offset+count*FILE_SIZE>pac.stat().st_size:
            raise ValueError("Invalid PAC file table")
        fd.seek(offset)
        selected={}
        for _ in range(count):
            row=struct.unpack(FILE_FMT,fd.read(FILE_SIZE))
            if row[0]!=FILE_SIZE:raise ValueError("Unexpected PAC entry format")
            ident=decode(row[1])
            if ident=="Super" or ident in REQUIRED_AVB:
                off=(row[5]<<32)|row[9]
                size=(row[4]<<32)|row[6]
                if size<=0 or off+size>pac.stat().st_size:raise ValueError("PAC entry out of range: "+ident)
                if ident in selected:raise ValueError("Duplicate PAC entry: "+ident)
                selected[ident]=(off,size)
        if set(selected)!={"Super"}|REQUIRED_AVB:
            raise ValueError("PAC missing Super or one of five signed vbmeta entries")
        result={}
        for ident,(start,size) in selected.items():
            dest=output/("super-stock-sparse.img" if ident=="Super" else ident.lower()+".img")
            fd.seek(start)
            with dest.open("wb") as out:
                remaining=size
                while remaining:
                    buf=fd.read(min(remaining,4*1024*1024))
                    if not buf:raise EOFError("Truncated PAC "+ident)
                    out.write(buf);remaining-=len(buf)
            if ident=="Super":
                if sha(dest)!=EXPECTED_SUPER:raise ValueError("Stock sparse super digest mismatch")
                if dest.open("rb").read(4)!=bytes.fromhex("3aff26ed"):
                    raise ValueError("Super not Android sparse")
            elif dest.open("rb").read(4)!=b"AVB0":
                raise ValueError("AVB0 signature missing "+ident)
            result[ident]={"bytes":size,"sha256":sha(dest)}
            print("PAC "+ident+": "+str(size)+" bytes verified",flush=True)
        return result

def stat_exists(image,path):
    # debugfs returns zero even when stat fails; inspect both streams.
    x=subprocess.run(["debugfs","-R","stat "+path,str(image)],capture_output=True,text=True)
    text=x.stdout+"\n"+x.stderr
    missing=bool(re.search(r"(not found|No such file|File not found)",text,re.I))
    if x.returncode and not missing:raise RuntimeError("debugfs stat failed: "+path+" "+text[-400:])
    if not missing and not re.search(r"(?m)^\s*(Inode:|Size:|Type:)",text):
        raise RuntimeError("Ambiguous debugfs stat: "+path+" "+text[-500:])
    return not missing

def check(image,apks,writes):
    checked=[]
    for ix,apk in enumerate(apks,1):
        parent=apk.rsplit("/",1)[0]
        is_overlay=parent=="/overlay"
        if not stat_exists(image,apk):raise ValueError("Original APK missing "+apk)
        if not stat_exists(image,parent):raise ValueError("Original folder missing "+parent)
        checked.append((apk,parent,is_overlay))
        print(f"CHECK {ix}/{len(apks)} present {apk}",flush=True)
    if not writes:return checked
    deleted=set()
    for ix,(apk,parent,is_overlay) in enumerate(checked,1):
        if is_overlay:
            debug(image,"rm "+apk,write=True)
        elif parent not in deleted:
            erase_tree(image,parent,[])
            deleted.add(parent)
        if stat_exists(image,apk):raise ValueError("APK still present after deletion: "+apk)
        if not is_overlay and stat_exists(image,parent):
            raise ValueError("APK-containing folder still exists: "+parent)
        if is_overlay and not stat_exists(image,"/overlay"):
            raise ValueError("Shared /overlay was removed")
        print(f"DELETE {ix}/{len(checked)} VERIFIED: {apk} ; folder "+("SHARED /overlay preserved" if is_overlay else "ABSENT"),flush=True)
    for apk,parent,is_overlay in checked:
        if stat_exists(image,apk) or (not is_overlay and stat_exists(image,parent)):
            raise ValueError("Final audit target still exists "+apk)
    return checked

def main():
    arg=argparse.ArgumentParser()
    for option in ("pac","targets","work","avbtool"):
        arg.add_argument("--"+option,type=Path,required=True)
    a=arg.parse_args()
    a.work.mkdir(exist_ok=True,parents=True)
    entries=list_targets(a.targets)
    print("[1/6] Validating all 73 targets",flush=True)
    print("Counts "+json.dumps({k:len(v) for k,v in entries.items()}),flush=True)
    risk=[x for group in entries.values() for x in group if x.rsplit("/",1)[-1].removesuffix(".apk") in DANGEROUS]
    print("WARNING core function impact / not boot-tested: "+json.dumps(risk),flush=True)
    print("[2/6] Verifying entire stock PAC SHA-256",flush=True)
    if sha(a.pac)!=EXPECTED_PAC:raise ValueError("PAC does not match original RMP2106PU_11.A.21")
    print("[3/6] Extracting stock sparse Super plus all 5 original vbmeta images",flush=True)
    metadata=extract_pac(a.pac,a.work/"pac")
    for name in sorted(REQUIRED_AVB):
        avb=a.work/"pac"/(name.lower()+".img")
        r=subprocess.run(["python3",str(a.avbtool),"info_image","--image",str(avb)],
                         capture_output=True,text=True)
        match=re.search(r"(?m)^\s*Algorithm:\s*(\S+)",r.stdout)
        if r.returncode or not match or match.group(1)!="SHA256_RSA4096":
            raise ValueError(
                "Could not inspect original "+name+
                " (exit="+str(r.returncode)+", algorithm="+repr(match.group(1) if match else None)+")"+
                "\nstdout tail: "+r.stdout[-1300:]+
                "\nstderr tail: "+r.stderr[-1300:])
        print("AVB inspected "+name+"; rsa4096",flush=True)
    print("[4/6] Unpacking untouched stock super",flush=True)
    raw=a.work/"stock.raw"
    cmd("simg2img",a.work/"pac"/"super-stock-sparse.img",raw)
    parts=a.work/"parts";parts.mkdir(exist_ok=True)
    cmd("lpunpack","-p","system_a",raw,parts)
    cmd("lpunpack","-p","product_a",raw,parts)
    raw.unlink()
    print("[5/6] Prove every requested original APK exists; delete on disposable copies",flush=True)
    results={}
    for part,apks in entries.items():
        image=parts/(part+".img")
        if not image.is_file():raise ValueError("Partition extraction failed "+part)
        before=sha(image)
        completed=check(image,apks,writes=True)
        fsck=subprocess.run(["e2fsck","-fn",str(image)],text=True,capture_output=True)
        if fsck.returncode:
            raise ValueError(f"{part} e2fsck returned {fsck.returncode}: "+(fsck.stderr+"\n"+fsck.stdout)[-900:])
        results[part]={"requested":len(apks),"apk_absent":len(completed),
                       "private_parent_folders_absent":sum(not x[2] for x in completed),
                       "shared_overlay_files_removed":sum(x[2] for x in completed),
                       "sha256_changed":sha(image)!=before,"fsck":"PASSED"}
    print("[6/6] In-memory / log-only validation summary",flush=True)
    print(json.dumps({"status":"OFFLINE APP REMOVAL TEST PASSED",
          "counts":results,"pac_entries_inspected":sorted(metadata),
          "UNVERIFIED":["bootability","AVB signatures","FEC","PAC repacking","device acceptance"],
          "artifact_uploaded":False,"flashable_firmware_created":False},indent=2),flush=True)
    print("DO NOT FLASH: modified images have stale OEM AVB signatures and FEC",flush=True)

if __name__=="__main__":main()
