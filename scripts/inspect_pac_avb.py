#!/usr/bin/env python3
"""Read-only PAC AVB audit: extract only vbmeta payloads and summarize descriptor data."""
import argparse, hashlib, json, re, struct, subprocess
from pathlib import Path

PAC_FMT="<44sII512s512sIIIIIII200sIII800sIHH"
FILE_FMT="<I512s512s504sIIIIIIII5I996s"
PAC_SIZE=struct.calcsize(PAC_FMT)
FILE_SIZE=struct.calcsize(FILE_FMT)
PAC_SHA256="381c295640947371b604ab830da04dc6d90be4b3c99b9c9c409c73dd51320c0b"
NAMES=("VBMETA","VBMETA_SYSTEM","VBMETA_PRODUCT","VBMETA_SYSTEM_EXT","VBMETA_VENDOR")
def decode(value):
    return value.decode("utf-16le",errors="replace").split("\x00",1)[0]
def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(4*1024*1024),b""):h.update(chunk)
    return h.hexdigest()
def main():
    a=argparse.ArgumentParser()
    a.add_argument("--pac",required=True,type=Path)
    a.add_argument("--avbtool",required=True,type=Path)
    a.add_argument("--report",required=True,type=Path)
    opt=a.parse_args()
    opt.report.mkdir(exist_ok=True,parents=True)
    if digest(opt.pac)!=PAC_SHA256:
        raise ValueError("PAC SHA256 differs from previously inspected original")
    with opt.pac.open("rb") as stream:
        header=struct.unpack(PAC_FMT,stream.read(PAC_SIZE))
        count,offset=header[5],header[6]
        if not 1<=count<=1024 or offset<PAC_SIZE or offset+count*FILE_SIZE>opt.pac.stat().st_size:
            raise ValueError("Invalid PAC table")
        stream.seek(offset)
        records=[]
        for i in range(count):
            fields=struct.unpack(FILE_FMT,stream.read(FILE_SIZE))
            if fields[0]!=FILE_SIZE:raise ValueError("Unsupported PAC record layout")
            name=decode(fields[1])
            if name in NAMES:
                records.append({"id":name,"filename":decode(fields[2]),
                                "offset":(fields[5]<<32)|fields[9],
                                "length":(fields[4]<<32)|fields[6],
                                "flag":fields[7],"checkflag":fields[8]})
        if {x["id"] for x in records}!=set(NAMES):
            raise ValueError("Expected five AVB metadata images")
        for record in records:
            if record["length"]==0 or record["length"]>2*1024*1024:
                raise ValueError("Unexpected vbmeta size "+record["id"])
            if record["offset"]+record["length"]>opt.pac.stat().st_size:
                raise ValueError("Out-of-bounds vbmeta "+record["id"])
            stream.seek(record["offset"])
            data=stream.read(record["length"])
            image=opt.report/(record["id"].lower()+".img")
            image.write_bytes(data)
            record["sha256"]=hashlib.sha256(data).hexdigest()
            record["has_avb_header"]=data.startswith(b"AVB0")
            if not record["has_avb_header"]:
                record["note"]="No AVB0 header at offset zero; may contain a format wrapper"
            result=subprocess.run(["python3",str(opt.avbtool),"info_image","--image",str(image)],
                                  text=True,capture_output=True)
            record["avbtool_exit_code"]=result.returncode
            record["avbtool_report"]=result.stdout.strip() or result.stderr.strip()
            (opt.report/(record["id"].lower()+"-avbtool.txt")).write_text(
                result.stdout+"\n"+result.stderr)
    report={"scope":"OFFLINE ORIGINAL PAC ONLY","pac_sha256":PAC_SHA256,
            "images":records,
            "conclusion":"This reports AVB descriptors. It cannot determine tablet storage contents or prove Fastbootd writes are effective."}
    (opt.report/"avb-inspection.json").write_text(json.dumps(report,indent=2)+"\n")
    summary=["READ-ONLY ORIGINAL PAC AVB INSPECTION","",
             "Original PAC SHA256: "+PAC_SHA256,""]
    for item in records:
        summary.extend([item["id"]+" ("+item["filename"]+")",
                        "  Packaged bytes: "+str(item["length"]),
                        "  SHA256: "+item["sha256"],
                        "  File flag / check flag: "+str(item["flag"])+"/"+str(item["checkflag"]),
                        "  avbtool exit: "+str(item["avbtool_exit_code"]),
                        item["avbtool_report"],""])
    summary.append("No PAC modification, signing, verification bypass, or flashing performed.")
    (opt.report/"READ_ME_AVB_REPORT.txt").write_text("\n".join(summary)+"\n")
    print("\n".join(summary),flush=True)
    if any(item["avbtool_exit_code"] for item in records):
        raise ValueError("One or more vbmeta images were not readable by avbtool: see report")
if __name__=="__main__":main()
