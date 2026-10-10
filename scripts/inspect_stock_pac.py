#!/usr/bin/env python3
"""Strictly read-only Unisoc PAC header inventory and embedded super checksum."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

PAC_FMT="<44sII512s512sIIIIIII200sIII800sIHH"
FILE_FMT="<I512s512s504sIIIIIIII5I996s"
PAC_SIZE=struct.calcsize(PAC_FMT)
FILE_SIZE=struct.calcsize(FILE_FMT)
EXPECTED_STOCK_SHA256="4dbf410905fe93e4e04563c5cc3e97864541af1f7dd2c68ef107830c8236afe1"
SPARSE_MAGIC=bytes.fromhex("3aff26ed")
def utf16(raw):
    return raw.decode("utf-16le",errors="replace").split("\x00",1)[0]
def hash_range(f, offset, size):
    sha=hashlib.sha256()
    f.seek(offset)
    remain=size
    while remain:
        data=f.read(min(remain,4*1024*1024))
        if not data: raise ValueError("PAC ended inside file payload")
        sha.update(data)
        remain-=len(data)
    return sha.hexdigest()
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--pac",required=True,type=Path)
    ap.add_argument("--report",required=True,type=Path)
    args=ap.parse_args()
    args.report.mkdir(exist_ok=True,parents=True)
    total=args.pac.stat().st_size
    if total<PAC_SIZE:raise ValueError("File too short to be PAC")
    with args.pac.open("rb") as f:
        h=struct.unpack(PAC_FMT,f.read(PAC_SIZE))
        version=utf16(h[0])
        declared=(h[1]<<32)|h[2]
        product=utf16(h[3]); firmware=utf16(h[4])
        count=h[5]; list_offset=h[6]
        info={"format_version":version,"product":product,
              "firmware":firmware,"pac_file_bytes":total,
              "pac_declared_bytes":declared,"entry_count":count,
              "file_table_offset":list_offset,"pac_header_struct_bytes":PAC_SIZE,
              "partition_header_struct_bytes":FILE_SIZE,
              "pac_magic":hex(h[-3]),"records":[]}
        if not version.startswith("BP_R"):
            raise ValueError("Unexpected PAC format version: "+repr(version))
        if declared!=total:raise ValueError("PAC stated size differs from download")
        if not 1<=count<=1024:raise ValueError("Unexpected number of PAC entries")
        if list_offset<PAC_SIZE or list_offset+count*FILE_SIZE>total:
            raise ValueError("PAC file table outside of file")
        f.seek(list_offset)
        for i in range(count):
            fields=struct.unpack(FILE_FMT,f.read(FILE_SIZE))
            if fields[0]!=FILE_SIZE:
                raise ValueError("PAC entry layout incompatible at "+str(i))
            record={"index":i,
                "partition":utf16(fields[1]),"filename":utf16(fields[2]),
                "entry_bytes":fields[0],
                "payload_bytes":(fields[4]<<32)|fields[6],
                "payload_offset":(fields[5]<<32)|fields[9],
                "file_flag":fields[7],"check_flag":fields[8],
                "can_omit_flag":fields[10]}
            if record["payload_bytes"] and record["payload_offset"]+record["payload_bytes"]>total:
                raise ValueError("PAC file payload out of bounds: "+str(record))
            info["records"].append(record)
        candidates=[r for r in info["records"] if "super" in (r["filename"]+" "+r["partition"]).lower() and r["payload_bytes"]>0]
        for rec in candidates:
            off=rec["payload_offset"]
            f.seek(off)
            magic=f.read(4)
            rec["payload_magic_hex"]=magic.hex()
            rec["is_android_sparse"]=magic==SPARSE_MAGIC
            rec["sha256"]=hash_range(f,off,rec["payload_bytes"])
            rec["matches_pinned_original_super"]=rec["sha256"]==EXPECTED_STOCK_SHA256
    info["super_entries_found"]=len(candidates)
    (args.report/"pac-inventory.json").write_text(json.dumps(info,indent=2)+"\n")
    lines=["READ-ONLY UNISOC PAC FIRMWARE INVENTORY", "="*55,
      "PAC file: "+args.pac.name,"PAC bytes: "+str(total),
      "Format: "+version,"Product: "+product,"Firmware: "+firmware,
      "Entry count: "+str(count),"", "FILE RECORDS:"]
    for x in info["records"]:
        line=(f"{x['index']:03d} | {x['partition']} | {x['filename']} | "
            f"{x['payload_bytes']} bytes | file_flag={x['file_flag']} check_flag={x['check_flag']} can_omit={x['can_omit_flag']}")
        lines.append(line)
    lines.extend(["","SUPER PAYLOADS:"])
    if not candidates:lines.append("No super payload detected in PAC file table.")
    for rec in candidates:
        lines.extend(["Name: "+rec["filename"],"Partition: "+rec["partition"],
         "Offset: "+str(rec["payload_offset"]),
         "Length: "+str(rec["payload_bytes"]),
         "Sparse: "+str(rec["is_android_sparse"]),
         "SHA256: "+rec["sha256"],
         "Matches original stock super: "+str(rec["matches_pinned_original_super"])])
    lines+=["","NO FLASH OR PAC MODIFICATIONS PERFORMED."]
    (args.report/"READ_ME_PAC_INSPECTION.txt").write_text("\n".join(lines)+"\n")
    print("\n".join(lines),flush=True)
if __name__=="__main__":main()
