#!/usr/bin/env python3
"""Read-only inventory of repository OTA update.zip; no patching or flashing."""
import argparse,base64,collections,hashlib,json,struct,zipfile
from pathlib import Path

def varint(data,pos):
    out=0;shift=0
    while True:
        if pos>=len(data) or shift>70:raise ValueError("Invalid protobuf varint")
        b=data[pos];pos+=1;out|=(b&127)<<shift
        if b<128:return out,pos
        shift+=7

def fields(data):
    pos=0;out=[]
    while pos<len(data):
        tag,pos=varint(data,pos)
        number,typ=tag>>3,tag&7
        if not number:raise ValueError("Invalid protobuf field")
        if typ==0:value,pos=varint(data,pos)
        elif typ==2:
            length,pos=varint(data,pos)
            if length>len(data)-pos:raise ValueError("Truncated protobuf")
            value=data[pos:pos+length];pos+=length
        elif typ==1:
            value=data[pos:pos+8];pos+=8
        elif typ==5:
            value=data[pos:pos+4];pos+=4
        else:raise ValueError("Unsupported protobuf wire type")
        out.append((number,typ,value))
    return out

def one(items,n,default=None):
    vals=[v for f,t,v in items if f==n]
    if len(vals)>1:raise ValueError("Duplicate singleton field "+str(n))
    return vals[0] if vals else default

def metadata(s):
    result={}
    for line in s.splitlines():
        if "=" in line:
            key,value=line.split("=",1)
            result[key]=value.strip()
    return result

def hash_bytes(blob):
    return hashlib.sha256(blob).digest()

def main():
    arg=argparse.ArgumentParser()
    arg.add_argument("--zip",required=True,type=Path)
    arg.add_argument("--report",required=True,type=Path)
    a=arg.parse_args()
    with zipfile.ZipFile(a.zip) as z:
        if z.testzip() is not None:raise ValueError("ZIP CRC mismatch")
        names=set(z.namelist())
        for required in ("payload.bin","payload_properties.txt","META-INF/com/android/metadata"):
            if required not in names:raise ValueError("Missing "+required)
        props=metadata(z.read("payload_properties.txt").decode())
        ota=metadata(z.read("META-INF/com/android/metadata").decode())
        payload=z.read("payload.bin")
    if payload[:4]!=b"CrAU" or len(payload)<24:raise ValueError("Not a ChromeOS/Android A/B payload")
    version,manifest_len=struct.unpack_from(">QQ",payload,4)
    if version!=2:raise ValueError("Unexpected payload version")
    signature_len=struct.unpack_from(">I",payload,20)[0]
    metadata_end=24+manifest_len+signature_len
    if metadata_end>len(payload):raise ValueError("Truncated payload metadata")
    props_sha=base64.b64decode(props["FILE_HASH"],validate=True)
    props_metadata_sha=base64.b64decode(props["METADATA_HASH"],validate=True)
    if int(props["FILE_SIZE"])!=len(payload) or props_sha!=hash_bytes(payload):
        raise ValueError("Payload declared size/digest mismatch")
    metadata_size=int(props["METADATA_SIZE"])
    if metadata_size!=24+manifest_len:
        raise ValueError("Unexpected metadata length; refusing unverified hash boundary")
    if props_metadata_sha!=hash_bytes(payload[:metadata_size]):
        raise ValueError("Payload metadata SHA256 mismatch")
    manifest=fields(payload[24:24+manifest_len])
    entries=[]
    for number,wire,raw in manifest:
        if number!=13:continue
        if wire!=2:raise ValueError("Invalid partition entry")
        entry=fields(raw)
        name=one(entry,1).decode()
        if not name.isascii() or not name.replace("_","").isalnum():raise ValueError("Bad partition name")
        def pinfo(tag):
            blob=one(entry,tag)
            if blob is None:return None
            info=fields(blob)
            return {"size":one(info,1),"sha256":one(info,2,b"").hex()}
        operations=[fields(blob) for field,w,blob in entry if field==8]
        types=collections.Counter(str(one(op,1,"unknown")) for op in operations)
        entries.append({"partition":name,"old":pinfo(6),"new":pinfo(7),
                        "operation_count":len(operations),"operation_types":dict(types),
                        "uses_source_extents":any(any(field==4 for field,_,_ in op) for op in operations)})
    names=[x["partition"] for x in entries]
    if len(names)!=len(set(names)) or not entries:raise ValueError("Duplicate or missing partitions")
    expected={"product":1809002496,"system":1996099584}
    size_comparison={name:{"ota_source_size":next((e["old"]["size"] for e in entries if e["partition"]==name and e["old"]),None),
                           "known_stock_pac_partition_size":size}
                     for name,size in expected.items()}
    for name,obj in size_comparison.items():
        obj["size_matches"]=obj["ota_source_size"]==obj["known_stock_pac_partition_size"]
    result={"status":"READ-ONLY OTA INVENTORY VALIDATED","source_zip_sha256":hashlib.sha256(a.zip.read_bytes()).hexdigest(),
            "payload_sha256":hash_bytes(payload).hex(),"metadata_sha256":hash_bytes(payload[:metadata_size]).hex(),
            "payload_version":version,"metadata":ota,"partition_count":len(entries),
            "partitions":entries,"known_partition_size_comparison":size_comparison,
            "source_partition_hashes_verified_against_PAC":False,
            "incremental_OTA_safe_to_apply_to_modified_super":False,
            "avb_oem_signing_keys_present":False}
    a.report.parent.mkdir(parents=True,exist_ok=True)
    a.report.write_text(json.dumps(result,indent=2)+"\n")
    print("OTA READ-ONLY INVENTORY PASSED",flush=True)
    print("Source:",ota.get("pre-build"),flush=True)
    print("Target:",ota.get("post-build"),flush=True)
    print("Partitions:",len(entries),flush=True)
    for e in entries:
        print("PARTITION",e["partition"],"old",e["old"]["size"] if e["old"] else None,
              "new",e["new"]["size"] if e["new"] else None,
              "ops",e["operation_count"],"uses-source",e["uses_source_extents"],flush=True)
    print("Matching sizes do not prove matching hashes or OTA applicability",flush=True)

if __name__=="__main__":main()
