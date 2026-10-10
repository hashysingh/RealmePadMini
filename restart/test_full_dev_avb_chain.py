#!/usr/bin/env python3
"""Experimentally sign an internally consistent five-node AVB chain OFFLINE.

Not OEM-trusted; never publish images or keys. Only product/system child metadata
is regenerated. system_ext/vendor stock metadata and their public keys stay intact.
The root is re-signed by a temporary untrusted key to reflect the two new keys.
"""
import argparse,hashlib,re,struct,subprocess,tempfile,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'scripts'))
from audit_stock_avb_chain import parse,CHILDREN
from test_avb_tree_rebuild import desc
from test_dev_avb_signing import run

def inspect(avbtool,path):
    top,descriptors=parse(run("python3",avbtool,"info_image","--image",path))
    return top,descriptors

def number(value):
    return int(str(value).split()[0],0)

def public_key_from_vbmeta(path,out):
    """AVB v1 header: embedded public key is in the auxiliary data block."""
    with path.open("rb") as f:
        head=f.read(256)
        if len(head)!=256 or head[:4]!=b"AVB0":raise ValueError("Invalid stock AVB0 header "+str(path))
        auth_size=struct.unpack_from(">Q",head,12)[0]
        aux_size=struct.unpack_from(">Q",head,20)[0]
        off=struct.unpack_from(">Q",head,64)[0]
        size=struct.unpack_from(">Q",head,72)[0]
        if not (512<=size<=8192 and off+size<=aux_size and 256+auth_size+aux_size<=path.stat().st_size):
            raise ValueError("Invalid stock public key offsets "+str(path))
        f.seek(256+auth_size+off)
        blob=f.read(size)
    if len(blob)!=size:raise EOFError(path)
    out.write_bytes(blob)
    return blob

def stock_root_chains(image):
    """Extract all chain descriptors and OEM public keys straight from AVB0 bytes."""
    with image.open("rb") as fd:
        head=fd.read(256)
        if len(head)!=256 or head[:4]!=b"AVB0":
            raise ValueError("Invalid root vbmeta header")
        auth_size=struct.unpack_from(">Q",head,12)[0]
        aux_size=struct.unpack_from(">Q",head,20)[0]
        desc_offset=struct.unpack_from(">Q",head,96)[0]
        desc_size=struct.unpack_from(">Q",head,104)[0]
        if not (desc_size>0 and desc_offset+desc_size<=aux_size and
                256+auth_size+aux_size<=image.stat().st_size):
            raise ValueError("Out-of-bounds root AVB descriptors")
        fd.seek(256+auth_size+desc_offset)
        buf=fd.read(desc_size)
    result={}
    cursor=0
    while cursor<len(buf):
        if len(buf)-cursor<16:raise ValueError("Truncated root descriptor")
        tag,following=struct.unpack_from(">QQ",buf,cursor)
        total=16+following
        if total<16 or total%8 or cursor+total>len(buf):
            raise ValueError("Malformed root descriptor size")
        if tag!=4 or total<92:
            raise ValueError("Unexpected non-chain root descriptor tag "+str(tag))
        location,name_len,key_len=struct.unpack_from(">III",buf,cursor+16)
        if not name_len or key_len<512 or 92+name_len+key_len>total:
            raise ValueError("Malformed chain descriptor sizes")
        name=buf[cursor+92:cursor+92+name_len].decode("utf-8")
        key=buf[cursor+92+name_len:cursor+92+name_len+key_len]
        if not re.fullmatch(r"[a-z0-9_]+",name) or name in result:
            raise ValueError("Invalid/duplicate root chain name "+name)
        result[name]=(location,key)
        cursor+=total
    if cursor!=len(buf) or len(result)!=13:
        raise ValueError("Expected exactly 13 OEM root chains, found "+str(len(result)))
    return result

def cut_prefix(source,out,length):
    with source.open("rb") as fd,out.open("wb") as dst:
        while length:
            chunk=fd.read(min(4*1024*1024,length))
            if not chunk:raise EOFError(source)
            dst.write(chunk)
            length-=len(chunk)

def equals_range(source,other,start,count,label):
    with source.open("rb") as src,other.open("rb") as dst:
        src.seek(start);dst.seek(start)
        left=count
        while left:
            size=min(4*1024*1024,left)
            if src.read(size)!=dst.read(size):raise ValueError("Generated "+label+" differs from validated Super partition")
            left-=size

def main():
    p=argparse.ArgumentParser()
    for name in ("stock","parts","avbtool","work"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    a.work.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dev-chain-only-",dir=a.work) as dirname:
        tmp=Path(dirname)
        keys={}
        pub={}
        children={}
        stocks={}
        for name in ("vbmeta",)+tuple(CHILDREN):
            path=a.stock/(name+".img")
            top,descriptors=inspect(a.avbtool,path)
            if top.get("Algorithm")!="SHA256_RSA4096" or top.get("Flags") not in ("0","0x0"):
                raise ValueError("Unexpected stock AVB signing or flags "+name)
            stocks[name]=(top,descriptors)
        root_descriptors=stocks["vbmeta"][1]
        print("STOCK ROOT DESCRIPTOR INVENTORY:",flush=True)
        for i,item in enumerate(root_descriptors,1):
            fields=item["fields"]
            print("  "+str(i)+": type="+item["type"]+" partition="+str(fields.get("Partition Name"))+" keys="+",".join(sorted(fields)),flush=True)
        expected_root_chains=stock_root_chains(a.stock/"vbmeta.img")
        displayed={d["fields"].get("Partition Name") for d in root_descriptors if d["type"]=="Chain Partition"}
        if len(root_descriptors)!=13 or displayed!=set(expected_root_chains):
            raise ValueError("Binary and avbtool root chain inventory disagree")
        print("STOCK ROOT ALL 13 CHAINS VERIFIED:",",".join(sorted(expected_root_chains)),flush=True)
        for name in ("vbmeta","vbmeta_system","vbmeta_product"):
            key=tmp/(name+"-TEMP-UNTRUSTED.pem")
            run("openssl","genrsa","-out",key,"4096")
            pubkey=tmp/(name+".avbpubkey")
            run("python3",a.avbtool,"extract_public_key","--key",key,"--output",pubkey)
            keys[name]=key;pub[name]=pubkey
        for name,partition in CHILDREN.items():
            child_top,child_descriptors=stocks[name]
            if len(child_descriptors)!=1 or child_descriptors[0]["type"]!="Hashtree":
                raise ValueError("Child has unexpected stock descriptors: "+name)
            if child_descriptors[0]["fields"].get("Partition Name")!=partition:
                raise ValueError("Child protects unexpected partition: "+name)
            if partition in ("system","product"):
                stock_desc=desc(a.avbtool,a.stock/(name+".img"),partition)
                source=a.parts/(partition+"_a.img")
                data_size=number(stock_desc["Image Size"])
                logical_size=source.stat().st_size
                child_image=tmp/(partition+".img")
                cut_prefix(source,child_image,data_size)
                dev=tmp/(name+".img")
                command=["python3",str(a.avbtool),"add_hashtree_footer",
                         "--image",str(child_image),"--partition_name",partition,
                         "--partition_size",str(logical_size),
                         "--algorithm","SHA256_RSA4096","--key",str(keys[name]),
                         "--hash_algorithm","sha1","--salt",stock_desc["Salt"],
                         "--block_size","4096","--fec_num_roots","2",
                         "--rollback_index",str(number(child_top["Rollback Index"])),
                         "--output_vbmeta_image",str(dev),"--do_not_append_vbmeta_image"]
                run(*command)
                updated=desc(a.avbtool,dev,partition)
                for field in ("Image Size","Tree Offset","Tree Size","FEC offset","FEC size",
                              "FEC num roots","Data Block Size","Hash Block Size","Salt","Hash Algorithm"):
                    if updated.get(field)!=stock_desc.get(field):
                        raise ValueError(partition+" AVB descriptor geometry changed: "+field+
                                         " stock="+str(stock_desc.get(field))+" new="+str(updated.get(field)))
                if updated["Root Digest"].lower()==stock_desc["Root Digest"].lower():
                    raise ValueError("Expected changed root for "+partition)
                for off,size,label in [(0,data_size,"data"),
                                      (number(stock_desc["Tree Offset"]),number(stock_desc["Tree Size"]),"tree"),
                                      (number(stock_desc["FEC offset"]),number(stock_desc["FEC size"]),"FEC")]:
                    equals_range(source,child_image,off,size,partition+" "+label)
                run("python3",a.avbtool,"verify_image","--image",dev,"--key",keys[name])
                children[name]=dev
                print("DEV CHILD VERIFIED "+name+" all data/tree/FEC bytes equal validated Super",flush=True)
            else:
                # Retain original OEM signature and embedded OEM public key.
                pubkey=tmp/(name+"-OEM-unchanged.avbpubkey")
                public_key_from_vbmeta(a.stock/(name+".img"),pubkey)
                pub[name]=pubkey
                destination=tmp/(name+".img")
                shutil.copyfile(a.stock/(name+".img"),destination)
                children[name]=destination
                print("UNCHANGED OEM CHILD "+name,flush=True)
        # Preserve all 11 unaffected OEM root descriptors' exact key bytes,
        # partition names and rollback locations. Replace only system/product keys.
        chain=[]
        expected_keys={}
        for name,(location,original_key) in expected_root_chains.items():
            if name in ("vbmeta_system","vbmeta_product"):
                chosen=pub[name].read_bytes()
            else:
                chosen=original_key
            out=tmp/(name+"-root-key.avbpubkey")
            out.write_bytes(chosen)
            expected_keys[name]=(location,chosen)
            chain.extend(["--chain_partition",name+":"+str(location)+":"+str(out)])
        if len(expected_keys)!=13:raise ValueError("Not all OEM root chains preserved")
        root=tmp/"vbmeta.img"
        root_top=stocks["vbmeta"][0]
        run("python3",a.avbtool,"make_vbmeta_image",
            "--output",root,"--algorithm","SHA256_RSA4096","--key",keys["vbmeta"],
            "--rollback_index",str(number(root_top["Rollback Index"])),*chain)
        top,descriptors=inspect(a.avbtool,root)
        if top.get("Algorithm")!="SHA256_RSA4096" or len(descriptors)!=13:
            raise ValueError("Development root chain malformed")
        result_chains=stock_root_chains(root)
        if result_chains!=expected_keys:
            raise ValueError("Root chain changed an unexpected key, name, or rollback location")
        for name in CHILDREN:
            match=[d for d in descriptors if d["type"]=="Chain Partition"
                   and d["fields"].get("Partition Name")==name]
            if len(match)!=1:raise ValueError("Development root chain omits "+name)
        print("ALL 13 ROOT CHAIN DESCRIPTORS PRESERVED; only system/product keys changed",flush=True)
        run("python3",a.avbtool,"verify_image","--image",root,"--key",keys["vbmeta"])
        print("DEVELOPMENT ROOT SIGNATURE VERIFIED (OEM trust NOT established)",flush=True)
        print("THIRTEEN-DESCRIPTOR DEVELOPMENT CHAIN TEST PASSED; all ephemeral metadata destroyed after script exits",flush=True)
        print("DO NOT FLASH: OEM root signature and OEM child keys for modified partitions are replaced by untrusted temporary keys.",flush=True)

if __name__=="__main__":main()
