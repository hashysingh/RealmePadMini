#!/usr/bin/env python3
"""Offline-only experimental AVB signature verification on modified RMP2106 data.

Produces ephemeral, standalone vbmeta for test only, not a flashable boot chain.
Original OEM signed vbmeta remains untouched. No artifacts are uploaded.
"""
import hashlib,json,re,subprocess,tempfile
from pathlib import Path
from test_avb_tree_rebuild import desc

def run(*args):
    proc=subprocess.run([str(x) for x in args],capture_output=True,text=True)
    if proc.returncode:
        raise RuntimeError("Command failed "+str([str(x) for x in args][:4])+
                           "\nexit="+str(proc.returncode)+"\nstdout="+proc.stdout[-1200:]+
                           "\nstderr="+proc.stderr[-1200:])
    return proc.stdout

def digest(path):
    hash=hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda:handle.read(4*1024*1024),b""):
            hash.update(chunk)
    return hash.hexdigest()

def verify_offline_dev_metadata(avbtool,stock_vbmeta_dir,modified_partitions,hashtree_report):
    with tempfile.TemporaryDirectory(prefix="test-dev-avb-") as d:
        scratch=Path(d)
        key=scratch/"ephemeral-dev-only.pem"
        run("openssl","genrsa","-out",key,"4096")
        report={}
        for partition in ("product","system"):
            image=modified_partitions/(partition+"_a.img")
            stock=desc(avbtool,stock_vbmeta_dir/("vbmeta_"+partition+".img"),partition)
            data_bytes=int(stock["Image Size"].split()[0])
            logical_size=image.stat().st_size
            # avbtool verify_image resolves the signed descriptor to <partition>.img
            # in the standalone vbmeta directory; use that exact scratch filename.
            data_only=scratch/(partition+".img")
            with image.open("rb") as source,data_only.open("wb") as output:
                remaining=data_bytes
                while remaining:
                    chunk=source.read(min(remaining,4*1024*1024))
                    if not chunk:raise EOFError(partition)
                    output.write(chunk)
                    remaining-=len(chunk)
            devmeta=scratch/(partition+"-DEV-NOT-OEM-vbmeta.img")
            # avbtool creates a signed development-only standalone descriptor.
            # --do_not_generate_fec means its descriptor DOES NOT describe our
            # previously validated FEC region, and it MUST NOT be installed.
            run("python3",avbtool,"add_hashtree_footer",
                "--image",data_only,
                "--partition_name",partition,
                "--partition_size",logical_size,
                "--algorithm","SHA256_RSA4096",
                "--key",key,
                "--hash_algorithm","sha1",
                "--salt",stock["Salt"],
                "--block_size","4096",
                "--fec_num_roots","2",
                "--output_vbmeta_image",devmeta,
                "--do_not_append_vbmeta_image",
                "--do_not_generate_fec")
            info=run("python3",avbtool,"info_image","--image",devmeta)
            matching=re.search(r"(?m)^\s*Algorithm:\s*(\S+)",info)
            if not matching or matching.group(1)!="SHA256_RSA4096":
                raise ValueError("Development signature algorithm mismatch "+partition)
            new_info=scratch/(partition+"-dev-inspection.txt")
            new_info.write_text(info)
            from offline_dev_avb_prototype import properties
            new=properties(new_info)
            expected_root=hashtree_report[partition]["modified_root"]
            if new.get("Root Digest","").lower()!=expected_root:
                raise ValueError(partition+" development signed root does not match verified FEC partition")
            if new.get("Partition Name")!=partition or new.get("Salt")!=stock["Salt"]:
                raise ValueError("Development descriptor partition/salt mismatch "+partition)
            if int(new["Image Size"].split()[0])!=data_bytes:
                raise ValueError("Development descriptor protected-data-size mismatch "+partition)
            # Stock and dev signatures represent different public keys.
            # The SDK's native verifier must independently validate RSA.
            output=run("python3",avbtool,"verify_image","--image",devmeta,"--key",key)
            print("DEVELOPMENT AVB RSA VERIFIED "+partition+" "+output[-600:],flush=True)
            report[partition]={
                "signature":"SHA256_RSA4096; avbtool verify_image PASS",
                "signed_root":expected_root,
                "stock_root_changed":expected_root!=stock["Root Digest"].lower(),
                "stock_salt_preserved":True,
                "signed_descriptor_not_compatible_with_original_FEC":True,
                "OEM_key_used":False,
                "device_bootloader_acceptance":"UNKNOWN",
                "temp_signed_vbmeta_sha256":digest(devmeta)}
        print("DEVELOPMENT-KEY SIGNING TEST PASSED; NOT A TRUSTED CHAIN; DO NOT FLASH",flush=True)
        return report
