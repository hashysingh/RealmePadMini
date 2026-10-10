#!/usr/bin/env python3
"""Read-only audit of original RMP2106 AVB chain from previously extracted PAC reports.

This is a trust-chain inventory, NOT an assertion that unlocked boot accepts custom keys.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

EXPECTED = {
    "vbmeta": "VBMETA",
    "vbmeta_system": "VBMETA_SYSTEM",
    "vbmeta_product": "VBMETA_PRODUCT",
    "vbmeta_system_ext": "VBMETA_SYSTEM_EXT",
    "vbmeta_vendor": "VBMETA_VENDOR",
}
def sections(raw):
    headers = list(re.finditer(r"(?m)^\s*(Hashtree|Hash|Chain Partition|Kernel Cmdline|Prop) descriptor:\s*$", raw))
    for i, head in enumerate(headers):
        end=headers[i+1].start() if i+1<len(headers) else len(raw)
        yield head.group(1),raw[head.end():end]

def fields(s):
    return {k.strip(): v.strip() for k,v in re.findall(r"(?m)^\s*([^:\n]+?):\s*(.*?)\s*$",s) if k.strip()}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",type=Path,required=True)
    ap.add_argument("--report",type=Path,required=True)
    args=ap.parse_args()
    args.report.mkdir(parents=True,exist_ok=True)
    entries=[]
    for base, origin in EXPECTED.items():
        file=args.input/(base+"-avbtool.txt")
        if not file.is_file():raise FileNotFoundError(f"Missing original-PAC report: {file}")
        content=file.read_text(errors="replace")
        if "Minimum libavb version" not in content or "Algorithm:" not in content:
            raise ValueError(f"Unrecognized AVB report for {base}; refusing invented assumptions")
        first=content.split("Descriptors:",1)[0]
        top=fields(first)
        parsed=[]
        for typ, body in sections(content):
            info=fields(body)
            desc={"type":typ,"partition":info.get("Partition Name"),
                  "rollback_location":info.get("Rollback Index Location"),
                  "algorithm":info.get("Hash Algorithm"),
                  "public_key_fingerprint":info.get("Public key (sha1)")}
            parsed.append({k:v for k,v in desc.items() if v is not None})
        blob=args.input/(base+".img")
        if not blob.is_file() or blob.read_bytes()[:4]!=b"AVB0":
            raise ValueError(f"Original binary vbmeta missing or not AVB0: {base}")
        entry={"name":base,"pac_entry":origin,"binary_sha256":hashlib.sha256(blob.read_bytes()).hexdigest(),
               "algorithm":top.get("Algorithm"),"flags":top.get("Flags"),
               "rollback_index":top.get("Rollback Index"),
               "rollback_location":top.get("Rollback Index Location"),
               "descriptors":parsed}
        entries.append(entry)
        print(f"{base}: algorithm={entry['algorithm']}; flags={entry['flags']}; "
              f"descriptors={len(parsed)}",flush=True)
        for d in parsed:print("  "+json.dumps(d,sort_keys=True),flush=True)
    chains={(x["name"],d["partition"]) for x in entries for d in x["descriptors"]
            if d["type"]=="Chain Partition" and d.get("partition")}
    hashtrees={(x["name"],d["partition"]) for x in entries for d in x["descriptors"]
               if d["type"]=="Hashtree" and d.get("partition")}
    conclusion={
      "source":"Previously saved five vbmeta binaries and avbtool reports extracted from SHA-pinned stock PAC",
      "scope":"offline read-only inventory; no PAC redownload, no on-device modifications",
      "entries":entries,"chain_descriptors":sorted([list(x) for x in chains]),
      "hashtree_descriptors":sorted([list(x) for x in hashtrees]),
      "custom_avb_private_keys_available":False,
      "device_acceptance_of_custom_keys":"NOT TESTED",
      "unlocked_bootloader_accepts_modified_vbmeta":"NOT ESTABLISHED",
      "flashable_image_generated":False,
      "follow_up":"Confirm chain hierarchy and key trust through authentic device-specific documentation or read-only device evidence before making any installation plan"
    }
    (args.report/"stock-trust-chain.json").write_text(json.dumps(conclusion,indent=2)+"\n")
    lines=["# RMP2106 stock AVB trust-chain inventory","",
           "**Read-only. No PAC download, signing, device modifications or flashable images.**","",
           "| Stock vbmeta | Algorithm | Flags | Rollback index / location | Descriptors |",
           "|---|---|---|---|---|"]
    for e in entries:
        lines.append(f'| {e["name"]} | {e["algorithm"] or "unknown"} | {e["flags"] or "unknown"} | {e["rollback_index"] or "unknown"} / {e["rollback_location"] or "unknown"} | {len(e["descriptors"])} |')
    lines+=["","## Chain partition descriptors"]
    if chains:
        lines+=["- "+a+" -> "+b for a,b in sorted(chains)]
    else:lines+=["- None detected (inspect avbtool source reports)"]
    lines+=["","## Hashtree descriptors"]
    if hashtrees:lines+=["- "+a+" protects "+b for a,b in sorted(hashtrees)]
    else:lines+=["- None detected (inspect avbtool source reports)"]
    lines+=["","## Interpretation",
            "- A valid regenerated hashtree does not establish that a device trusts the metadata signer.",
            "- OEM private signing keys are not present in the stock firmware.",
            "- Unlocked-bootloader custom-key acceptance is **unknown** from these offline reports.",
            "- This is an inventory, not an authorization to flash modified vbmeta."]
    (args.report/"REPORT.md").write_text("\n".join(lines)+"\n")

if __name__=="__main__":main()
