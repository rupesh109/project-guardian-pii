#!/usr/bin/env python3
import sys, json, re, ast, csv
from typing import Dict, Any, Tuple

# -------- Patterns --------
EMAIL_RE   = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE10_RE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")
AADHAAR_RE = re.compile(r"(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)")
PASSPORT_RE= re.compile(r"(?<![A-Za-z0-9])([A-PR-WYa-pr-wy][0-9]{7})(?![A-Za-z0-9])")
UPI_RE     = re.compile(r"\b([A-Za-z0-9._-]{2,})@([A-Za-z]{2,})\b")
IPV4_RE    = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

PHONE_KEYS = {"phone","contact","mobile","alt_phone"}
AADHAAR_KEYS={"aadhar","aadhaar"}
PASSPORT_KEYS={"passport"}
UPI_KEYS={"upi","upi_id"}
EMAIL_KEYS={"email"}
NAME_KEYS={"name","full_name"}
FIRST_NAME_KEYS={"first_name","firstname","given_name"}
LAST_NAME_KEYS ={"last_name","lastname","surname"}
ADDRESS_KEYS={"address","street"}
IP_KEYS={"ip","ip_address"}
DEVICE_KEYS={"device_id","deviceid"}

def try_parse_json(s: str):
    if isinstance(s, dict): return s
    if s is None: return {}
    s = str(s).strip()
    if not s: return {}
    try:
        return json.loads(s)
    except Exception:
        pass
    try:
        return ast.literal_eval(s)
    except Exception:
        pass
    try:
        s2 = re.sub(r"(?<!\\)'", '"', s)
        return json.loads(s2)
    except Exception:
        return {}

def mask_number_keep_2_2(num_str: str) -> str:
    digits = re.sub(r"\D","",str(num_str))
    if len(digits) < 4: return "X"*len(digits)
    out = digits[:2] + "X"*(len(digits)-4) + digits[-2:]
    return (out[:4]+" "+out[4:8]+" "+out[8:]) if len(digits)==12 else out

def mask_email(email: str) -> str:
    if not EMAIL_RE.search(email or ""): return email
    local, domain = email.split("@",1)
    keep = min(2,len(local))
    return local[:keep] + "X"*max(0,len(local)-keep) + "@" + domain

def mask_name(n: str) -> str:
    if not isinstance(n,str): return n
    return " ".join([p[0]+"X"*(len(p)-1) if p else p for p in n.split()])

def mask_upi(u: str) -> str:
    m = UPI_RE.search(u or "")
    if not m: return u
    left, domain = m.group(1), m.group(2)
    keep = min(2,len(left))
    return left[:keep]+"X"*max(0,len(left)-keep)+"@"+domain

def mask_ip(ip: str) -> str:
    m = IPV4_RE.search(ip or "")
    if not m: return ip
    parts = m.group(1).split(".")
    parts[-1] = "XX"
    return ".".join(parts)

def mask_device(dev: str) -> str:
    s = str(dev)
    return "X"*len(s) if len(s)<=4 else s[:2]+"X"*max(0,len(s)-6)+s[-4:]

def detect_standalone(d: Dict[str,Any]) -> set:
    hits=set()
    for k,v in d.items():
        kl = (k or "").lower()
        s  = v if isinstance(v,str) else str(v)
        if   kl in PHONE_KEYS    and PHONE10_RE.search(s): hits.add(k)
        elif kl in AADHAAR_KEYS  and AADHAAR_RE.search(s): hits.add(k)
        elif kl in PASSPORT_KEYS and PASSPORT_RE.search(s): hits.add(k)
        elif kl in UPI_KEYS      and UPI_RE.search(s):     hits.add(k)
    return hits

def has_full_name(d: Dict[str,Any]) -> bool:
    n=None
    for k in NAME_KEYS:
        if k in d and isinstance(d[k],str):
            n=d[k].strip(); break
    if n and len(n.split())>=2: return True
    has_first = any(k in d and str(d[k]).strip() for k in FIRST_NAME_KEYS)
    has_last  = any(k in d and str(d[k]).strip() for k in LAST_NAME_KEYS)
    return has_first and has_last

def has_email(d):   return any(k in d and EMAIL_RE.search(str(d[k])) for k in EMAIL_KEYS)
def has_address(d): 
    addr=any(k in d and str(d[k]).strip() for k in ADDRESS_KEYS)
    loc =any(k in d and str(d[k]).strip() for k in {"city","pin_code","state"})
    return addr and loc
def has_ip_or_device(d):
    if any(k in d and isinstance(d[k],str) and IPV4_RE.search(d[k]) for k in IP_KEYS): return True
    if any(k in d and str(d[k]).strip() for k in DEVICE_KEYS): return True
    return False

def combinatorial_is_pii(d: Dict[str,Any]):
    f=has_full_name(d); e=has_email(d); a=has_address(d); idip=has_ip_or_device(d)
    two = (1 if f else 0)+(1 if e else 0)+(1 if a else 0) >= 2
    tied = idip and (f or e or a)
    return (two or tied), {"full_name":f,"email":e,"address":a,"id_or_ip":idip}

def mask_record(d: Dict[str,Any], is_pii: bool, standalone_hits: set, combo_flags: Dict[str,bool]) -> Dict[str,Any]:
    out=dict(d)
    for k in list(d.keys()):
        kl=k.lower(); v=d[k]
        if k in standalone_hits:
            if kl in AADHAAR_KEYS or kl in PHONE_KEYS: out[k]=mask_number_keep_2_2(str(v))
            elif kl in PASSPORT_KEYS: out[k]=str(v)[:1]+"X"*max(0,len(str(v))-1)
            elif kl in UPI_KEYS: out[k]=mask_upi(str(v))
    if is_pii:
        for k in list(d.keys()):
            if k.lower() in NAME_KEYS: out[k]=mask_name(str(d[k]))
        if any(k in d for k in FIRST_NAME_KEYS) and any(k in d for k in LAST_NAME_KEYS):
            for k in FIRST_NAME_KEYS:
                if k in d: out[k]=mask_name(str(d[k]))
            for k in LAST_NAME_KEYS:
                if k in d: out[k]=mask_name(str(d[k]))
        if "email" in d and d["email"]: out["email"]=mask_email(str(d["email"]))
        if combo_flags.get("address"):
            for k in ADDRESS_KEYS:
                if k in d and d[k]: out[k]="[REDACTED_PII]"
        for k in IP_KEYS:
            if k in d and d[k]: out[k]=mask_ip(str(d[k]))
        for k in DEVICE_KEYS:
            if k in d and d[k]: out[k]=mask_device(str(d[k]))
    return out

def process_csv(in_path: str, out_path: str):
    # Read CSV with columns: record_id, Data_json (case-insensitive)
    with open(in_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # find columns
        cols = {c.lower(): c for c in reader.fieldnames or []}
        rid_col  = cols.get("record_id", list(reader.fieldnames)[0])
        data_col = cols.get("data_json", None)
        if data_col is None:
            for c in reader.fieldnames:
                if "json" in c.lower():
                    data_col=c; break
        if data_col is None:
            raise ValueError("Could not find a 'Data_json' column in the CSV.")
        rows_out = []
        for row in reader:
            rid = row.get(rid_col)
            raw = row.get(data_col, "")
            d = try_parse_json(raw)
            if not isinstance(d, dict): d = {}

            standalone_hits = detect_standalone(d)
            combo_bool, combo_flags = combinatorial_is_pii(d)
            is_pii = bool(standalone_hits) or combo_bool

            redacted = mask_record(d, is_pii, standalone_hits, combo_flags)
            redacted_str = json.dumps(redacted, ensure_ascii=False, separators=(",", ": "))

            rows_out.append({"record_id": rid, "redacted_data_json": redacted_str, "is_pii": str(is_pii)})

    # Write output with exact required header order
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        for r in rows_out:
            writer.writerow(r)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_path>")
        sys.exit(1)
    in_path = sys.argv[1]
    out_path = "redacted_output_candidate_full_name.csv"  # Windows-safe default
    process_csv(in_path, out_path)
    print(f"Done. Wrote: {out_path}")

if __name__ == "__main__":
    main()
