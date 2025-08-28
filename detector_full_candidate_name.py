
#!/usr/bin/env python3
import sys, json, re, ast, csv
from typing import Dict, Any, Tuple

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE10_RE = re.compile(r"(?<!\d)([6-9]\d{9})(?!\d)")
AADHAAR_RE = re.compile(r"(?<!\d)(\d{4}\s?\d{4}\s?\d{4})(?!\d)")
PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])([A-PR-WYa-pr-wy][0-9]{7})(?![A-Za-z0-9])")
UPI_RE = re.compile(r"\b([A-Za-z0-9._-]{2,})@([A-Za-z]{2,})\b")
IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

PHONE_KEYS = {"phone", "contact", "mobile", "alt_phone"}
AADHAAR_KEYS = {"aadhar", "aadhaar"}
PASSPORT_KEYS = {"passport"}
UPI_KEYS = {"upi", "upi_id"}
EMAIL_KEYS = {"email"}
NAME_KEYS = {"name", "full_name"}
FIRST_NAME_KEYS = {"first_name", "firstname", "given_name"}
LAST_NAME_KEYS = {"last_name", "lastname", "surname"}
ADDRESS_KEYS = {"address", "street"}
IP_KEYS = {"ip", "ip_address"}
DEVICE_KEYS = {"device_id", "deviceid"}

def try_parse_json(s: str):
    if isinstance(s, dict):
        return s
    if s is None:
        return {}
    s = str(s).strip()
    if not s:
        return {}
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
    digits = re.sub(r"\D", "", str(num_str))
    if len(digits) < 4:
        return "X" * len(digits)
    masked_mid = "X" * (len(digits) - 4)
    out = digits[:2] + masked_mid + digits[-2:]
    if len(digits) == 12:
        return out[:4] + " " + out[4:8] + " " + out[8:]
    return out

def mask_email(email: str) -> str:
    m = EMAIL_RE.search(email or "")
    if not m:
        return email
    local, domain = email.split("@", 1)
    keep = min(2, len(local))
    return local[:keep] + "X" * max(0, len(local) - keep) + "@" + domain

def mask_name(n: str) -> str:
    if not isinstance(n, str):
        return n
    parts = n.split()
    mparts = [p[0] + "X" * max(0, len(p) - 1) for p in parts if p]
    return " ".join(mparts)

def mask_upi(u: str) -> str:
    m = UPI_RE.search(u or "")
    if not m:
        return u
    left, domain = m.group(1), m.group(2)
    keep = min(2, len(left))
    return left[:keep] + "X" * max(0, len(left) - keep) + "@" + domain

def mask_ip(ip: str) -> str:
    if not isinstance(ip, str):
        return ip
    m = IPV4_RE.search(ip or "")
    if not m:
        return ip
    parts = m.group(1).split(".")
    if len(parts) == 4:
        parts[-1] = "XX"
        return ".".join(parts)
    return ip

def mask_device(dev: str) -> str:
    if not isinstance(dev, str):
        return dev
    s = str(dev)
    if len(s) <= 4:
        return "X" * len(s)
    return s[:2] + "X" * max(0, len(s) - 6) + s[-4:]

def detect_standalone(d: Dict[str, Any]) -> set:
    hits = set()
    for k, v in d.items():
        k_l = (k or "").lower()
        s = v if isinstance(v, str) else str(v)
        if k_l in {"phone", "contact", "mobile", "alt_phone"} and PHONE10_RE.search(s): hits.add(k)
        elif k_l in {"aadhar", "aadhaar"} and AADHAAR_RE.search(s): hits.add(k)
        elif k_l in {"passport"} and PASSPORT_RE.search(s): hits.add(k)
        elif k_l in {"upi", "upi_id"} and UPI_RE.search(s): hits.add(k)
    return hits

def has_full_name(d: Dict[str, Any]) -> bool:
    n = None
    for key in {"name","full_name"}:
        if key in d and isinstance(d[key], str):
            n = d[key].strip()
            break
    if n and len(n.split()) >= 2: return True
    has_first = any(k in d and str(d[k]).strip() for k in {"first_name","firstname","given_name"})
    has_last  = any(k in d and str(d[k]).strip() for k in {"last_name","lastname","surname"})
    return has_first and has_last

def has_email(d: Dict[str, Any]) -> bool:
    for k in {"email"}:
        if k in d and EMAIL_RE.search(str(d[k])):
            return True
    return False

def has_address(d: Dict[str, Any]) -> bool:
    addr = any(k in d and str(d[k]).strip() for k in {"address","street"})
    locality = any(k in d and str(d[k]).strip() for k in {"city","pin_code","state"})
    return addr and locality

def has_ip_or_device(d: Dict[str, Any]) -> bool:
    for k in {"ip","ip_address"}:
        if k in d and isinstance(d[k], str) and IPV4_RE.search(d[k]):
            return True
    for k in {"device_id","deviceid"}:
        if k in d and str(d[k]).strip():
            return True
    return False

def combinatorial_is_pii(d: Dict[str, Any]):
    f = has_full_name(d); e = has_email(d); a = has_address(d)
    id_or_ip = has_ip_or_device(d)
    two = (1 if f else 0) + (1 if e else 0) + (1 if a else 0) >= 2
    tied = id_or_ip and (f or e or a)
    return (two or tied), {"full_name": f, "email": e, "address": a, "id_or_ip": id_or_ip}

def mask_record(d, is_pii, standalone_hits, combo_flags):
    out = dict(d)
    for k in list(d.keys()):
        kl = k.lower(); v = d[k]
        if k in standalone_hits:
            if kl in {"aadhar","aadhaar","phone","contact","mobile","alt_phone"}:
                out[k] = mask_number_keep_2_2(str(v))
            elif kl in {"passport"}:
                s = str(v); out[k] = s[:1] + "X" * max(0, len(s) - 1)
            elif kl in {"upi","upi_id"}:
                out[k] = mask_upi(str(v))
    if is_pii:
        for k in list(d.keys()):
            if k.lower() in {"name","full_name"}:
                out[k] = mask_name(str(d[k]))
        if any(k in d for k in {"first_name","firstname","given_name"}) and any(k in d for k in {"last_name","lastname","surname"}):
            for k in {"first_name","firstname","given_name"}:
                if k in d: out[k] = mask_name(str(d[k]))
            for k in {"last_name","lastname","surname"}:
                if k in d: out[k] = mask_name(str(d[k]))
        if "email" in d and d["email"]:
            out["email"] = mask_email(str(d["email"]))
        if combo_flags.get("address"):
            for k in {"address","street"}:
                if k in d and d[k]: out[k] = "[REDACTED_PII]"
        for k in {"ip","ip_address"}:
            if k in d and d[k]: out[k] = mask_ip(str(d[k]))
        for k in {"device_id","deviceid"}:
            if k in d and d[k]: out[k] = mask_device(str(d[k]))
    return out

def process_csv(in_path: str, out_path: str):
    import pandas as pd, json
    df = pd.read_csv(in_path)
    cols = {c.lower(): c for c in df.columns}
    rid_col = cols.get("record_id", list(df.columns)[0])
    data_col = cols.get("data_json", None)
    if data_col is None:
        for c in df.columns:
            if "json" in c.lower():
                data_col = c; break
    if data_col is None:
        raise ValueError("Could not find a 'Data_json' column in the CSV.")
    out_rows = []
    for _, row in df.iterrows():
        rid = row[rid_col]; raw = row[data_col]
        d = try_parse_json(raw); 
        if not isinstance(d, dict): d = {}
        standalone = detect_standalone(d)
        combo_bool, combo_flags = combinatorial_is_pii(d)
        is_pii = bool(standalone) or combo_bool
        redacted = mask_record(d, is_pii, standalone, combo_flags)
        out_rows.append({"record_id": rid, "redacted_data_json": json.dumps(redacted, ensure_ascii=False, separators=(",", ": ")), "is_pii": is_pii})
    pd.DataFrame(out_rows, columns=["record_id","redacted_data_json","is_pii"]).to_csv(out_path, index=False)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv_path>"); sys.exit(1)
    in_path = sys.argv[1]; out_path = "redacted_output_candidate_full_name.csv"
    process_csv(in_path, out_path); print(f"Done. Wrote: {out_path}")

if __name__ == "__main__":
    main()
