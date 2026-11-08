"""
Threat-intelligence (TI) helpers for MalSense.

1. MITRE ATT&CK for Mobile mapping - which attacker techniques an app's permissions make possible.
   Source: MITRE ATT&CK Mobile matrix, https://attack.mitre.org/matrices/mobile/
   A permission only makes a technique POSSIBLE - it does not prove the app uses it.
2. Malware family / category from VirusTotal's "popular threat classification".
3. Indicators of compromise (IOCs) export: CSV and STIX 2.1 (the standard format TI platforms
   such as MISP and OpenCTI import).
"""
import re
import uuid
from datetime import datetime, timezone

# technique id -> (name, tactic(s))
TECHNIQUES = {
    "T1636.001": ("Protected User Data: Calendar Entries", "Collection"),
    "T1636.002": ("Protected User Data: Call Log", "Collection"),
    "T1636.003": ("Protected User Data: Contact List", "Collection"),
    "T1636.004": ("Protected User Data: SMS Messages", "Collection"),
    "T1430": ("Location Tracking", "Collection, Discovery"),
    "T1429": ("Audio Capture", "Collection"),
    "T1512": ("Video Capture", "Collection"),
    "T1582": ("SMS Control", "Impact"),
    "T1616": ("Call Control", "Collection, Command and Control, Impact"),
    "T1426": ("System Information Discovery", "Discovery"),
    "T1533": ("Data from Local System", "Collection"),
    "T1417.002": ("Input Capture: GUI Input Capture", "Collection, Credential Access"),
    "T1624.001": ("Event Triggered Execution: Broadcast Receivers", "Persistence"),
    "T1541": ("Foreground Persistence", "Defense Evasion, Persistence"),
    "T1418": ("Software Discovery", "Discovery"),
}

# Android permission (short name) -> techniques it enables
PERMISSION_TECHNIQUES = {
    "READ_CALENDAR": ["T1636.001"], "WRITE_CALENDAR": ["T1636.001"],
    "READ_CALL_LOG": ["T1636.002"], "WRITE_CALL_LOG": ["T1636.002"],
    "PROCESS_OUTGOING_CALLS": ["T1636.002", "T1616"],
    "CALL_PHONE": ["T1616"], "ANSWER_PHONE_CALLS": ["T1616"],
    "READ_CONTACTS": ["T1636.003"], "WRITE_CONTACTS": ["T1636.003"],
    "READ_SMS": ["T1636.004"], "RECEIVE_SMS": ["T1636.004"], "RECEIVE_MMS": ["T1636.004"],
    "SEND_SMS": ["T1582"], "WRITE_SMS": ["T1582"],
    "ACCESS_FINE_LOCATION": ["T1430"], "ACCESS_COARSE_LOCATION": ["T1430"],
    "ACCESS_BACKGROUND_LOCATION": ["T1430"],
    "RECORD_AUDIO": ["T1429"], "CAMERA": ["T1512"],
    "READ_PHONE_STATE": ["T1426"], "READ_PHONE_NUMBERS": ["T1426"],
    "READ_EXTERNAL_STORAGE": ["T1533"], "WRITE_EXTERNAL_STORAGE": ["T1533"],
    "MANAGE_EXTERNAL_STORAGE": ["T1533"],
    "SYSTEM_ALERT_WINDOW": ["T1417.002"],
    "RECEIVE_BOOT_COMPLETED": ["T1624.001"],
    "FOREGROUND_SERVICE": ["T1541"],
    "QUERY_ALL_PACKAGES": ["T1418"], "GET_TASKS": ["T1418"],
}


def technique_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def attack_techniques(permissions):
    """[{id, name, tactic, url, permissions: [...]}, ...] for the permissions an app requests."""
    found = {}
    for p in permissions or []:
        for tid in PERMISSION_TECHNIQUES.get(p, []):
            found.setdefault(tid, []).append(p)
    return [{"id": t, "name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1], "url": technique_url(t),
             "permissions": perms} for t, perms in sorted(found.items())]


def app_permissions(details):
    """All standard permissions of a saved scan (older scans only stored the dangerous ones)."""
    return (details or {}).get("permissions") or (details or {}).get("dangerous_permissions") or []


# ----------------------------------------------------------------------------- malware family
GENERIC = {"trojan", "malware", "android", "andr", "generic", "riskware", "adware", "spyware", "pua", "fakeapp",
           "agent", "smsreg", "banker", "dropper", "downloader", "ransom", "ransomware", "hacktool", "virus",
           "worm", "backdoor", "rootkit", "unknown", "msil", "app", "apk", "gen", "artemis", "variant", "a", "b"}


def family_of(vt):
    """(family, category) from a VirusTotal result, e.g. 'trojan.joker/smsreg' -> ('joker', 'trojan').
    Returns ('', '') when VirusTotal has no label (clean or unknown files)."""
    vt = vt or {}
    family, category = vt.get("family") or "", vt.get("category") or ""
    label = (vt.get("threat_label") or "").lower()
    if label and not (family and category):
        parts = [p for p in re.split(r"[./:!\s]+", label) if p]
        if not category and parts:
            category = parts[0] if parts[0] in GENERIC else ""
        if not family:
            family = next((p for p in parts if p not in GENERIC and len(p) > 2 and not p.isdigit()), "")
    return family, category


# ----------------------------------------------------------------------------- IOCs
def ioc_rows(scans, reports, vt_confirm):
    """Malware indicators from scan logs + admin-confirmed reports, one row per SHA-256.
    A scan counts when the AI model OR >= vt_confirm antivirus engines say malware."""
    rows = {}
    for s in scans:
        d = s.details or {}
        vt = d.get("virustotal") or {}
        flagged = vt.get("flagged", 0) if vt.get("status") == "found" else 0
        if s.ml_result != "Malware" and flagged < vt_confirm:
            continue
        evidence = []
        if s.ml_result == "Malware":
            evidence.append(f"MalSense model {s.confidence:.0f}%")
        if flagged:
            evidence.append(f"VirusTotal {vt.get('detection_ratio')}")
        family, category = family_of(vt)
        row = rows.setdefault(s.file_hash, {
            "sha256": s.file_hash, "sha1": d.get("sha1", ""), "md5": d.get("md5", ""),
            "package": s.package_name or "", "app_name": d.get("app_name") or "", "family": family,
            "category": category, "risk": d.get("risk", ""), "evidence": "; ".join(evidence),
            "attack": " ".join(t["id"] for t in attack_techniques(app_permissions(d))),
            "first_seen": s.scanned_at, "last_seen": s.scanned_at, "times_seen": 0})
        row["times_seen"] += 1
        row["first_seen"] = min(row["first_seen"], s.scanned_at)
        row["last_seen"] = max(row["last_seen"], s.scanned_at)
    for r in reports:
        if r.status != "added_malware":
            continue
        row = rows.setdefault(r.file_hash, {
            "sha256": r.file_hash, "sha1": "", "md5": "", "package": "", "app_name": "", "family": "",
            "category": "", "risk": "", "evidence": "", "attack": "", "first_seen": r.created_at,
            "last_seen": r.created_at, "times_seen": 0})
        row["evidence"] = "; ".join(x for x in (row["evidence"], f"confirmed by admin (report #{r.report_id})") if x)
        row["first_seen"] = min(row["first_seen"], r.created_at)
    return sorted(rows.values(), key=lambda x: x["last_seen"], reverse=True)


IOC_COLUMNS = ["sha256", "sha1", "md5", "package", "app_name", "family", "category", "risk",
               "evidence", "attack", "first_seen", "last_seen", "times_seen"]

_NS = uuid.UUID("6f1b8a52-7c0e-4b6e-9d7a-4d616c53656e")   # fixed namespace: same file -> same STIX id


def _ts(dt):
    """STIX time stamps are UTC. Times in the database are local time (no time zone attached)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_bundle(rows):
    """STIX 2.1 bundle: one Indicator per file + one Malware object per family (+ 'indicates' links)."""
    now = _ts(datetime.now())
    identity = {"type": "identity", "spec_version": "2.1", "id": f"identity--{uuid.uuid5(_NS, 'MalSense')}",
                "created": now, "modified": now, "name": "MalSense", "identity_class": "system"}
    objects, families = [identity], {}
    for r in rows:
        hashes = [f"file:hashes.'SHA-256' = '{r['sha256']}'"]
        if r["md5"]:
            hashes.append(f"file:hashes.MD5 = '{r['md5']}'")
        ind_id = f"indicator--{uuid.uuid5(_NS, r['sha256'])}"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id, "created": now, "modified": now,
            "created_by_ref": identity["id"],
            "name": f"Malicious Android app {r['app_name'] or r['package'] or r['sha256'][:12]}",
            "description": f"Evidence: {r['evidence']}." + (f" ATT&CK: {r['attack']}." if r["attack"] else ""),
            "indicator_types": ["malicious-activity"], "pattern_type": "stix",
            "pattern": "[" + " OR ".join(hashes) + "]", "valid_from": _ts(r["first_seen"]),
            "labels": [x for x in (r["family"], r["category"]) if x]})
        if r["family"]:
            fam = families.setdefault(r["family"], {
                "type": "malware", "spec_version": "2.1", "id": f"malware--{uuid.uuid5(_NS, 'fam:' + r['family'])}",
                "created": now, "modified": now, "name": r["family"], "is_family": True,
                "malware_types": [r["category"]] if r["category"] else ["unknown"]})
            objects.append({"type": "relationship", "spec_version": "2.1",
                            "id": f"relationship--{uuid.uuid5(_NS, 'rel:' + r['sha256'])}", "created": now,
                            "modified": now, "relationship_type": "indicates", "source_ref": ind_id,
                            "target_ref": fam["id"]})
    objects += families.values()
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
