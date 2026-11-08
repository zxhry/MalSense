"""
Sprint 4 - Step 5: Combine the ML model and VirusTotal into ONE result (Figure 3.2, Stage 6).
Usage : python src/final_verdict.py samples/<file>.apk     (full scan: model + VirusTotal)
        python src/final_verdict.py --test-rules           (shows every decision rule with example inputs)
Later, Flask will import full_scan() from this file.
"""
import sys, os
from malsense_scanner import scan_apk
from virustotal_check import vt_lookup

VT_CONFIRM = 5        # >= 5 engines flagging a file is a common "confirmed malicious" cut-off in research

ACTIONS = {
    "HIGH":   "Do NOT install this app. If it is already installed, uninstall it, then change "
              "passwords used on this phone and check your bank/SMS activity.",
    "MEDIUM": "Be careful. Only install if it comes from the official Play Store or the developer's "
              "own website, and review the permissions it asks for before allowing them.",
    "LOW":    "No threat found. Still only grant the permissions the app really needs.",
}


# The 5 decision rules, in plain words (also shown to users on the results page)
RULES = [
    (1, f"{VT_CONFIRM} or more antivirus engines flag the file", "HIGH"),
    (2, f"The AI model says malware AND 1-{VT_CONFIRM - 1} antivirus engines agree", "HIGH"),
    (3, "The AI model says malware, but no antivirus engine confirms it", "MEDIUM"),
    (4, f"The AI model says safe, but 1-{VT_CONFIRM - 1} antivirus engines flag it", "MEDIUM"),
    (5, "The AI model says safe and no antivirus engine flags it", "LOW"),
]


def rule_id(verdict, vt):
    """Which of the 5 RULES applies. Used by combine() AND the results page, so they always match."""
    found = vt.get("status") == "found"
    f = (vt.get("flagged") or 0) if found else 0
    ml_malware = verdict == "MALWARE"
    if f >= VT_CONFIRM:
        return 1
    if ml_malware and f >= 1:
        return 2
    if ml_malware:
        return 3
    if f >= 1:
        return 4
    return 5


def combine(model, vt):
    """model = {'verdict', 'malware_probability'};  vt = result of vt_lookup().
    Returns (risk level, reason)."""
    p = model["malware_probability"]
    found = vt.get("status") == "found"
    f = vt.get("flagged", 0) if found else 0
    vt_txt = f"VirusTotal {vt['detection_ratio']}" if found else "VirusTotal has no record"
    prob = f"malware probability {p:.1%}"
    rule = rule_id(model["verdict"], vt)
    risk = RULES[rule - 1][2]
    reason = {
        1: (f"{f} antivirus engines confirm this file is malicious ({vt_txt}), and the AI model agrees ({prob})"
            if model["verdict"] == "MALWARE" else
            f"{f} antivirus engines confirm this file is malicious ({vt_txt}), "
            f"even though the AI model did not detect it ({prob})"),
        2: f"The AI model says malware ({prob}) and some engines agree ({vt_txt})",
        3: (f"The AI model says malware ({prob}) but antivirus engines do not confirm ({vt_txt}). "
            "It may be new malware - or a false alarm"),
        4: f"The AI model says safe ({prob}) but {f} engine(s) flag it ({vt_txt})",
        5: (f"The AI model says safe ({prob}) and no engine flags it ({vt_txt})" if found else
            f"The AI model says safe ({prob}); not verified by VirusTotal ({vt.get('message', '')})"),
    }[rule]
    return risk, reason


def full_scan(apk_path):
    model = scan_apk(apk_path)
    vt = vt_lookup(model["sha256"])
    risk, reason = combine(model, vt)
    return {**model, "virustotal": vt, "risk": risk, "reason": reason, "action": ACTIONS[risk]}


def test_rules():
    """Print every rule with made-up inputs so each branch can be checked without real malware."""
    B = {"verdict": "BENIGN", "malware_probability": 0.06}
    M = {"verdict": "MALWARE", "malware_probability": 0.93}
    def vt(n, tot=66):
        return {"status": "found", "flagged": n, "detection_ratio": f"{n}/{tot}"}
    NF = {"status": "not_found", "message": "VirusTotal has never seen this file"}
    cases = [("Model MALWARE, VT 40/66", M, vt(40)), ("Model BENIGN, VT 12/66", B, vt(12)),
             ("Model MALWARE, VT 2/66", M, vt(2)),  ("Model MALWARE, VT 0/66", M, vt(0)),
             ("Model MALWARE, VT not found", M, NF), ("Model BENIGN, VT 2/66", B, vt(2)),
             ("Model BENIGN, VT 0/66", B, vt(0)),   ("Model BENIGN, VT not found", B, NF)]
    print("=== DECISION RULE TEST (example inputs, no real files) ===")
    for name, m, v in cases:
        risk, reason = combine(m, v)
        print(f"{name:<30} -> {risk:<6} | {reason}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test-rules":
        test_rules()
        sys.exit()
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/a2dp.Vol_137.apk"
    r = full_scan(path)
    vt = r["virustotal"]
    print("=== MALSENSE FULL SCAN ===")
    print(f"App            : {r['app_name']} ({r['package']})")
    print(f"1. ML model    : {r['verdict']} (malware probability {r['malware_probability']:.1%})")
    if vt["status"] == "found":
        print(f"2. VirusTotal  : {vt['detection_ratio']} engines flagged it  {vt['threat_label']}")
    else:
        print(f"2. VirusTotal  : {vt['status'].upper()} - {vt['message']}")
    print(f"Dangerous perms: {', '.join(r['dangerous_permissions']) or 'none'}")
    print()
    print(f">>> RISK LEVEL : {r['risk']}")
    print(f"    Why        : {r['reason']}")
    print(f"    What to do : {r['action']}")