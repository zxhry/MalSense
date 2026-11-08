"""
Sprint 4 - Step 3: The MalSense scanner - APK file -> 158 features -> XGBoost prediction.
The APK is only READ (static analysis); it is never installed or run.
Usage : python src/malsense_scanner.py samples/<file>.apk
Later, Flask will import scan_apk() from this file.
"""
import os, sys, hashlib, zipfile
import joblib
import pandas as pd
from loguru import logger
logger.remove()                                   # hide Androguard debug messages
from androguard.core.apk import APK
from explain import explain

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "malsense_scanner.joblib")
BUNDLE = joblib.load(MODEL_PATH)


def reload_bundle():
    """Load the model file again (used after the admin retrains the model)."""
    global BUNDLE
    BUNDLE = joblib.load(MODEL_PATH)
    return BUNDLE
# Permission prefixes that KronoDroid treats as standard (short name = last part after the dot)
STANDARD_PREFIXES = ("android.permission.", "com.android.launcher.permission.",
                     "com.android.alarm.permission.", "com.android.voicemail.permission.")


def extract_features(apk_path):
    """Return (features dict, info dict) for one APK, calculated the same way as KronoDroid."""
    apk = APK(apk_path)
    kd_perms = set(BUNDLE["kd_permissions"])
    levels = BUNDLE["permission_levels"]

    requested = sorted(set(apk.get_permissions()))
    standard, custom = [], []
    for p in requested:
        short = p.split(".")[-1]
        if p.startswith(STANDARD_PREFIXES) and short in kd_perms:
            standard.append(short)
        else:
            custom.append(p)

    with zipfile.ZipFile(apk_path) as z:
        entries = z.infolist()

    f = {name: 0 for name in BUNDLE["features"]}
    for short in standard:
        if short in f:                            # the 20 never-used permissions are not model features
            f[short] = 1
    f["nr_permissions"] = len(standard)
    f["normal"] = sum(levels[p] == "normal" for p in standard)
    f["dangerous"] = sum(levels[p] == "dangerous" for p in standard)
    f["signature"] = sum(levels[p] == "signature" for p in standard)
    f["nr_custom"] = len(custom)
    f["custom_yes"] = int(len(custom) > 0)
    f["total_perm"] = len(standard) + len(custom)
    f["CFileSize"] = os.path.getsize(apk_path)
    f["UFileSize"] = sum(e.file_size for e in entries)
    f["FilesInsideAPK"] = len(entries)
    f["Activities"] = len(apk.get_activities())
    f["NrServices"] = len(apk.get_services())

    content = open(apk_path, "rb").read()
    info = {"app_name": apk.get_app_name(), "package": apk.get_package(),
            "sha256": hashlib.sha256(content).hexdigest(),
            "sha1": hashlib.sha1(content).hexdigest(),             # extra hashes for the report (IOCs)
            "md5": hashlib.md5(content).hexdigest(),
            "permissions": standard,
            "dangerous_permissions": [p for p in standard if levels[p] == "dangerous"],
            "custom_permissions": custom,
            "min_sdk": apk.get_min_sdk_version(),            # shown on the results page
            "file_size": os.path.getsize(apk_path)}
    return f, info


def scan_apk(apk_path):
    """Scan one APK and return a result dictionary."""
    features, info = extract_features(apk_path)
    X = pd.DataFrame([features])[BUNDLE["features"]]
    prob = float(BUNDLE["model"].predict_proba(BUNDLE["preprocess"].transform(X))[0, 1])
    verdict = "MALWARE" if prob >= BUNDLE["threshold"] else "BENIGN"
    return {**info, "verdict": verdict, "malware_probability": round(prob, 4),
            "features": features,
            "explanation": explain(BUNDLE, features)}          # Explainable AI: why this decision


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/a2dp.Vol_137.apk"
    r = scan_apk(path)
    f = r["features"]
    print("=== MALSENSE SCAN ===")
    print(f"File        : {os.path.basename(path)}")
    print(f"App         : {r['app_name']} ({r['package']})")
    print(f"SHA-256     : {r['sha256']}")
    print(f"Permissions : {f['total_perm']} total = {f['nr_permissions']} standard "
          f"({f['normal']} normal, {f['dangerous']} dangerous, {f['signature']} signature) + {f['nr_custom']} custom")
    print(f"APK details : {f['FilesInsideAPK']} files, {f['Activities']} activities, {f['NrServices']} services")
    print(f"Dangerous permissions requested: {', '.join(r['dangerous_permissions']) or 'none'}")
    print(f"Features sent to model: {len(BUNDLE['features'])} "
          f"({sum(v != 0 for v in f.values())} non-zero)")
    print()
    print(f">>> VERDICT: {r['verdict']}  (malware probability {r['malware_probability']:.1%})")
    print("\nWhy? (Explainable AI - top reasons)")
    for e in r["explanation"]:
        arrow = "-> MALWARE" if e["direction"] == "malware" else "-> SAFE   "
        print(f"  {arrow} {e['score']:+.2f}  {e['label']} ({e['value']})")