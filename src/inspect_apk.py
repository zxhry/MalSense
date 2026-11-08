"""
Diagnose a FALSE NEGATIVE: why did the AI model call an APK "safe" when VirusTotal says malware?
Compares what the model CAN see (permissions, sizes, components) with code-level tricks it CANNOT see.
Usage : python src/inspect_apk.py path/to/file.apk
"""
import os, sys, zipfile, re
from loguru import logger
logger.remove()
from androguard.core.apk import APK
from malsense_scanner import scan_apk
from virustotal_check import vt_lookup

# Code-level tricks that are common in Android malware - but NOT features in the KronoDroid model
CODE_SIGNS = {
    b"Ldalvik/system/DexClassLoader;":          "Loads extra code at run time (DexClassLoader)",
    b"Ldalvik/system/InMemoryDexClassLoader;":  "Loads hidden code straight from memory",
    b"Ldalvik/system/PathClassLoader;":         "Loads code from another file (PathClassLoader)",
    b"Ljava/lang/reflect/Method;":              "Uses reflection (calls functions by name - hides behaviour)",
    b"Ljavax/crypto/Cipher;":                   "Uses encryption/decryption (can hide strings or payloads)",
    b"Ljava/lang/Runtime;":                     "Can run shell commands (Runtime.exec)",
    b"loadLibrary":                             "Loads native C/C++ code",
    b"Landroid/telephony/SmsManager;":          "Can send SMS in code",
    b"getDeviceId":                             "Reads the phone's device ID in code",
}
HIDDEN_EXT = (".dex", ".jar", ".apk", ".so", ".bin", ".dat", ".enc")


def main(path):
    apk = APK(path)
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        dex_files = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
        code = b"".join(z.read(n) for n in dex_files)

    r = scan_apk(path)
    print("=" * 70)
    print(f"File     : {os.path.basename(path)}   ({apk.get_package()})")
    print(f"AI model : {r['verdict']}  (malware probability {r['malware_probability']:.1%})")
    vt = vt_lookup(r["sha256"])
    if vt.get("status") == "found":
        print(f"VirusTotal: {vt['detection_ratio']} engines   label: {vt.get('threat_label') or '-'}")
    else:
        print(f"VirusTotal: {vt.get('message', vt.get('status'))}")

    print("\n--- 1. What the AI model SEES (KronoDroid features) ---")
    perms = sorted(set(apk.get_permissions()))
    print(f"Permissions requested : {len(perms)}")
    for p in perms:
        print(f"   - {p}")
    print(f"Activities / services / receivers : {len(apk.get_activities())} / "
          f"{len(apk.get_services())} / {len(apk.get_receivers())}")
    print(f"Files inside APK : {len(names)}")
    print("Top reasons the model gave (SHAP):")
    for e in r["explanation"][:5]:
        print(f"   {'+' if e['direction'] == 'malware' else '-'} {e['label']}: {e['value']}")

    print("\n--- 2. What the AI model CANNOT see (code-level signs) ---")
    found = [txt for sig, txt in CODE_SIGNS.items() if sig in code]
    for txt in found:
        print(f"   [!] {txt}")
    print(f"   Code files (dex): {len(dex_files)}  {'[!] more than one - code split or packed' if len(dex_files) > 1 else ''}")
    native = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    print(f"   Native libraries (.so): {len(native)}  {native[:3]}")
    hidden = [n for n in names if n.startswith(("assets/", "res/raw/")) and n.lower().endswith(HIDDEN_EXT)]
    print(f"   Code/data hidden in assets: {len(hidden)}  {hidden[:5]}")
    if not found and not native and not hidden:
        print("   (no obvious code-level tricks found)")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python src/inspect_apk.py path/to/file.apk")
    main(sys.argv[1])