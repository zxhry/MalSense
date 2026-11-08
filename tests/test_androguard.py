"""
Sprint 4 - Step 1: Check that Androguard can read an APK (static analysis, the app is NOT run).
Usage: python tests/test_androguard.py samples/<file>.apk
"""
import sys, os, hashlib, zipfile
from loguru import logger
logger.remove()                       # hide Androguard's very long debug messages
from androguard.core.apk import APK

path = sys.argv[1] if len(sys.argv) > 1 else "samples/a2dp.Vol_137.apk"
sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()
apk = APK(path)
perms = sorted(apk.get_permissions())
with zipfile.ZipFile(path) as z:
    infos = z.infolist()

print("=== ANDROGUARD TEST ===")
print(f"File           : {os.path.basename(path)}  ({os.path.getsize(path):,} bytes)")
print(f"SHA-256        : {sha256}   <- this is what we will send to VirusTotal later")
print(f"App name       : {apk.get_app_name()}")
print(f"Package        : {apk.get_package()}")
print(f"Files in APK   : {len(infos):,} (uncompressed {sum(i.file_size for i in infos):,} bytes)")
print(f"Activities     : {len(apk.get_activities())}")
print(f"Services       : {len(apk.get_services())}")
print(f"Receivers      : {len(apk.get_receivers())}")
print(f"Permissions    : {len(perms)}")
for p in perms:
    print(f"   - {p}")