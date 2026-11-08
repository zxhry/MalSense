"""
Malware TYPE model - recalculate the 369 CICMalDroid features from an APK with Androguard.
Used by the website scanner (same rules as cmd_build_features.py: every feature is 0/1).

How each feature group is found (matches how CICMalDroid's columns behave - see notes):
  permissions        requested in AndroidManifest.xml                       (APK.get_permissions)
  intent actions     declared in the manifest OR used as a string in the code (CIC counted code strings:
  intent categories  e.g. android.intent.action.VIEW is in 98% of benign apps, which only happens if
                     strings inside the code count, not just the manifest)
  sensitive API      the code references the method, e.g. Landroid/telephony/SmsManager;->sendTextMessage
                     (read from the DEX method table - no slow full code analysis needed)

Usage:  python src/cmd_extract.py samples/a2dp.Vol_137.apk   (also prints the predicted type)
"""
import sys, time
from androguard.core.apk import APK
from androguard.core.dex import DEX
try:
    from loguru import logger; logger.remove()       # Androguard 4 logs a lot - keep the console clean
except Exception:
    pass

FEATURE_FILE = "data/processed/cmd_feature_list.txt"
# Calls like getFilesDir() are often made through a subclass (Activity, Service...), so for
# Context methods those class names count too.
CLASS_ALIASES = {"Context": {"Context", "ContextWrapper", "ContextThemeWrapper", "Activity", "Service",
                             "Application", "AppCompatActivity", "FragmentActivity", "IntentService"}}


def load_features(path=FEATURE_FILE):
    return [f for f in open(path, encoding="utf-8").read().splitlines() if f]


def _simple_class(descriptor):
    """'Landroid/telephony/SmsManager;' -> 'SmsManager' (inner classes keep the outer name)."""
    return descriptor.strip("L;").split("/")[-1].split("$")[0]


def extract(apk_path, features=None, apk=None):
    """Return ({feature: 0/1}, {"perm": [...], "action": [...], "category": [...], "api": [...]})."""
    features = features or load_features()
    a = apk or APK(apk_path)
    perms = set(a.get_permissions())

    # manifest intent filters (every component type)
    manifest = set()
    xml = a.get_android_manifest_xml()
    if xml is not None:
        ns = "{http://schemas.android.com/apk/res/android}name"
        for tag in ("action", "category"):
            for el in xml.iter(tag):
                if el.get(ns):
                    manifest.add(el.get(ns))

    strings, calls = set(), set()                    # strings in the code, (Class, method) references
    for raw in a.get_all_dex():
        d = DEX(raw)
        strings.update(d.get_strings())
        for m in d.get_methods_id_item().get_obj():
            calls.add((_simple_class(m.get_class_name()), m.get_name().lower()))
    call_classes = {}
    for cls, meth in calls:
        call_classes.setdefault(cls, set()).add(meth)

    out, found = {}, {"perm": [], "action": [], "category": [], "api": []}
    for f in features:
        if ":" in f:                                  # sensitive API, e.g. SmsManager:sendTextMessage
            cls, meth = f.split(":")
            meth = meth.lower()
            hit = any(m.startswith(meth)              # prefix: CIC's 'requestLocationUpdate' = requestLocationUpdates
                      for c in CLASS_ALIASES.get(cls, {cls}) for m in call_classes.get(c, ()))
            group = "api"
        elif ".permission." in f:
            hit, group = f in perms, "perm"
        else:
            hit = f in manifest or f in strings
            group = "category" if ".category." in f else "action"
        out[f] = int(hit)
        if hit:
            found[group].append(f)
    return out, found


def predict_type(vec, model_path="models/cmd_type_model.json", info_path="models/cmd_type_model_info.json"):
    """Return [(type, probability), ...] sorted from most to least likely."""
    import json
    import numpy as np
    from xgboost import XGBClassifier
    info = json.load(open(info_path))
    m = XGBClassifier(); m.load_model(model_path)
    p = m.predict_proba(np.array([[vec[f] for f in info["features"]]]))[0]
    return sorted(zip(info["types"], p.round(3).tolist()), key=lambda t: -t[1])


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "samples/a2dp.Vol_137.apk"
    t = time.time()
    vec, found = extract(path)
    print(f"{path}: {sum(vec.values())} of {len(vec)} features present ({time.time() - t:.1f} s)")
    for g, items in found.items():
        print(f"  {g:<9} {len(items):>3}: " + ", ".join(i.replace('android.permission.', '')
                                                       .replace('android.intent.action.', '') for i in items[:12])
              + (" ..." if len(items) > 12 else ""))
    print("  Malware type (only meaningful if the main model says MALWARE): " +
          ", ".join(f"{t} {p:.0%}" for t, p in predict_type(vec)))
