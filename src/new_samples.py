"""
New training samples added by the admin (from APKs users reported).

The original KronoDroid dataset (data/processed/kd_features.csv) is NEVER changed.
New samples are kept in their own file, data/new_samples.csv, one row per APK:
    sha256, label (1 = malware, 0 = benign), source, added_at, <the 158 scanner features>
When the admin presses "Retrain model", train_scanner_model.py trains on
KronoDroid's training part + these new samples, and still tests on the SAME KronoDroid test set,
so the new accuracy can be compared fairly with the old one.
"""
import os
from datetime import datetime

import pandas as pd

BASE = os.path.join(os.path.dirname(__file__), "..")
PATH = os.path.join(BASE, "data", "new_samples.csv")
META = ["sha256", "label", "source", "added_at"]


def load():
    """All new samples as a DataFrame (empty if none were added yet)."""
    if not os.path.exists(PATH):
        return pd.DataFrame(columns=META)
    return pd.read_csv(PATH, dtype={"sha256": str})


def add_sample(apk_path, label, sha256, source=""):
    """Extract the 158 features from an APK and store them with the admin's label (1 malware / 0 benign).
    Adding the same APK again just updates its label. Raises an error if the APK cannot be read."""
    import malsense_scanner                                   # imported here: loading the model is slow
    features, _ = malsense_scanner.extract_features(apk_path)
    row = {"sha256": sha256, "label": int(label), "source": source[:100],
           "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    row |= {f: features[f] for f in malsense_scanner.BUNDLE["features"]}
    df = load()
    df = df[df["sha256"] != sha256]                           # no duplicates
    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    os.makedirs(os.path.dirname(PATH), exist_ok=True)
    df.to_csv(PATH, index=False)
    return len(df)


def remove_sample(sha256):
    df = load()
    if len(df):
        df[df["sha256"] != sha256].to_csv(PATH, index=False)


def summary(trained_at=None):
    """Counts for the admin ML-model page. 'waiting' = added after the model was last trained."""
    df = load()
    s = {"total": len(df), "malware": int((df["label"] == 1).sum()) if len(df) else 0,
         "benign": int((df["label"] == 0).sum()) if len(df) else 0, "waiting": len(df)}
    if trained_at and len(df):
        s["waiting"] = int((pd.to_datetime(df["added_at"]) > pd.to_datetime(trained_at)).sum())
    return s
