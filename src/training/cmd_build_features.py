"""
CICMalDroid 2020 - Step 2: Build a clean static feature table for the MALWARE TYPE model.
(cmd_ = CICMalDroid. The KronoDroid benign/malware model is not touched.)

Input : data/raw/cicmaldroid/CSV.zip   (read directly, never extracted)
Output: data/processed/cmd_features.csv.gz   (one row per unique app, 0/1 features + class)
        data/processed/cmd_feature_list.txt
        evidence/cmd_build_features_report.txt

Rules (so the website scanner can recalculate EVERY feature from an APK with Androguard):
  1. Keep only columns whose meaning is clear from the name and is standard Android:
       - permissions        android.* / com.android.* / com.google.android.* ... .permission.
       - intent actions     android.* ... .action.  (+ android.provider.Telephony.* e.g. SMS_RECEIVED)
       - intent categories  android.intent.category.*
       - sensitive API calls  Class:method  (e.g. SmsManager:sendTextMessage)
     App-specific names (com.yahoo..., custom permissions), smali method tags, file-type counts,
     the num_* summary columns (definition not documented) and garbled warning text are dropped.
  2. Columns whose names differ only by quotes/spaces are merged (OR).
  3. Values become 0/1 (feature present or not). Counts depend on CIC's exact extraction tool,
     presence does not - so the scanner can reproduce it.
  4. Rows: invalid APKs removed; exact duplicates (same features + class) kept once;
     feature vectors that appear under DIFFERENT classes removed (ambiguous).
  5. Columns used by fewer than MIN_APPS apps removed (no label used - unsupervised filter).
Labels come from the dynamic file's row order (checked in inspect_cicmaldroid.py).
"""
import csv, io, re, zipfile
from collections import Counter
import numpy as np
import pandas as pd

ZIP = "data/raw/cicmaldroid/CSV.zip"
STATIC = "feature_vectors_static.csv"
DYNAMIC = "feature_vectors_syscallsbinders_frequency_5_Cat.csv"
CLASS_NAMES = {1: "Adware", 2: "Banking", 3: "SMS malware", 4: "Riskware", 5: "Benign"}
MIN_APPS = 10
csv.field_size_limit(10**9)
report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

STD = ("android.", "com.android.", "com.google.android.")
def kind(raw):
    n = raw.strip().strip("'\"").strip()
    if re.fullmatch(r"[A-Za-z]+:[A-Za-z]+", n):                          return "api", n
    if not re.fullmatch(r"[A-Za-z0-9_.]+", n) or not n.startswith(STD):   return None, n
    if ".permission." in n:                                               return "perm", n
    if n.startswith("android.intent.category."):                          return "category", n
    if ".action." in n or n.startswith("android.provider.Telephony."):    return "action", n
    return None, n

with zipfile.ZipFile(ZIP) as z:
    labels = pd.read_csv(z.open(DYNAMIC), usecols=["Class"])["Class"].to_numpy()

with zipfile.ZipFile(ZIP) as z:
    reader = csv.reader(io.TextIOWrapper(z.open(STATIC), encoding="utf-8", errors="replace", newline=""))
    header = next(reader)
    valid_col = header.index("is_valid_APK")
    keep = {}                                                  # clean name -> list of raw column indexes
    kinds = {}
    for i, h in enumerate(header):
        k, name = kind(h)
        if k:
            keep.setdefault(name, []).append(i); kinds[name] = k
    names = sorted(keep, key=lambda n: (["perm", "action", "category", "api"].index(kinds[n]), n))
    groups = [np.array(keep[n]) for n in names]
    X = np.zeros((len(labels), len(names)), dtype=np.uint8)
    valid = np.zeros(len(labels), dtype=bool)
    for r, row in enumerate(reader):
        a = np.asarray(row)
        nz = (a != "") & (a != "0") & (a != "0.0") & (a != "False")
        X[r] = [nz[g].any() for g in groups]
        valid[r] = row[valid_col] == "True"

merged = sum(len(v) - 1 for v in keep.values())
log("=== CICMalDroid 2020 - STEP 2: BUILD STATIC FEATURE TABLE (malware type model) ===")
log(f"Start: {len(labels):,} apps x {len(header):,} columns")
log(f"Columns kept by name rule: {len(names):,} (from {sum(len(v) for v in keep.values()):,} raw columns; "
    f"{merged} merged because they differed only by quotes/spaces)")
log("   " + ", ".join(f"{k}: {sum(kinds[n] == k for n in names):,}" for k in ["perm", "action", "category", "api"]))
log("")

df = pd.DataFrame(X, columns=names)
df["class"] = labels
log(f"Invalid APKs removed: {int((~valid).sum()):,}")
df = df[valid].reset_index(drop=True)

feat = names
dup_same = df.duplicated(feat + ["class"]).sum()
df = df.drop_duplicates(feat + ["class"]).reset_index(drop=True)
amb_mask = df.duplicated(feat, keep=False)
log(f"Exact duplicates removed (same features + same class): {int(dup_same):,}")
log(f"Ambiguous rows removed (same features, different class): {int(amb_mask.sum()):,}")
df = df[~amb_mask].reset_index(drop=True)

used = df[feat].sum()
feat = [f for f in feat if used[f] >= MIN_APPS]
log(f"Columns used by fewer than {MIN_APPS} apps removed: {len(names) - len(feat):,} -> {len(feat):,} features remain")
log("   " + ", ".join(f"{k}: {sum(kinds[n] == k for n in feat):,}" for k in ["perm", "action", "category", "api"]))
empty = (df[feat].sum(axis=1) == 0)
log(f"Apps with none of the kept features: {int(empty.sum()):,} (kept - 'no features' is information too)")
log("")
log("FINAL per class:")
counts = df["class"].map(CLASS_NAMES).value_counts().reindex(CLASS_NAMES.values())
log(counts.to_string())
log(f"Total: {len(df):,} unique apps | {len(feat)} features (all 0/1)")
log("")
log("All 34-ish sensitive API features kept: " + ", ".join(f for f in feat if kinds[f] == "api"))
log("")
mal = df[df["class"] != 5]
top = (mal.groupby("class")[feat].mean().T)
top.columns = [CLASS_NAMES[c] for c in top.columns]
spread = (top.max(axis=1) - top.min(axis=1)).sort_values(ascending=False)
log("Features that differ most between the 4 malware types (share of apps using it):")
log(top.loc[spread.index[:15]].round(2).rename(index=lambda s: s.replace("android.permission.", "perm:")
                                                 .replace("android.intent.action.", "action:")).to_string())

df[feat + ["class"]].to_csv("data/processed/cmd_features.csv.gz", index=False)
open("data/processed/cmd_feature_list.txt", "w").write("\n".join(feat))
with open("evidence/cmd_build_features_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print("\nSaved: data/processed/cmd_features.csv.gz, cmd_feature_list.txt, evidence/cmd_build_features_report.txt")
