"""
CICMalDroid 2020 - Step 1: Inspect the STATIC feature file (nothing is changed or removed yet).
Input : data/raw/cicmaldroid/CSV.zip  (read directly from the zip - the 596 MB CSV is never extracted)
          - feature_vectors_static.csv                      : static features, 11,598 rows, NO label column
          - feature_vectors_syscallsbinders_frequency_5_Cat.csv : dynamic features, has the 'Class' label
Output: evidence/cicmaldroid_inspection.txt

Why this step matters: the static file ships WITHOUT labels. The dynamic file has the same number of
rows, sorted in 5 class blocks. This script checks whether the static rows follow the same order
before those labels are used (sanity check, not proof - the files share no ID/hash column).
"""
import csv, io, re, zipfile, hashlib
from collections import Counter
import numpy as np
import pandas as pd

ZIP = "data/raw/cicmaldroid/CSV.zip"
STATIC = "feature_vectors_static.csv"
DYNAMIC = "feature_vectors_syscallsbinders_frequency_5_Cat.csv"
CLASS_NAMES = {1: "Adware", 2: "Banking", 3: "SMS malware", 4: "Riskware", 5: "Benign"}   # from the CIC website
csv.field_size_limit(10**9)
report = []
def log(msg=""):
    print(msg); report.append(str(msg))

def group(name):
    """Rough feature group from the column name (CICMalDroid column names have no group prefix)."""
    n = name.strip()
    if not n:                                                   return "index"
    if "=>" in n:                                               return "method tags (smali + opcode)"
    if re.fullmatch(r"[A-Za-z]+:[A-Za-z]+", n):                 return "sensitive API calls"
    if ".permission." in n:                                     return "permissions"
    if ".intent.action." in n or ".action." in n:               return "intent actions"
    if ".intent.category." in n:                                return "intent categories"
    if n.startswith(("num_", "is_valid", "dynamic_code", "native_code", "reflection",
                     "ascii_obfuscation", "version_code", "main_activity", "antagonist")):
                                                                return "summary / metadata"
    if re.fullmatch(r"[A-Z0-9_]{2,12}", n):                     return "file types / misc tags"
    if " " in n or "+A" in n or "'" in n:                       return "junk (manifest warning text)"
    return "other names (services, receivers, packages...)"

# ---- 1. Labels from the dynamic file ----
with zipfile.ZipFile(ZIP) as z:
    dyn = pd.read_csv(z.open(DYNAMIC), usecols=["Class"])
labels = dyn["Class"].to_numpy()
blocks = []                                                     # [class, start_row, end_row]
for i, c in enumerate(labels):
    if not blocks or blocks[-1][0] != c:
        blocks.append([c, i, i])
    blocks[-1][2] = i

# ---- 2. Stream the static file once ----
with zipfile.ZipFile(ZIP) as z:
    reader = csv.reader(io.TextIOWrapper(z.open(STATIC), encoding="utf-8", errors="replace", newline=""))
    header = next(reader)
    n_cols = len(header)
    groups = [group(h) for h in header]
    watch = ["num_permissions", "num_services", "num_receivers", "num_intent_actions", "num_files",
             "is_valid_APK", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
             "android.permission.READ_SMS", "android.permission.INTERNET", "SmsManager:sendTextMessage",
             "TelephonyManager:getDeviceId"]
    widx = {w: header.index(w) for w in watch if w in header}
    used = np.zeros(n_cols, dtype=np.int64)                     # rows where the column is non-empty and non-zero
    nonempty = np.zeros(n_cols, dtype=np.int64)
    values = Counter()
    seen, dup_rows, rows = {}, 0, []
    for r, row in enumerate(reader):
        a = np.asarray(row[1:])
        ne = a != ""
        nz = ne & (a != "0") & (a != "0.0") & (a != "False")
        nonempty[1:] += ne
        used[1:] += nz
        if r < 300:
            values.update(a[ne].tolist())
        h = hashlib.md5("\x1f".join(row[1:]).encode()).hexdigest()
        if h in seen:
            dup_rows += 1
        seen.setdefault(h, []).append(r)
        rows.append({w: row[i] for w, i in widx.items()} | {"_n_nonempty": int(ne.sum())})
n_rows = len(rows)
info = pd.DataFrame(rows)
for c in info.columns:
    if c not in ("is_valid_APK", "_n_nonempty"):
        info[c] = pd.to_numeric(info[c], errors="coerce")

log("=== CICMalDroid 2020 - STATIC FEATURES - INSPECTION ===")
log(f"Static file : {n_rows:,} rows x {n_cols:,} columns (first column = row index)")
log(f"Dynamic file: {len(labels):,} rows, label column 'Class'")
log("")
log("!! The static file has NO label column. Labels exist only in the dynamic files.")
log("   Class blocks in the dynamic file (rows are sorted by class):")
for c, s, e in blocks:
    log(f"     Class {c} = {CLASS_NAMES.get(c, '?'):<12}: rows {s:>5,} - {e:>5,}  ({e - s + 1:,} apps)")
log(f"   Same row count in both files: {n_rows == len(labels)}")
log("")

# ---- 3. Feature groups ----
log("Column groups (approximate - grouped by the shape of the column name):")
g = pd.DataFrame({"group": groups[1:], "used_by": used[1:]})
summary = g.groupby("group").agg(columns=("used_by", "size"),
                                 used_by_10plus_apps=("used_by", lambda s: int((s >= 10).sum())))
log(summary.sort_values("columns", ascending=False).to_string())
log("")
log("Feature sparsity (how many apps use each column):")
for t in [0, 1, 10, 100, 1000]:
    log(f"   columns used by <= {t:>4} apps: {(used[1:] <= t).sum():>6,} of {n_cols - 1:,}")
log(f"   -> only {(used[1:] >= 10).sum():,} columns are used by at least 10 apps")
log("")
log("Value formats seen (first 300 rows): " + ", ".join(f"'{v}' x{n:,}" for v, n in values.most_common(12)))
log("   -> mix of '1' and '1.0', and counts (e.g. 2.0, 5.0), not only 0/1 flags. Empty cell = feature absent.")
log("")

# ---- 4. Invalid APKs and duplicates ----
invalid = info["is_valid_APK"] != "True"
log(f"Rows not marked is_valid_APK=True: {int(invalid.sum()):,} (these rows are almost completely empty: "
    f"median {int(info.loc[invalid, '_n_nonempty'].median()) if invalid.any() else 0} non-empty cells)")
log(f"Duplicate rows (identical static features): {dup_rows:,}")
groups_dup = [r for r in seen.values() if len(r) > 1]
mixed = [r for r in groups_dup if len({labels[i] for i in r}) > 1]
inv_set = set(np.flatnonzero(invalid.to_numpy()))
log(f"   {len(groups_dup):,} groups of identical rows; {sum(1 for r in groups_dup if r[0] in inv_set)} of them are the empty invalid rows")
log(f"   groups whose rows have DIFFERENT assumed classes: {len(mixed):,} ({sum(len(r) for r in mixed):,} rows)")
log(f"   rows left if each valid group keeps one copy: {len(seen) - sum(1 for r in seen.values() if r[0] in inv_set):,}")
log("")

# ---- 5. Sanity check: does the static row order follow the dynamic class blocks? ----
info["assumed_class"] = labels[:n_rows]
valid = info[~invalid].copy()
for c in ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
          "android.permission.INTERNET", "SmsManager:sendTextMessage", "TelephonyManager:getDeviceId"]:
    if c in valid:
        valid[c] = (valid[c].fillna(0) > 0).astype(int)
log("Sanity check - profile of each ASSUMED class block (valid APKs only):")
cols = [c for c in ["num_permissions", "num_receivers", "android.permission.SEND_SMS",
                    "android.permission.RECEIVE_SMS", "android.permission.READ_SMS",
                    "SmsManager:sendTextMessage", "TelephonyManager:getDeviceId"] if c in valid]
prof = valid.groupby("assumed_class")[cols].mean().round(2)
prof.index = [f"{i} {CLASS_NAMES.get(i, '')}" for i in prof.index]
prof.columns = [c.replace("android.permission.", "").replace("SmsManager:", "").replace("TelephonyManager:", "")
                for c in prof.columns]
prof.insert(0, "apps", valid.groupby("assumed_class").size().values)
log(prof.to_string())
log("   (permission/API columns show the share of apps using them, e.g. 0.80 = 80%)")
log("")
log("Change-point check - share of apps with SEND_SMS in windows of 200 rows around each block edge:")
s = (info["android.permission.SEND_SMS"].fillna(0) > 0).astype(int) if "android.permission.SEND_SMS" in info else None
if s is not None:
    for c, st, _ in blocks[1:]:
        before, after = s.iloc[max(0, st - 200):st].mean(), s.iloc[st:st + 200].mean()
        log(f"   edge at row {st:>5,} (class {blocks[[b[0] for b in blocks].index(c) - 1][0]} -> {c}): "
            f"{before:.2f} -> {after:.2f}")
log("")
log("Reading the check: if the static rows follow the class blocks, the profiles should differ clearly")
log("between blocks (e.g. SMS malware highest for SEND_SMS/sendTextMessage, Benign lowest) and the")
log("share should jump at the block edges. Labels are still an ASSUMPTION based on row order -")
log("state this as a limitation in the report.")

with open("evidence/cicmaldroid_inspection.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print("\nSaved: evidence/cicmaldroid_inspection.txt")
