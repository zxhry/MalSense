"""
New dataset - Step 1: Inspect KronoDroid (real-device version).
Input : data/raw/kronodroid/real_malware_v1.csv, real_legitimate_v1.csv  (unzipped)
Output: data/processed/kronodroid_combined.csv, evidence/kronodroid_inspection.txt
Nothing is removed yet - this step only combines the two files and describes the data.
"""
import os
import pandas as pd

RAW = "data/raw/kronodroid"
os.makedirs("data/processed", exist_ok=True)
report = []
def log(msg=""):
    print(msg); report.append(str(msg))

mal = pd.read_csv(f"{RAW}/real_malware_v1.csv", low_memory=False)
ben = pd.read_csv(f"{RAW}/real_legitimate_v1.csv", low_memory=False)
df = pd.concat([mal, ben], ignore_index=True)
cols = list(df.columns)

# ---- Group the 484 columns by what they are ----
first_perm = cols.index("nr_syscalls") + 1                           # permissions start right after the syscalls
syscalls   = cols[cols.index("execve"):first_perm]                      # DYNAMIC (needs running the app)
permissions = cols[first_perm:cols.index("nr_permissions")]             # STATIC - Androguard can read these
static_meta = ["nr_permissions", "normal", "dangerous", "signature", "custom_yes", "nr_custom",
               "total_perm", "CFileSize", "UFileSize", "FilesInsideAPK", "Activities",
               "NrIntServices", "NrIntServicesActions", "NrIntActivities", "NrIntActivitiesActions",
               "NrIntReceivers", "NrIntReceiversActions", "TotalIntentFilters", "NrServices",
               "EarliestModDate", "HighestModDate"]
leakage = ["Scanners", "Detection_Ratio", "TimesSubmitted", "MalFamily"]   # come from VirusTotal/labels
ids = ["Package", "sha256"]
other = [c for c in cols if c not in syscalls + permissions + static_meta + leakage + ids + ["Malware"]]

log("=== KRONODROID (REAL DEVICE) - INSPECTION ===")
log(f"Malware file : {mal.shape[0]:,} rows | Benign file: {ben.shape[0]:,} rows")
log(f"Combined     : {df.shape[0]:,} rows x {df.shape[1]} columns")
log(f"Label 'Malware': {df['Malware'].value_counts().to_dict()}  (1 = malware, 0 = benign)")
log("")
log("Column groups:")
log(f"  Dynamic system calls (NOT usable by a static scanner) : {len(syscalls)}")
log(f"  Permissions (STATIC, named)                          : {len(permissions)}")
log(f"  Static metadata (counts, sizes, intent filters)      : {len(static_meta)}")
log(f"  Leakage columns (from VirusTotal / the label itself) : {len(leakage)} -> {leakage}")
log(f"  ID columns                                           : {ids}")
log(f"  Other (NrContactedIps = network activity, DYNAMIC)   : {other}")
log("")
log("Example permission columns: " + ", ".join(permissions[:4]) + ", ... , SEND_SMS, READ_CONTACTS, RECEIVE_BOOT_COMPLETED")
log("")
static_cols = permissions + static_meta
log(f"Duplicate rows (same static features + same label): {df.duplicated(static_cols + ['Malware']).sum():,}")
log(f"Duplicate sha256 (exact same APK file)            : {df['sha256'].duplicated().sum():,}")
na = df[static_cols].isna().sum()
log(f"Missing values in static columns                  : {int(na.sum()):,} cells in {(na > 0).sum()} columns, "
    f"{df[static_cols].isna().any(axis=1).sum():,} rows")
log("")
log(f"Malware families: {df['MalFamily'].nunique()} | top 8:")
log(df["MalFamily"].value_counts().head(8).to_string())

df.to_csv("data/processed/kronodroid_combined.csv", index=False)
with open("evidence/kronodroid_inspection.txt", "w") as fh:
    fh.write("\n".join(report))
print("\nSaved: data/processed/kronodroid_combined.csv, evidence/kronodroid_inspection.txt")