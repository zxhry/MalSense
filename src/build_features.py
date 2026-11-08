"""
New dataset - Step 2: Build the STATIC feature table from KronoDroid.
Keeps only features that Androguard can extract from an APK file WITHOUT running it.
Duplicates are KEPT (supervisor decision). Missing values are NOT filled here -
they are filled in Step 3 using the training set only (to avoid data leakage).
Input : data/processed/kronodroid_combined.csv
Output: data/processed/kd_features.csv, data/processed/kd_feature_list.txt,
        evidence/kd_build_features_report.txt
"""
import pandas as pd

df = pd.read_csv("data/processed/kronodroid_combined.csv", low_memory=False)
cols = list(df.columns)
report = []
def log(msg=""):
    print(msg); report.append(str(msg))

# ---- 1. Decide which columns are features ----
permissions = cols[cols.index("nr_syscalls") + 1:cols.index("nr_permissions")]
static_counts = ["nr_permissions", "normal", "dangerous", "signature", "custom_yes", "nr_custom",
                 "total_perm", "CFileSize", "UFileSize", "FilesInsideAPK", "Activities",
                 "NrIntServices", "NrIntServicesActions", "NrIntActivities", "NrIntActivitiesActions",
                 "NrIntReceivers", "NrIntReceiversActions", "TotalIntentFilters", "NrServices"]

excluded = {
    "Dynamic system calls (need to run the app)": cols[cols.index("execve"):cols.index("nr_syscalls") + 1],
    "Dynamic network activity": ["NrContactedIps"],
    "VirusTotal / label leakage": ["Scanners", "Detection_Ratio", "TimesSubmitted", "MalFamily"],
    "Dates (temporal bias - see note)": ["EarliestModDate", "HighestModDate"],
    "Identifiers": ["Package", "sha256"],
}

log("=== STEP 2: BUILD STATIC FEATURE TABLE (KronoDroid real device) ===")
log(f"Start: {df.shape[0]:,} rows x {df.shape[1]} columns")
log("\nExcluded column groups:")
for reason, c in excluded.items():
    log(f"  - {reason:<45}: {len(c)}")

# ---- 2. Evidence for dropping dates: they mostly reflect WHEN apps were collected ----
year = pd.to_datetime(df["EarliestModDate"], errors="coerce").dt.year
tab = pd.crosstab(year.clip(2007, 2021), df["Malware"]).rename(columns={0: "benign", 1: "malware"})
log("\nNote on dates - APKs per year of EarliestModDate (benign vs malware):")
log(tab.loc[[2010, 2012, 2014, 2016, 2018]].to_string())
log("Years are unevenly split between classes, so a model could learn 'old/new = malware'")
log("instead of real behaviour. Every APK scanned today would have a recent date -> dates dropped.")

# ---- 3. Remove permissions that NO app in the dataset uses (always 0 = no information) ----
constant = [c for c in permissions + static_counts if df[c].nunique(dropna=True) <= 1]
features = [c for c in permissions + static_counts if c not in constant]
log(f"\nConstant columns removed (no app uses them): {len(constant)}")
log("  e.g. " + ", ".join(constant[:5]))

# ---- 4. Build the table: IDs + label + features. Duplicates are KEPT. ----
out = df[["sha256", "MalFamily", "Malware"] + features].rename(columns={"Malware": "label"})
out["MalFamily"] = out["MalFamily"].fillna("Benign")   # kept for the awareness quiz, NOT a feature

n_perm = len([f for f in features if f in permissions])
log(f"\nFINAL: {len(out):,} rows | {len(features)} features ({n_perm} permissions + {len(features) - n_perm} static counts)")
log(f"Label: malware(1) = {int(out.label.sum()):,} ({out.label.mean():.1%}) | benign(0) = {int((out.label == 0).sum()):,}")
log(f"Duplicate rows kept (supervisor decision): {out.duplicated(features + ['label']).sum():,}")
na = out[features].isna().sum()
log(f"Missing values left for Step 3 (filled using training data only): {int(na.sum()):,} cells in "
    f"{(na > 0).sum()} columns -> {', '.join(na[na > 0].index)}")
log("\nAverage values by class (for 0/1 permissions, 0.47 means 47% of apps request it):")
log(out.groupby("label")[["nr_permissions", "dangerous", "SEND_SMS", "READ_PHONE_STATE", "CFileSize"]]
    .agg(["mean"]).round(2).rename(index={0: "benign", 1: "malware"}).to_string())

out.to_csv("data/processed/kd_features.csv", index=False)
with open("data/processed/kd_feature_list.txt", "w") as fh:
    fh.write("\n".join(features))
with open("evidence/kd_build_features_report.txt", "w") as fh:
    fh.write("\n".join(report))
print("\nSaved: data/processed/kd_features.csv, kd_feature_list.txt, evidence/kd_build_features_report.txt")