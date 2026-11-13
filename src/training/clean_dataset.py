"""
Clean the dataset (Figure 3.3: duplicate removal + missing value handling).
Input : data/processed/X_raw.npz, meta.csv, feature_names.csv   (from Step 2)
Output: data/processed/X_clean.npz, meta_clean.csv, feature_names_clean.csv
        evidence/cleaning_report.txt
Min-max normalisation is NOT done here - it must be fitted on the training set only (Step 4).
"""
import hashlib
import numpy as np
import pandas as pd
from scipy import sparse

P = "data/processed"
X = sparse.load_npz(f"{P}/X_raw.npz").tocsr()
meta = pd.read_csv(f"{P}/meta.csv")
features = pd.read_csv(f"{P}/feature_names.csv")["feature"].tolist()
report = []

def log(msg=""):
    print(msg)
    report.append(msg)

def counts(m):
    c = m["label"].value_counts()
    return f"{len(m):,} rows | malware(1)={c.get(1, 0):,} | benign(0)={c.get(0, 0):,}"

log("=== STEP 3: DATA CLEANING REPORT ===")
log(f"Start                          : {counts(meta)} | {X.shape[1]:,} features")

# ---- 3a. Missing values: fill with the column median (which is 0 for all 4 columns) ----
nan_mask = np.isnan(X.data)
n_nan = int(nan_mask.sum())
nan_rows = np.unique(np.repeat(np.arange(X.shape[0]), np.diff(X.indptr))[nan_mask])
X.data[nan_mask] = 0.0
X.eliminate_zeros()
log(f"3a Missing values filled with 0 : {n_nan} cells in {len(nan_rows)} rows "
    f"({meta.loc[nan_rows, 'category'].value_counts().to_dict()})")

# ---- 3b. Fingerprint every row so identical feature vectors can be found ----
fp = [hashlib.md5(X.indices[X.indptr[i]:X.indptr[i + 1]].tobytes() +
                  X.data[X.indptr[i]:X.indptr[i + 1]].tobytes()).hexdigest()
      for i in range(X.shape[0])]
meta["fingerprint"] = fp
log(f"   Rows whose features duplicate another row: {meta['fingerprint'].duplicated().sum():,}")

# ---- 3c. Remove ambiguous vectors: identical features but labelled BOTH malware and benign ----
n_labels = meta.groupby("fingerprint")["label"].transform("nunique")
ambiguous = (n_labels > 1).to_numpy()
log(f"3c Ambiguous rows removed       : {ambiguous.sum():,} rows "
    f"({meta.loc[ambiguous, 'fingerprint'].nunique()} feature vectors labelled both 0 and 1)")
keep = ~ambiguous

# ---- 3d. Remove exact duplicates (same features + same label), keep first copy ----
dup = meta["fingerprint"].duplicated(keep="first").to_numpy() & keep
log(f"3d Duplicate rows removed       : {dup.sum():,}")
keep &= ~dup

X = X[keep]
meta = meta.loc[keep].drop(columns="fingerprint").reset_index(drop=True)
log(f"After de-duplication           : {counts(meta)}")

# ---- 3e. Remove constant columns (same value for every remaining APK = no information) ----
col_nnz = X.getnnz(axis=0)
constant = col_nnz == 0          # all features are >= 0, so nnz==0 means always 0
# a column that is non-zero for EVERY row is also constant only if all values equal - check it
full = np.where(col_nnz == X.shape[0])[0]
for j in full:
    col = X[:, j].data
    if col.min() == col.max():
        constant[j] = True
X = X[:, ~constant]
features = [f for f, c in zip(features, constant) if not c]
log(f"3e Constant columns removed     : {int(constant.sum())} -> {len(features):,} features remain")

# ---- Final summary ----
log("")
log(f"FINAL                          : {counts(meta)} | {X.shape[1]:,} features")
ratio = meta['label'].value_counts(normalize=True)
log(f"Class balance                  : benign {ratio.get(0, 0):.1%} / malware {ratio.get(1, 0):.1%}")
log("Category counts after cleaning :")
log(meta["category"].value_counts().to_string())

sparse.save_npz(f"{P}/X_clean.npz", X)
meta.to_csv(f"{P}/meta_clean.csv", index=False)
pd.Series(features).to_csv(f"{P}/feature_names_clean.csv", index=False, header=["feature"])
with open("evidence/cleaning_report.txt", "w") as fh:
    fh.write("\n".join(report))
print("\nSaved: data/processed/X_clean.npz, meta_clean.csv, feature_names_clean.csv, evidence/cleaning_report.txt")