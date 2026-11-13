"""
Show real examples of the missing values and duplicates found in the dataset.
Run AFTER Step 2 (needs data/processed/X_raw.npz, meta.csv, feature_names.csv).
Nothing is changed - this script only looks and prints.
"""
import hashlib
import numpy as np
import pandas as pd
from scipy import sparse

P = "data/processed"
X = sparse.load_npz(f"{P}/X_raw.npz").tocsr()
meta = pd.read_csv(f"{P}/meta.csv")
names = np.array(pd.read_csv(f"{P}/feature_names.csv")["feature"])

def active_features(i):
    """Names of the features that are switched ON (non-zero) for row i."""
    return list(names[X.indices[X.indptr[i]:X.indptr[i + 1]]])

# ---------------- PART A: missing values ----------------
print("=" * 70)
print("PART A - MISSING VALUES (NaN = the cell is empty in the original file)")
print("=" * 70)
last4 = pd.DataFrame(X[:, -4:].toarray(), columns=names[-4:])
rows_nan = last4[last4.isna().any(axis=1)]
print(f"{len(rows_nan)} APKs have an empty value in the last 4 columns. First 5:\n")
print(pd.concat([meta.loc[rows_nan.index, ["sha256", "category"]]
                 .assign(sha256=lambda d: d.sha256.str[:16] + "..."),
                 rows_nan], axis=1).head().to_string())

# ---------------- PART B: duplicates ----------------
print("\n" + "=" * 70)
print("PART B - DUPLICATES (different APK files, but IDENTICAL feature values)")
print("=" * 70)
data = np.nan_to_num(X.data, nan=-1)
meta["fingerprint"] = [hashlib.md5(X.indices[X.indptr[i]:X.indptr[i+1]].tobytes() +
                                   data[X.indptr[i]:X.indptr[i+1]].tobytes()).hexdigest()
                       for i in range(X.shape[0])]
groups = meta.groupby("fingerprint")
size = groups["sha256"].transform("size")
n_labels = groups["label"].transform("nunique")

# B1: a group of same-label duplicates
g = meta[(size >= 5) & (n_labels == 1) & (meta.category == "Adware")]["fingerprint"].iloc[0]
ex = meta[meta.fingerprint == g]
i0 = ex.index[0]
print(f"\nExample 1: {len(ex)} DIFFERENT Adware APKs (different SHA-256 hashes)")
print(f"that have exactly the same {X.indptr[i0+1]-X.indptr[i0]} features switched on:")
print(f"   features ON: {active_features(i0)[:12]} ...")
print(ex[["sha256", "category", "label"]].head(5).to_string())
for i in ex.index[:5]:
    assert active_features(i) == active_features(i0)
print("   -> checked: all rows above have identical feature values")

# B2: an ambiguous group (same features, labelled both malware and benign)
g2 = meta[n_labels > 1]["fingerprint"].iloc[0]
ex2 = meta[meta.fingerprint == g2]
print(f"\nExample 2: {len(ex2)} APKs with IDENTICAL features but DIFFERENT labels:")
print(ex2.sort_values("label", ascending=False)[["sha256", "category", "label"]].head(6).to_string())
print("   -> the model cannot learn from these: same input, opposite answers")

# ---------------- PART C: the totals ----------------
print("\n" + "=" * 70)
print("PART C - TOTALS")
print("=" * 70)
dups = meta.fingerprint.duplicated()
print(f"Rows that are a copy of an earlier row : {dups.sum():,} of {len(meta):,} ({dups.mean():.0%})")
print("Copies per category (top 6):")
print((meta[dups].category.value_counts() / meta.category.value_counts())
      .dropna().sort_values(ascending=False).head(6).map('{:.0%} of the category are copies'.format).to_string())

# Save examples as CSV so they can be opened in Excel
out = pd.concat([ex.head(5).assign(example="1_same_label_duplicates"),
                 ex2.assign(example="2_conflicting_labels")])
out["features_on"] = [", ".join(active_features(i)) for i in out.index]
out[["example", "sha256", "category", "label", "features_on"]].to_csv("evidence/duplicate_examples.csv", index=False)
rows_nan.join(meta[["sha256", "category"]]).to_csv("evidence/missing_value_rows.csv")
print("\nSaved: evidence/duplicate_examples.csv and evidence/missing_value_rows.csv (open in Excel)")