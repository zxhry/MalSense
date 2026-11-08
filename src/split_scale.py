"""
Stratified 80/20 train/test split + normalisation (Figure 3.3 & 3.4).
Input : data/processed/X_clean.npz, meta_clean.csv
Output: data/processed/X_train.npz, X_test.npz, y_train.csv, y_test.csv
        models/scaler.joblib            (re-used later by the Flask scanner)
        evidence/split_report.txt
The scaler is FITTED ON THE TRAINING SET ONLY, then applied to both sets,
so no information from the test set leaks into training.
"""
import numpy as np
import pandas as pd
import joblib
from scipy import sparse
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MaxAbsScaler

P = "data/processed"
RANDOM_STATE = 42          # fixed seed -> the same split every time (reproducible)
X = sparse.load_npz(f"{P}/X_clean.npz").tocsr()
meta = pd.read_csv(f"{P}/meta_clean.csv")
y = meta["label"].to_numpy()
report = []

def log(msg=""):
    print(msg)
    report.append(msg)

# ---- 4a. Stratified 80/20 split: both sets keep the same malware/benign ratio ----
idx_train, idx_test = train_test_split(
    np.arange(len(y)), test_size=0.20, stratify=y, random_state=RANDOM_STATE)
X_train, X_test = X[idx_train], X[idx_test]
y_train, y_test = y[idx_train], y[idx_test]

log("=== STEP 4: TRAIN/TEST SPLIT + NORMALISATION ===")
for name, yy in [("Full ", y), ("Train", y_train), ("Test ", y_test)]:
    log(f"{name}: {len(yy):>7,} rows | malware {int(yy.sum()):>6,} ({yy.mean():.2%}) | "
        f"benign {int((yy == 0).sum()):>7,}")
log(f"Overlap between train and test rows: {len(set(idx_train) & set(idx_test))}")

# ---- 4b. Min-max normalisation fitted on TRAIN only ----
# All features are >= 0 and their minimum is 0, so min-max scaling (x - min)/(max - min)
# is identical to x / max. MaxAbsScaler does exactly that AND keeps the matrix sparse
# (sklearn's MinMaxScaler would turn it into a 12 GB dense matrix).
train_min = X_train.min(axis=0).toarray().ravel()
assert (train_min == 0).all(), "Some feature has minimum > 0 - MaxAbsScaler would not equal min-max"
log(f"\nCheck: minimum of every training feature is 0 -> min-max == x / max  (OK)")

scaler = MaxAbsScaler().fit(X_train)
X_train_s = scaler.transform(X_train).tocsr()
X_test_s = scaler.transform(X_test).tocsr()

log(f"Train values now range : {X_train_s.min():.2f} to {X_train_s.max():.2f}")
log(f"Test values now range  : {X_test_s.min():.2f} to {X_test_s.max():.2f}  "
    f"(may exceed 1 slightly - that is normal, the scaler never saw the test set)")
counts = np.argsort(-scaler.max_abs_)[:4]
log(f"Example: features with largest raw values (before scaling): "
    + ", ".join(f"F{int(pd.read_csv(f'{P}/feature_names_clean.csv')['feature'][i][1:])} max={scaler.max_abs_[i]:,.0f}" for i in counts))

# ---- Save ----
sparse.save_npz(f"{P}/X_train.npz", X_train_s)
sparse.save_npz(f"{P}/X_test.npz", X_test_s)
pd.DataFrame({"sha256": meta["sha256"].iloc[idx_train].values, "category": meta["category"].iloc[idx_train].values,
              "label": y_train}).to_csv(f"{P}/y_train.csv", index=False)
pd.DataFrame({"sha256": meta["sha256"].iloc[idx_test].values, "category": meta["category"].iloc[idx_test].values,
              "label": y_test}).to_csv(f"{P}/y_test.csv", index=False)
joblib.dump(scaler, "models/scaler.joblib")
with open("evidence/split_report.txt", "w") as fh:
    fh.write("\n".join(report))
print("\nSaved: X_train.npz, X_test.npz, y_train.csv, y_test.csv, models/scaler.joblib, evidence/split_report.txt")