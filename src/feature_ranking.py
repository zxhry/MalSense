"""
Rank features by Information Gain (Section 3.4.2), using the TRAINING set only.
Information Gain = how much knowing a feature reduces uncertainty about malware vs benign
(0 = useless, higher = more useful). Maximum possible here is the label entropy (~0.66 bits).
Input : data/processed/X_train.npz, y_train.csv, feature_names_clean.csv
Output: evidence/feature_ranking.csv, evidence/ig_curve.png, evidence/feature_ranking_report.txt
Nothing is removed yet - Step 6 uses this ranking to choose how many features to keep.
"""
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import sparse
from sklearn.feature_selection import mutual_info_classif

P = "data/processed"
X = sparse.load_npz(f"{P}/X_train.npz").tocsc()
y = pd.read_csv(f"{P}/y_train.csv")["label"].to_numpy()
names = pd.read_csv(f"{P}/feature_names_clean.csv")["feature"].to_numpy()
report = []
def log(msg=""):
    print(msg); report.append(msg)

def entropy(p):
    p = np.clip(p, 1e-12, 1 - 1e-12)
    return -(p * np.log2(p) + (1 - p) * np.log2(1 - p))

n = len(y)
H_y = entropy(y.mean())

# ---- Binary features (0/1): exact Information Gain from counts ----
present = np.diff(X.indptr)                       # how many APKs have feature = 1
present_mal = (X != 0).astype("int32").T @ y         # ... of which are malware
absent_mal = y.sum() - present_mal
absent = n - present
H_present = entropy(np.divide(present_mal, present, out=np.zeros(len(names)), where=present > 0))
H_absent = entropy(np.divide(absent_mal, absent, out=np.zeros(len(names)), where=absent > 0))
ig = H_y - (present / n) * H_present - (absent / n) * H_absent
ig = np.clip(ig, 0, None)

# ---- Count features (not just 0/1): estimate IG with sklearn (k-NN estimator) ----
is_binary = np.array([np.isin(X.data[X.indptr[j]:X.indptr[j + 1]], [1.0]).all() for j in range(X.shape[1])])
count_cols = np.where(~is_binary)[0]
mi = mutual_info_classif(X[:, count_cols].toarray(), y, discrete_features=False, random_state=42)
ig[count_cols] = mi / np.log(2)                    # nats -> bits, same unit as above

# ---- Rank and save ----
rank = pd.DataFrame({"feature": names, "info_gain": ig,
                     "type": np.where(is_binary, "binary", "count"),
                     "pct_malware_with_feature": np.round(100 * present_mal / np.maximum(y.sum(), 1), 2),
                     "pct_benign_with_feature": np.round(100 * (present - present_mal) / max((y == 0).sum(), 1), 2)})
rank = rank.sort_values("info_gain", ascending=False).reset_index(drop=True)
rank.index += 1
rank.index.name = "rank"
rank.to_csv("evidence/feature_ranking.csv")

total = rank["info_gain"].sum()
cum = rank["info_gain"].cumsum() / total
log("=== STEP 5: INFORMATION GAIN FEATURE RANKING (training set only) ===")
log(f"Training rows: {n:,} | features ranked: {len(names):,} ({(~is_binary).sum()} count, {is_binary.sum():,} binary)")
log(f"Label entropy H(y) = {H_y:.3f} bits (the maximum any single feature could score)")
log(f"Features with IG = 0 (never seen in training)     : {(present == 0).sum():,}")
log(f"Features with IG < 0.0001 (practically useless)   : {(rank.info_gain < 1e-4).sum():,}")
for t in (0.80, 0.90, 0.95, 0.99):
    log(f"Top features needed for {t:.0%} of total IG        : {int((cum < t).sum()) + 1:,}")
log("\nTop 15 features:")
log(rank.head(15).to_string())

fig, ax = plt.subplots(1, 2, figsize=(12, 4))
ax[0].plot(np.arange(1, len(rank) + 1), rank["info_gain"])
ax[0].set(xscale="log", xlabel="Feature rank (log scale)", ylabel="Information Gain (bits)",
          title="Information Gain of each feature")
ax[1].plot(np.arange(1, len(rank) + 1), cum * 100)
for k in (100, 250, 500, 1000, 2000):
    ax[1].axvline(k, ls=":", c="grey"); ax[1].text(k, 5, str(k), rotation=90, fontsize=8)
ax[1].set(xscale="log", xlabel="Number of top features kept (log scale)", ylabel="% of total IG captured",
          title="Cumulative Information Gain")
for a in ax: a.grid(alpha=.3)
plt.tight_layout(); plt.savefig("evidence/ig_curve.png", dpi=150)
with open("evidence/feature_ranking_report.txt", "w") as fh:
    fh.write("\n".join(report))
print("\nSaved: evidence/feature_ranking.csv, evidence/ig_curve.png, evidence/feature_ranking_report.txt")