"""
KronoDroid Step 3 - Stratified 80/20 split, missing-value filling, min-max normalisation.
The imputer and scaler are FITTED ON THE TRAINING SET ONLY, then applied to both sets.
Input : data/processed/kd_features.csv, kd_feature_list.txt
Output: data/processed/kd_X_train.csv, kd_X_test.csv, kd_y_train.csv, kd_y_test.csv
        models/kd_preprocess.joblib   (re-used later by the Flask scanner)
        evidence/kd_split_report.txt
"""
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import MinMaxScaler

P = "data/processed"
RANDOM_STATE = 42
df = pd.read_csv(f"{P}/kd_features.csv", low_memory=False)
features = open(f"{P}/kd_feature_list.txt").read().split("\n")
X, y, info = df[features], df["label"], df[["sha256", "MalFamily"]]
report = []
def log(msg=""):
    print(msg); report.append(str(msg))

# ---- 3a. Stratified 80/20 split ----
X_train, X_test, y_train, y_test, info_train, info_test = train_test_split(
    X, y, info, test_size=0.20, stratify=y, random_state=RANDOM_STATE)

log("=== KRONODROID STEP 3: SPLIT + MISSING VALUES + NORMALISATION ===")
for name, yy in [("Full ", y), ("Train", y_train), ("Test ", y_test)]:
    log(f"{name}: {len(yy):>6,} rows | malware {int(yy.sum()):>6,} ({yy.mean():.2%}) | benign {int((yy == 0).sum()):>6,}")

# Transparency check (duplicates were kept on supervisor's instruction):
train_keys = set(pd.util.hash_pandas_object(X_train.fillna(-1), index=False))
test_keys = pd.util.hash_pandas_object(X_test.fillna(-1), index=False)
seen = test_keys.isin(train_keys).sum()
log(f"\nTest rows whose exact feature values also appear in training: {seen:,} ({seen / len(X_test):.1%})")
log("(Kept as instructed. Reported so results can be interpreted honestly.)")

# ---- 3b + 3c. Fill missing values with the TRAINING median, then min-max scale to 0-1 ----
log(f"\nMissing cells before - train: {int(X_train.isna().sum().sum()):,} | test: {int(X_test.isna().sum().sum()):,}")
prep = Pipeline([("impute", SimpleImputer(strategy="median")),
                 ("scale", MinMaxScaler())])
prep.fit(X_train)
X_train_p = pd.DataFrame(prep.transform(X_train), columns=features, index=X_train.index)
X_test_p = pd.DataFrame(prep.transform(X_test), columns=features, index=X_test.index)
log(f"Missing cells after  - train: {int(X_train_p.isna().sum().sum())} | test: {int(X_test_p.isna().sum().sum())}")

med = pd.Series(prep.named_steps["impute"].statistics_, index=features)
miss_cols = X.columns[X.isna().any()]
log("Training medians used to fill: " + ", ".join(f"{c}={med[c]:.0f}" for c in miss_cols))
log(f"\nTrain value range after scaling: {X_train_p.values.min():.2f} to {X_train_p.values.max():.2f}")
log(f"Test value range after scaling : {round(X_test_p.values.min(), 2) + 0.0:.2f} to {X_test_p.values.max():.2f} "
    "(can exceed 1 - normal, the scaler never saw the test set)")
log("Example - CFileSize before/after (first 3 training apps):")
log(pd.DataFrame({"before": X_train["CFileSize"].head(3).values,
                  "after": X_train_p["CFileSize"].head(3).round(4).values}).to_string(index=False))

# ---- Save ----
X_train_p.to_csv(f"{P}/kd_X_train.csv", index=False)
X_test_p.to_csv(f"{P}/kd_X_test.csv", index=False)
pd.concat([info_train, y_train], axis=1).to_csv(f"{P}/kd_y_train.csv", index=False)
pd.concat([info_test, y_test], axis=1).to_csv(f"{P}/kd_y_test.csv", index=False)
joblib.dump({"pipeline": prep, "features": features}, "models/kd_preprocess.joblib")
with open("evidence/kd_split_report.txt", "w") as fh:
    fh.write("\n".join(report))
print("\nSaved: kd_X_train.csv, kd_X_test.csv, kd_y_train.csv, kd_y_test.csv, "
      "models/kd_preprocess.joblib, evidence/kd_split_report.txt")