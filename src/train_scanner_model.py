"""
Sprint 4 - Step 2: Train the SCANNER model - the version MalSense will actually use on uploaded APKs.
It uses only the 158 features that can be re-calculated EXACTLY from an APK with Androguard.
The 7 intent-filter count features are dropped: KronoDroid does not document how they were
counted, and our checks show they cannot be reproduced reliably.
Input : data/processed/kd_features.csv, kd_feature_list.txt, kronodroid_combined.csv,
        models/kd_xgb_tuned_params.json
        data/new_samples.csv (optional - APKs the admin added from user reports, see src/new_samples.py)
Output: models/malsense_scanner.joblib, evidence/scanner_model_report.txt

New samples are added to the TRAINING part only. The test set is always the same 20% of KronoDroid,
so the scores before and after adding new samples can be compared fairly.
Safety check: if the retrained model is clearly worse on the test set (F1 drops by more than 1 percentage
point), it is NOT saved and the current model stays in use.
"""
import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from loguru import logger
logger.remove()
from androguard.core.api_specific_resources import load_permissions
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from xgboost import XGBClassifier

P = "data/processed"
NEW_SAMPLE_WEIGHT = 10      # each new (recent) sample counts like 10 KronoDroid apps, so a few samples still matter
MAX_F1_DROP = 0.01          # refuse to replace the current model if F1 gets worse by more than this
sys.path.insert(0, os.path.dirname(__file__))
import new_samples
report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

df = pd.read_csv(f"{P}/kd_features.csv", low_memory=False)
all_features = open(f"{P}/kd_feature_list.txt").read().split("\n")
INTENT = ["NrIntServices", "NrIntServicesActions", "NrIntActivities", "NrIntActivitiesActions",
          "NrIntReceivers", "NrIntReceiversActions", "TotalIntentFilters"]
features = [f for f in all_features if f not in INTENT]

# ---- 1. Permission list + protection levels (needed to calculate normal/dangerous/signature) ----
cols = list(pd.read_csv(f"{P}/kronodroid_combined.csv", nrows=1).columns)
kd_permissions = cols[cols.index("nr_syscalls") + 1:cols.index("nr_permissions")]   # all 166
api = load_permissions(30)
manual = {"ADD_VOICEMAIL": "dangerous", "INSTALL_SHORTCUT": "normal", "UNINSTALL_SHORTCUT": "normal",
          "SET_ALARM": "normal", "READ_VOICEMAIL": "signature", "WRITE_VOICEMAIL": "signature"}
def level(p):
    if p in manual:
        return manual[p]
    base = api["android.permission." + p]["protectionLevel"].split("|")[0]
    return "dangerous" if "dangerous" in base else ("signature" if ("signature" in base or "privileged" in base) else "normal")
levels = {p: level(p) for p in kd_permissions}

# Verify: our calculation must reproduce KronoDroid's own counts for every app
raw = pd.read_csv(f"{P}/kronodroid_combined.csv", usecols=kd_permissions + ["normal", "dangerous", "signature"])
log("=== SPRINT 4 STEP 2: TRAIN THE SCANNER MODEL ===")
log("Check - can we reproduce KronoDroid's permission-level counts from the permission names?")
for lv in ["normal", "dangerous", "signature"]:
    ours = raw[[p for p in kd_permissions if levels[p] == lv]].sum(axis=1)
    log(f"   {lv:<9}: matches for {(ours == raw[lv]).mean():.2%} of 78,137 apps")

# ---- 2. Same split as before (seed 42), 158 features ----
X, y = df[features], df["label"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)
# ---- 2b. Add the admin's new samples (from user reports) to the TRAINING part only ----
extra = new_samples.load()
extra = extra[~extra["sha256"].isin(df.loc[X_test.index, "sha256"])] if len(extra) else extra   # never leak into test
weights = np.ones(len(X_train))
if len(extra):
    X_train = pd.concat([X_train, extra[features]], ignore_index=True)
    y_train = pd.concat([y_train, extra["label"].astype(int)], ignore_index=True)
    weights = np.concatenate([weights, np.full(len(extra), NEW_SAMPLE_WEIGHT)])
log(f"New samples from user reports: {len(extra)} "
    f"({int((extra['label'] == 1).sum()) if len(extra) else 0} malware / "
    f"{int((extra['label'] == 0).sum()) if len(extra) else 0} benign), weight {NEW_SAMPLE_WEIGHT} each")

prep = Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", MinMaxScaler())]).fit(X_train)
best = json.load(open("models/kd_xgb_tuned_params.json"))
model = XGBClassifier(**best, eval_metric="logloss", n_jobs=-1, random_state=42)
model.fit(prep.transform(X_train), y_train, sample_weight=weights)

prob = model.predict_proba(prep.transform(X_test))[:, 1]
pred = (prob >= 0.5).astype(int)
log(f"\nFeatures used: {len(features)} (dropped {len(INTENT)} intent-filter counts: {', '.join(INTENT)})")
log("\nTest-set comparison:")
old = pd.read_csv("evidence/kd_test_results.csv", index_col=0).loc["XGBoost (tuned)"]
comp = pd.DataFrame({"Research model (165)": [old.Accuracy, old.Precision, old.Recall, old.F1, old["ROC-AUC"]],
                     "Scanner model (158)": [accuracy_score(y_test, pred), precision_score(y_test, pred),
                                             recall_score(y_test, pred), f1_score(y_test, pred),
                                             roc_auc_score(y_test, prob)]},
                    index=["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]).round(4)
comp["Difference"] = (comp.iloc[:, 1] - comp.iloc[:, 0]).round(4)
log(comp.to_string())

# ---- 2c. Does the new model now recognise the new samples? ----
learned = 0
if len(extra):
    extra_pred = (model.predict_proba(prep.transform(extra[features]))[:, 1] >= 0.5).astype(int)
    learned = int((extra_pred == extra["label"].astype(int).values).sum())
    log(f"New samples classified correctly by the retrained model: {learned} of {len(extra)}")

# ---- 2d. Safety check: never replace a good model with a clearly worse one ----
new_f1 = f1_score(y_test, pred)
if os.path.exists("models/scanner_metrics.json"):
    old_f1 = json.load(open("models/scanner_metrics.json")).get("f1")
    if old_f1 is not None and new_f1 < old_f1 - MAX_F1_DROP:
        log(f"\nNOT SAVED: test F1 would drop from {old_f1:.4f} to {new_f1:.4f}. The current model is kept.")
        print(f"Retrained model is worse on the test set (F1 {old_f1:.2%} -> {new_f1:.2%}); "
              "the current model was kept.", file=sys.stderr)
        sys.exit(2)

# ---- 3. Save everything the scanner needs in ONE file ----
bundle = {"model": model, "preprocess": prep, "features": features,
          "kd_permissions": kd_permissions, "permission_levels": levels,
          "xgb_params": best, "threshold": 0.5}
joblib.dump(bundle, "models/malsense_scanner.joblib")
from datetime import datetime
metrics = {"accuracy": accuracy_score(y_test, pred), "precision": precision_score(y_test, pred),
           "recall": recall_score(y_test, pred), "f1": f1_score(y_test, pred), "roc_auc": roc_auc_score(y_test, prob),
           "n_total": int(len(df)), "n_train": int(len(y_train)), "n_test": int(len(y_test)),
           "n_features": len(features), "n_malware": int(df["label"].sum()), "n_benign": int((df["label"] == 0).sum()),
           "n_new_samples": int(len(extra)), "n_new_learned": learned,
           "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
json.dump(metrics, open("models/scanner_metrics.json", "w"), indent=2)
with open("evidence/scanner_model_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print("\nSaved: models/malsense_scanner.joblib, evidence/scanner_model_report.txt")