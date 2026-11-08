"""
Sprint 3 - Step 6: FINAL evaluation on the locked 20% TEST set (right side of Figure 3.4).
Each model is trained once on the full training set, then tested ONCE on unseen test data.
Input : data/processed/kd_X_train.csv, kd_y_train.csv, kd_X_test.csv, kd_y_test.csv,
        models/kd_xgb_tuned_params.json
Output: models/kd_xgb_final.joblib (+ rf, svm), evidence/kd_test_results.csv,
        evidence/kd_confusion_matrices.png, evidence/kd_roc_curves.png,
        evidence/kd_xgb_top_features.png, evidence/kd_final_report.txt
"""
import json, time
import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, roc_curve, confusion_matrix, ConfusionMatrixDisplay)
from xgboost import XGBClassifier

P = "data/processed"
X_train = pd.read_csv(f"{P}/kd_X_train.csv")
X_test = pd.read_csv(f"{P}/kd_X_test.csv")
y_train = pd.read_csv(f"{P}/kd_y_train.csv")["label"]
test_info = pd.read_csv(f"{P}/kd_y_test.csv")
y_test = test_info["label"]
best = json.load(open("models/kd_xgb_tuned_params.json"))
report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

log("=== SPRINT 3 STEP 6: FINAL EVALUATION ON THE TEST SET ===")
log(f"Train: {len(y_train):,} apps | Test: {len(y_test):,} apps (never seen during training or tuning)")
log(f"XGBoost tuned parameters: {best}\n")

models = {
    "XGBoost (tuned)": XGBClassifier(**best, eval_metric="logloss", n_jobs=-1, random_state=42),
    "Random Forest":   RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42),
    "SVM (RBF)":       SVC(kernel="rbf", random_state=42),
}
files = {"XGBoost (tuned)": "kd_xgb_final", "Random Forest": "kd_rf_final", "SVM (RBF)": "kd_svm_final"}

rows, preds, scores = [], {}, {}
for name, model in models.items():
    log(f"Training {name} on the full training set..." + (" (~2-5 min)" if "SVM" in name else ""))
    t = time.time()
    model.fit(X_train, y_train)
    fit_s = time.time() - t
    t = time.time()
    pred = model.predict(X_test)
    score = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(X_test)
    ms_per_app = (time.time() - t) / len(X_test) * 1000
    preds[name], scores[name] = pred, score
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    rows.append({"Model": name,
                 "Accuracy": accuracy_score(y_test, pred), "Precision": precision_score(y_test, pred),
                 "Recall": recall_score(y_test, pred), "F1": f1_score(y_test, pred),
                 "ROC-AUC": roc_auc_score(y_test, score),
                 "Missed malware (FN)": fn, "False alarms (FP)": fp,
                 "Train time (s)": round(fit_s, 1), "Predict ms/app": round(ms_per_app, 3)})
    joblib.dump(model, f"models/{files[name]}.joblib")
    log(f"   done | F1 = {rows[-1]['F1']:.4f} | Recall = {rows[-1]['Recall']:.4f} | saved models/{files[name]}.joblib")

res = pd.DataFrame(rows).set_index("Model")
log("\n=== TEST SET RESULTS ===")
log(res.round(4).to_string())
log(f"\nTarget (>90% accuracy and >90% recall): " +
    ", ".join(f"{n}: {'MET' if (r.Accuracy > .9 and r.Recall > .9) else 'NOT met'}" for n, r in res.iterrows()))

# ---- Honesty check: duplicates were kept, so compare test apps seen vs. not seen in training ----
train_keys = set(pd.util.hash_pandas_object(X_train, index=False))
seen = pd.util.hash_pandas_object(X_test, index=False).isin(train_keys).values
p = preds["XGBoost (tuned)"]
log(f"\nXGBoost on test apps that ALSO appear in training ({seen.sum():,}): "
    f"accuracy {accuracy_score(y_test[seen], p[seen]):.4f}")
log(f"XGBoost on test apps that are truly NEW             ({(~seen).sum():,}): "
    f"accuracy {accuracy_score(y_test[~seen], p[~seen]):.4f}, recall {recall_score(y_test[~seen], p[~seen]):.4f}")

# ---- Which malware families does XGBoost miss most? (useful for the awareness module) ----
mal = test_info[y_test == 1].copy()
mal["detected"] = p[y_test.values == 1]
# some malware rows have no family in KronoDroid (Step 2 filled them as "Benign") - relabel them
mal.loc[mal["MalFamily"] == "Benign", "MalFamily"] = "(no family label)"
fam = mal.groupby("MalFamily")["detected"].agg(["size", "mean"]).query("size >= 30").sort_values("mean")
log("\nXGBoost detection rate by malware family (families with >= 30 test apps, lowest first):")
log(fam.head(8).rename(columns={"size": "test apps", "mean": "detected"}).round(3).to_string())

# ---- Figures ----
fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
for ax, (name, pred) in zip(axes, preds.items()):
    ConfusionMatrixDisplay(confusion_matrix(y_test, pred), display_labels=["Benign", "Malware"]).plot(
        ax=ax, colorbar=False, values_format=",")
    ax.set_title(name)
plt.suptitle("Confusion matrices on the test set"); plt.tight_layout()
plt.savefig("evidence/kd_confusion_matrices.png", dpi=150); plt.close()

plt.figure(figsize=(6, 5))
for name, score in scores.items():
    fpr, tpr, _ = roc_curve(y_test, score)
    plt.plot(fpr, tpr, label=f"{name} (AUC = {roc_auc_score(y_test, score):.4f})")
plt.plot([0, 1], [0, 1], "k--", lw=1)
plt.xlabel("False positive rate"); plt.ylabel("True positive rate (recall)")
plt.title("ROC curves on the test set"); plt.legend(loc="lower right"); plt.grid(alpha=.3)
plt.tight_layout(); plt.savefig("evidence/kd_roc_curves.png", dpi=150); plt.close()

imp = pd.Series(models["XGBoost (tuned)"].feature_importances_, index=X_train.columns).nlargest(15)
log("\nTop 15 features used by XGBoost:")
log(imp.round(4).to_string())
imp[::-1].plot(kind="barh", figsize=(7, 5), title="XGBoost - top 15 most important features")
plt.xlabel("Importance (gain share)"); plt.tight_layout()
plt.savefig("evidence/kd_xgb_top_features.png", dpi=150); plt.close()

res.to_csv("evidence/kd_test_results.csv")
with open("evidence/kd_final_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print("\nSaved: models/*.joblib, evidence/kd_test_results.csv, kd_confusion_matrices.png, "
      "kd_roc_curves.png, kd_xgb_top_features.png, kd_final_report.txt")