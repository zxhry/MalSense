"""
Sprint 3 - Step 4: Baseline 5-fold cross-validation of XGBoost, Random Forest and SVM
(Figure 3.4). Uses the TRAINING set only - the test set stays locked until the final evaluation.
Default settings are used here; XGBoost is tuned with Grid Search in the next step.
Input : data/processed/kd_X_train.csv, kd_y_train.csv
Output: evidence/kd_cv_baseline.csv, evidence/kd_cv_baseline.png, evidence/kd_cv_baseline_report.txt
"""
import time
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier

P = "data/processed"
X = pd.read_csv(f"{P}/kd_X_train.csv")
y = pd.read_csv(f"{P}/kd_y_train.csv")["label"]
report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

log("=== SPRINT 3 STEP 4: BASELINE 5-FOLD CROSS-VALIDATION (training set only) ===")
log(f"Training data: {X.shape[0]:,} apps x {X.shape[1]} features | malware {y.mean():.1%}")
log("SMOTE not applied: classes are already balanced (53% / 47%), so no synthetic samples are needed.\n")

models = {
    "XGBoost":       XGBClassifier(n_estimators=300, eval_metric="logloss", n_jobs=-1, random_state=42),
    "Random Forest": RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42),
    "SVM (RBF)":     SVC(kernel="rbf", random_state=42),
}
scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

rows = []
for name, model in models.items():
    log(f"Training {name} (5 folds)... " + ("this one takes ~5-15 minutes, please wait" if "SVM" in name else ""))
    t = time.time()
    res = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=1)
    secs = time.time() - t
    row = {"model": name}
    for m in scoring:
        row[m] = res[f"test_{m}"].mean()
        row[m + "_std"] = res[f"test_{m}"].std()
    row["time_s"] = secs
    rows.append(row)
    log(f"   done in {secs:,.0f} s | F1 = {row['f1']:.4f} | Recall = {row['recall']:.4f}")

df = pd.DataFrame(rows).set_index("model")
log("\n=== RESULTS (mean of 5 folds, +/- standard deviation) ===")
table = pd.DataFrame({m.capitalize() if m != "roc_auc" else "ROC-AUC":
                      df[m].map("{:.4f}".format) + " ± " + df[m + "_std"].map("{:.4f}".format)
                      for m in scoring})
table["Time (s)"] = df["time_s"].round(0).astype(int)
log(table.to_string())
best = df["f1"].idxmax()
log(f"\nBest F1 (main comparison metric, Section 3.5.3): {best}")
log(f"Best Recall (most important metric)            : {df['recall'].idxmax()}")
log(f"Target from proposal (>90% accuracy and recall): "
    + ", ".join(f"{n} {'MET' if (r.accuracy > .9 and r.recall > .9) else 'NOT met'}" for n, r in df.iterrows()))

df.to_csv("evidence/kd_cv_baseline.csv")
ax = df[scoring].T.plot(kind="bar", figsize=(9, 4.5), ylim=(0.8, 1.0), rot=0)
ax.set(title="Baseline 5-fold cross-validation (training set)", ylabel="Score")
ax.grid(axis="y", alpha=.3); ax.legend(loc="lower right")
plt.tight_layout(); plt.savefig("evidence/kd_cv_baseline.png", dpi=150)
with open("evidence/kd_cv_baseline_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print("\nSaved: evidence/kd_cv_baseline.csv, kd_cv_baseline.png, kd_cv_baseline_report.txt")