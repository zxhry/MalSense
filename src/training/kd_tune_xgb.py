"""
Sprint 3 - Step 5: Tune XGBoost hyperparameters with Grid Search + 5-fold CV (Section 3.5.2).
Uses the TRAINING set only. Selection metric = F1 (main comparison metric, Section 3.5.3).
Input : data/processed/kd_X_train.csv, kd_y_train.csv, evidence/kd_cv_baseline.csv
Output: models/kd_xgb_tuned_params.json, evidence/kd_gridsearch_results.csv,
        evidence/kd_gridsearch_report.txt
"""
import json, time
import pandas as pd
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from xgboost import XGBClassifier

P = "data/processed"
X = pd.read_csv(f"{P}/kd_X_train.csv")
y = pd.read_csv(f"{P}/kd_y_train.csv")["label"]
report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

param_grid = {
    "max_depth":        [4, 6, 8],        # how deep each tree can grow
    "learning_rate":    [0.05, 0.1, 0.2], # how big each correction step is
    "n_estimators":     [300, 600],       # how many trees
    "subsample":        [0.8, 1.0],       # share of apps each tree sees
}
n_comb = 1
for v in param_grid.values():
    n_comb *= len(v)

log("=== SPRINT 3 STEP 5: XGBOOST GRID SEARCH (training set only) ===")
log(f"Grid: {param_grid}")
log(f"{n_comb} combinations x 5 folds = {n_comb * 5} model fits (about 10-25 minutes)\n")

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
search = GridSearchCV(
    XGBClassifier(eval_metric="logloss", n_jobs=-1, random_state=42),
    param_grid, cv=cv, n_jobs=1, verbose=1,
    scoring={"f1": "f1", "recall": "recall", "precision": "precision",
             "accuracy": "accuracy", "roc_auc": "roc_auc"},
    refit="f1")
t = time.time()
search.fit(X, y)
log(f"\nGrid search finished in {(time.time() - t) / 60:.1f} minutes")

res = pd.DataFrame(search.cv_results_)
cols = ["param_max_depth", "param_learning_rate", "param_n_estimators", "param_subsample",
        "mean_test_f1", "std_test_f1", "mean_test_recall", "mean_test_precision",
        "mean_test_accuracy", "mean_test_roc_auc", "mean_fit_time"]
res = res[cols].sort_values("mean_test_f1", ascending=False)
res.columns = [c.replace("param_", "").replace("mean_test_", "") for c in cols]
res.to_csv("evidence/kd_gridsearch_results.csv", index=False)

log("\nTop 5 combinations (by F1):")
log(res.head(5).round(4).to_string(index=False))
log(f"\nWorst combination F1: {res['f1'].min():.4f}  (shows how much tuning matters)")

best = search.best_params_
b = res.iloc[0]
log(f"\nBEST PARAMETERS: {best}")
base = pd.read_csv("evidence/kd_cv_baseline.csv", index_col=0)
comp = pd.DataFrame({
    "XGBoost default": base.loc["XGBoost", ["accuracy", "precision", "recall", "f1", "roc_auc"]].values,
    "XGBoost tuned":   [b.accuracy, b.precision, b.recall, b.f1, b.roc_auc],
    "Random Forest":   base.loc["Random Forest", ["accuracy", "precision", "recall", "f1", "roc_auc"]].values,
}, index=["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]).round(4)
log("\nComparison (5-fold CV means, training set):")
log(comp.to_string())

json.dump(best, open("models/kd_xgb_tuned_params.json", "w"), indent=2)
with open("evidence/kd_gridsearch_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print("\nSaved: models/kd_xgb_tuned_params.json, evidence/kd_gridsearch_results.csv, evidence/kd_gridsearch_report.txt")