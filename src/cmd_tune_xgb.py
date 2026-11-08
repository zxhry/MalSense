"""
Malware type model - tune XGBoost with Grid Search + 5-fold CV (same method as kd_tune_xgb.py).
Uses ONLY the training part of the 80/20 split (seed 42) - the test apps are never seen.
Selection metric = macro F1 (each malware type counts equally).
Balanced sample weights are used in every fit (classes are unbalanced).
Input : data/processed/cmd_features.csv.gz, cmd_feature_list.txt
Output: models/cmd_xgb_tuned_params.json, evidence/cmd_type_model/gridsearch_results.csv,
        evidence/cmd_type_model/gridsearch_report.txt
"""
import json, os, time
import pandas as pd
from sklearn.model_selection import StratifiedKFold, train_test_split, cross_validate
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

P, OUT = "data/processed", "evidence/cmd_type_model"
os.makedirs(OUT, exist_ok=True)
df = pd.read_csv(f"{P}/cmd_features.csv.gz")
features = [f for f in open(f"{P}/cmd_feature_list.txt").read().splitlines() if f]
df = df[df["class"] != 5]
X, y = df[features].to_numpy(), (df["class"] - 1).to_numpy()
X_tr, _, y_tr, _ = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)
w_tr = compute_sample_weight("balanced", y_tr)

report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

param_grid = {
    "max_depth":        [4, 6, 8],
    "learning_rate":    [0.05, 0.1, 0.2],
    "n_estimators":     [300, 600],
    "subsample":        [0.8, 1.0],
    "colsample_bytree": [0.5, 1.0],    # share of features each tree sees (helps with 369 sparse 0/1 features)
}
n_comb = 1
for v in param_grid.values():
    n_comb *= len(v)
scoring = {"f1_macro": "f1_macro", "recall_macro": "recall_macro",
           "precision_macro": "precision_macro", "accuracy": "accuracy"}
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

log("=== MALWARE TYPE MODEL: XGBOOST GRID SEARCH (training set of the 80/20 split only) ===")
log(f"Training apps: {len(y_tr):,} | features: {len(features)}")
log(f"Grid: {param_grid}")
log(f"{n_comb} combinations x 5 folds = {n_comb * 5} model fits\n")

# Baselines on the SAME folds, for the comparison table (cached so resuming is quick)
BASE = f"{OUT}/gridsearch_baselines.json"
base = json.load(open(BASE)) if os.path.exists(BASE) else {}
for name, est, fp in [("XGBoost default", XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                                                        eval_metric="mlogloss", n_jobs=-1, random_state=42),
                       {"sample_weight": w_tr}),
                      ("Random Forest", RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                                               n_jobs=-1, random_state=42), {})]:
    if name in base:
        continue
    r = cross_validate(est, X_tr, y_tr, cv=cv, scoring=scoring, params=fp)
    base[name] = {k: float(r[f"test_{k}"].mean()) for k in scoring}
    json.dump(base, open(BASE, "w"))

# Grid search done by hand (same as GridSearchCV: every combination x the same 5 folds), but
# each finished combination is saved, so the script can be stopped and resumed:
#   python src/cmd_tune_xgb.py              -> runs everything (resumes if a progress file exists)
#   python src/cmd_tune_xgb.py --budget 150 -> stops after ~150 s; run again to continue
import sys, itertools
from sklearn.model_selection import ParameterGrid
budget = float(sys.argv[sys.argv.index("--budget") + 1]) if "--budget" in sys.argv else None
PROG = f"{OUT}/gridsearch_progress.csv"
done = pd.read_csv(PROG) if os.path.exists(PROG) else pd.DataFrame()
grid = list(ParameterGrid(param_grid))
t = time.time()
for i, params in enumerate(grid):
    if len(done) and i in set(done["combo"]):
        continue
    if budget and time.time() - t > budget:
        print(f"Budget reached - {len(done)}/{len(grid)} combinations done. Run again to continue.")
        sys.exit(0)
    r = cross_validate(XGBClassifier(**params, eval_metric="mlogloss", n_jobs=-1, random_state=42),
                       X_tr, y_tr, cv=cv, scoring=scoring, params={"sample_weight": w_tr})
    row = {"combo": i, **params, **{k: r[f"test_{k}"].mean() for k in scoring},
           "std_f1_macro": r["test_f1_macro"].std(), "fit_time": r["fit_time"].mean()}
    done = pd.concat([done, pd.DataFrame([row])], ignore_index=True)
    done.to_csv(PROG, index=False)
    print(f"  {len(done):>2}/{len(grid)}  macro F1 {row['f1_macro']:.4f}  {params}", flush=True)
log(f"All {len(grid)} combinations done")

res = done.sort_values("f1_macro", ascending=False)
res = res[list(param_grid) + ["f1_macro", "std_f1_macro", "recall_macro", "precision_macro", "accuracy", "fit_time"]]
res.to_csv(f"{OUT}/gridsearch_results.csv", index=False)
log("\nTop 5 combinations (by macro F1):")
log(res.head(5).round(4).to_string(index=False))
log(f"\nWorst combination macro F1: {res['f1_macro'].min():.4f}")

b = res.iloc[0]
best = {k: (int(b[k]) if k in ("max_depth", "n_estimators") else float(b[k])) for k in param_grid}
log(f"\nBEST PARAMETERS: {best}")
comp = pd.DataFrame({
    "XGBoost default": [base["XGBoost default"][k] for k in scoring],
    "XGBoost tuned":   [b.f1_macro, b.recall_macro, b.precision_macro, b.accuracy],
    "Random Forest":   [base["Random Forest"][k] for k in scoring],
}, index=["Macro F1", "Macro recall", "Macro precision", "Accuracy"]).round(4)
log("\nComparison (5-fold CV means, training set):")
log(comp.to_string())

json.dump({k: (int(v) if float(v).is_integer() and k in ("max_depth", "n_estimators") else float(v))
           for k, v in best.items()},
          open("models/cmd_xgb_tuned_params.json", "w"), indent=2)
with open(f"{OUT}/gridsearch_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print(f"\nSaved: models/cmd_xgb_tuned_params.json, {OUT}/gridsearch_results.csv, {OUT}/gridsearch_report.txt")
