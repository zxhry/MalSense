"""
Thesis experiment 2 - MALWARE TYPE model on CICMalDroid 2020 (static: permissions, intents, API calls).
Same design as kd_three_rounds.py (supervisor's instruction): 3 rounds x 3 models, all models in a
round use the SAME split.  Round 1 = 70/30, Round 2 = 80/20, Round 3 = 90/10, stratified, seed 42.

Task: given an app that is ALREADY classified as malware (by the KronoDroid model), predict its type:
      Adware / Banking / SMS malware / Riskware   (benign apps are not used here)
Classes are unbalanced, so every model uses balanced class weights, and the main score is MACRO F1
(each type counts equally, so the small SMS class is not hidden by the large Adware class).
Features are 0/1, so no scaling is needed (same input for all three models).

Input : data/processed/cmd_features.csv.gz, cmd_feature_list.txt  (from cmd_build_features.py)
Output: evidence/cmd_type_model/
This script does NOT touch the website's models.
"""
import json, os, time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             confusion_matrix, ConfusionMatrixDisplay, classification_report)
from xgboost import XGBClassifier

P, OUT = "data/processed", "evidence/cmd_type_model"
os.makedirs(OUT, exist_ok=True)
RANDOM_STATE = 42
ROUNDS = [(1, "70/30", 0.30), (2, "80/20", 0.20), (3, "90/10", 0.10)]
TYPES = ["Adware", "Banking", "SMS malware", "Riskware"]           # classes 1-4 -> 0-3
TUNED = "models/cmd_xgb_tuned_params.json"                      # from cmd_tune_xgb.py
XGB_PARAMS = (json.load(open(TUNED)) if os.path.exists(TUNED)
              else {"n_estimators": 300, "max_depth": 6, "learning_rate": 0.1})
XGB_NAME = "XGBoost (tuned)" if os.path.exists(TUNED) else "XGBoost"
MODEL_ORDER = ["SVM (RBF)", "Random Forest", XGB_NAME]

df = pd.read_csv(f"{P}/cmd_features.csv.gz")
features = [f for f in open(f"{P}/cmd_feature_list.txt").read().splitlines() if f]
df = df[df["class"] != 5]
X, y = df[features].to_numpy(), (df["class"] - 1).to_numpy()

report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

def make_models():
    return {"SVM (RBF)": SVC(kernel="rbf", class_weight="balanced", random_state=RANDOM_STATE),
            "Random Forest": RandomForestClassifier(n_estimators=300, class_weight="balanced",
                                                    n_jobs=-1, random_state=RANDOM_STATE),
            XGB_NAME: XGBClassifier(**XGB_PARAMS, eval_metric="mlogloss", n_jobs=-1, random_state=RANDOM_STATE)}

log("=== THESIS EXPERIMENT 2: MALWARE TYPE MODEL (CICMalDroid 2020) - 3 ROUNDS x 3 MODELS ===")
log(f"Apps: {len(y):,} unique malware apps | {len(features)} static 0/1 features "
    f"(permissions, intent actions/categories, sensitive API calls)")
log("Per type: " + ", ".join(f"{t} {int((y == i).sum()):,}" for i, t in enumerate(TYPES)))
log(f"Balanced class weights for all models | main score = macro F1 | {XGB_NAME} parameters: {XGB_PARAMS}\n")

rows = []
for rnd, label, ts in ROUNDS:
    log(f"---------------- ROUND {rnd}: {label} split ----------------")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=ts, stratify=y, random_state=RANDOM_STATE)
    log(f"Train {len(y_tr):,} | Test {len(y_te):,} (" +
        ", ".join(f"{t} {int((y_te == i).sum())}" for i, t in enumerate(TYPES)) + ")")
    preds = {}
    for name, m in make_models().items():
        t = time.time()
        if name == XGB_NAME:
            m.fit(X_tr, y_tr, sample_weight=compute_sample_weight("balanced", y_tr))
        else:
            m.fit(X_tr, y_tr)
        fit_s = time.time() - t
        p = m.predict(X_te); preds[name] = p
        f1s = f1_score(y_te, p, average=None, labels=range(4))
        row = {"Round": rnd, "Split": label, "Model": name,
               "Accuracy": accuracy_score(y_te, p),
               "Macro precision": precision_score(y_te, p, average="macro", zero_division=0),
               "Macro recall": recall_score(y_te, p, average="macro"),
               "Macro F1": f1_score(y_te, p, average="macro"),
               **{f"F1 {t}": f for t, f in zip(TYPES, f1s)}, "Train time (s)": round(fit_s, 1)}
        rows.append(row)
        log(f"  {name:<14} Accuracy {row['Accuracy']:.4f} | Macro F1 {row['Macro F1']:.4f} | " +
            " | ".join(f"{t} {f:.2f}" for t, f in zip(TYPES, f1s)))
    best = max(MODEL_ORDER, key=lambda n: f1_score(y_te, preds[n], average="macro"))
    log(f"Best macro F1 in round {rnd}: {best}")
    log("Per-type detail for the best model:")
    log(classification_report(y_te, preds[best], target_names=TYPES, digits=3))
    fig, axes = plt.subplots(1, 3, figsize=(17, 5))
    for ax, name in zip(axes, MODEL_ORDER):
        ConfusionMatrixDisplay(confusion_matrix(y_te, preds[name], labels=range(4)),
                               display_labels=TYPES).plot(ax=ax, colorbar=False)
        ax.set_title(name); ax.tick_params(axis="x", rotation=30)
    plt.suptitle(f"Malware type model - round {rnd} ({label}) - confusion matrices (test set)")
    plt.tight_layout(); plt.savefig(f"{OUT}/round{rnd}_confusion_matrices.png", dpi=150); plt.close()

res = pd.DataFrame(rows)
res.round(4).to_csv(f"{OUT}/all_rounds_results.csv", index=False)
log("================ SUMMARY: ALL 3 ROUNDS ================")
piv = res.pivot(index="Model", columns="Split", values="Macro F1")[["70/30", "80/20", "90/10"]].loc[MODEL_ORDER]
log("Macro F1 by round:"); log(piv.round(4).to_string())
cols = ["Accuracy", "Macro precision", "Macro recall", "Macro F1"]
mean, std = res.groupby("Model")[cols].mean().loc[MODEL_ORDER], res.groupby("Model")[cols].std().loc[MODEL_ORDER]
log("\nMean ± std over the 3 rounds:")
log((mean.round(4).astype(str) + " ± " + std.round(4).astype(str)).to_string())
log("\nPer-type F1, mean over 3 rounds:")
log(res.groupby("Model")[[f"F1 {t}" for t in TYPES]].mean().loc[MODEL_ORDER].round(3).to_string())
log(f"\nOverall best (mean macro F1): {mean['Macro F1'].idxmax()}")
with open(f"{OUT}/cmd_three_rounds_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print(f"\nSaved to {OUT}/")
