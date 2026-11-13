"""
Thesis experiment - 3 ROUNDS x 3 MODELS (SVM, Random Forest, XGBoost)
Supervisor's instruction: 3 rounds, every round involves all 3 models, and all
models in a round use the SAME data (same train/test split).

  Round 1 = 70/30   Round 2 = 80/20   Round 3 = 90/10

Everything else is identical to the existing pipeline:
  - data/processed/kd_features.csv (165 static features, KronoDroid real device)
  - stratified split, random_state = 42
  - median imputation + min-max scaling, FITTED ON EACH ROUND'S TRAINING SET ONLY
  - same model settings as kd_final_evaluation.py (XGBoost uses the tuned params)
Round 2 uses the same split as the original 80/20 run, so its numbers should match
evidence/kd_final_report.txt (a built-in consistency check).

This script does NOT touch the models used by the website (models/*.joblib).

Run from the MalSense folder:   python src/training/kd_three_rounds.py
Output: evidence/three_rounds/
"""
import json, os, time
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
                             roc_auc_score, roc_curve, confusion_matrix, ConfusionMatrixDisplay)
from xgboost import XGBClassifier

P = "data/processed"
OUT = "evidence/three_rounds"
os.makedirs(OUT, exist_ok=True)
RANDOM_STATE = 42
ROUNDS = [(1, "70/30", 0.30), (2, "80/20", 0.20), (3, "90/10", 0.10)]
MODEL_ORDER = ["SVM (RBF)", "Random Forest", "XGBoost (tuned)"]

df = pd.read_csv(f"{P}/kd_features.csv", low_memory=False)
features = [f for f in open(f"{P}/kd_feature_list.txt").read().splitlines() if f.strip()]
X, y = df[features], df["label"]
best = json.load(open("models/kd_xgb_tuned_params.json"))

report = []
def log(msg=""):
    print(msg, flush=True); report.append(str(msg))

def make_models():
    return {
        "SVM (RBF)":       SVC(kernel="rbf", random_state=RANDOM_STATE),
        "Random Forest":   RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=RANDOM_STATE),
        "XGBoost (tuned)": XGBClassifier(**best, eval_metric="logloss", n_jobs=-1, random_state=RANDOM_STATE),
    }

log("=== THESIS EXPERIMENT: 3 ROUNDS x 3 MODELS (same data for all models in a round) ===")
log(f"Dataset: KronoDroid real device | {len(y):,} apps | {len(features)} static features | "
    f"malware {int(y.sum()):,} ({y.mean():.2%}) | benign {int((y == 0).sum()):,}")
log(f"XGBoost tuned parameters: {best}")
log("Random Forest: 300 trees | SVM: RBF kernel | random_state = 42 everywhere\n")

all_rows = []
start_all = time.time()
for rnd, label, test_size in ROUNDS:
    log(f"---------------- ROUND {rnd}: {label} split ----------------")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=test_size, stratify=y,
                                              random_state=RANDOM_STATE)
    prep = Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", MinMaxScaler())])
    prep.fit(X_tr)                                   # fitted on THIS round's training set only
    X_tr = pd.DataFrame(prep.transform(X_tr), columns=features)
    X_te = pd.DataFrame(prep.transform(X_te), columns=features)
    log(f"Train: {len(y_tr):,} apps (malware {int(y_tr.sum()):,}) | "
        f"Test: {len(y_te):,} apps (malware {int(y_te.sum()):,})")

    preds, scores = {}, {}
    for name, model in make_models().items():
        log(f"  Training {name}..." + ("  (slowest, a few minutes)" if "SVM" in name else ""))
        t = time.time(); model.fit(X_tr, y_tr); fit_s = time.time() - t
        t = time.time()
        pred = model.predict(X_te)
        score = (model.predict_proba(X_te)[:, 1] if hasattr(model, "predict_proba")
                 else model.decision_function(X_te))
        ms = (time.time() - t) / len(X_te) * 1000
        preds[name], scores[name] = pred, score
        tn, fp, fn, tp = confusion_matrix(y_te, pred).ravel()
        row = {"Round": rnd, "Split": label, "Model": name,
               "Train apps": len(y_tr), "Test apps": len(y_te),
               "Accuracy": accuracy_score(y_te, pred), "Precision": precision_score(y_te, pred),
               "Recall": recall_score(y_te, pred), "F1": f1_score(y_te, pred),
               "ROC-AUC": roc_auc_score(y_te, score),
               "TP": tp, "TN": tn, "FP (false alarms)": fp, "FN (missed malware)": fn,
               "Train time (s)": round(fit_s, 1), "Predict ms/app": round(ms, 3)}
        all_rows.append(row)
        log(f"     Accuracy {row['Accuracy']:.4f} | Precision {row['Precision']:.4f} | "
            f"Recall {row['Recall']:.4f} | F1 {row['F1']:.4f} | {fit_s:.1f}s")

    rdf = pd.DataFrame([r for r in all_rows if r["Round"] == rnd]).set_index("Model")
    rdf.drop(columns=["Round", "Split"]).round(4).to_csv(f"{OUT}/round{rnd}_{label.replace('/', '-')}_results.csv")
    log(f"\nROUND {rnd} ({label}) RESULTS")
    log(rdf[["Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "FP (false alarms)",
             "FN (missed malware)", "Train time (s)"]].round(4).to_string())
    log(f"Best F1 in round {rnd}: {rdf['F1'].idxmax()}\n")

    # confusion matrices (one figure per round)
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    for ax, name in zip(axes, MODEL_ORDER):
        ConfusionMatrixDisplay(confusion_matrix(y_te, preds[name]),
                               display_labels=["Benign", "Malware"]).plot(ax=ax, colorbar=False, values_format=",")
        ax.set_title(name)
    plt.suptitle(f"Round {rnd} ({label} split) - confusion matrices on the test set")
    plt.tight_layout(); plt.savefig(f"{OUT}/round{rnd}_confusion_matrices.png", dpi=150); plt.close()

    # ROC curves (one figure per round)
    plt.figure(figsize=(6, 5))
    for name in MODEL_ORDER:
        fpr, tpr, _ = roc_curve(y_te, scores[name])
        plt.plot(fpr, tpr, label=f"{name} (AUC = {roc_auc_score(y_te, scores[name]):.4f})")
    plt.plot([0, 1], [0, 1], "k--", lw=1)
    plt.xlabel("False positive rate"); plt.ylabel("True positive rate (recall)")
    plt.title(f"Round {rnd} ({label}) - ROC curves"); plt.legend(loc="lower right"); plt.grid(alpha=.3)
    plt.tight_layout(); plt.savefig(f"{OUT}/round{rnd}_roc_curves.png", dpi=150); plt.close()

# ---------------- Summary across the 3 rounds ----------------
res = pd.DataFrame(all_rows)
res.round(4).to_csv(f"{OUT}/all_rounds_results.csv", index=False)
metrics = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC"]

log("================ SUMMARY: ALL 3 ROUNDS ================")
for m in ["Accuracy", "F1", "Recall"]:
    piv = res.pivot(index="Model", columns="Split", values=m)[["70/30", "80/20", "90/10"]].loc[MODEL_ORDER]
    log(f"\n{m} by round:")
    log(piv.round(4).to_string())

mean = res.groupby("Model")[metrics].mean().loc[MODEL_ORDER]
std = res.groupby("Model")[metrics].std().loc[MODEL_ORDER]
summary = mean.round(4).astype(str) + " ± " + std.round(4).astype(str)
summary.to_csv(f"{OUT}/summary_mean_std.csv")
log("\nAverage over the 3 rounds (mean ± standard deviation):")
log(summary.to_string())

winners = res.loc[res.groupby("Round")["F1"].idxmax(), ["Round", "Split", "Model", "F1"]]
log("\nBest model (by F1) in each round:")
log(winners.round(4).to_string(index=False))
log(f"Best average F1 over all rounds: {mean['F1'].idxmax()} ({mean['F1'].max():.4f})")
log(f"\nTarget (>90% accuracy and >90% recall) in every round: " + ", ".join(
    f"{n}: {'MET' if ((g.Accuracy > .9) & (g.Recall > .9)).all() else 'NOT met'}"
    for n, g in res.groupby("Model")))

# grouped bar charts: one chart per metric, bars = models, groups = rounds
fig, axes = plt.subplots(1, 3, figsize=(16, 4.8))
for ax, m in zip(axes, ["Accuracy", "Recall", "F1"]):
    piv = res.pivot(index="Split", columns="Model", values=m).loc[["70/30", "80/20", "90/10"], MODEL_ORDER]
    piv.plot(kind="bar", ax=ax, rot=0, width=0.8)
    ax.set_title(f"{m} by round"); ax.set_xlabel("Round (train/test split)"); ax.set_ylabel(m)
    ax.set_ylim(max(0.85, piv.values.min() - 0.02), 1.0); ax.grid(axis="y", alpha=.3)
    ax.legend(fontsize=8, loc="lower right")
    for c in ax.containers:
        ax.bar_label(c, fmt="%.3f", fontsize=7, rotation=90, padding=2)
plt.suptitle("SVM vs Random Forest vs XGBoost across 3 rounds")
plt.tight_layout(); plt.savefig(f"{OUT}/summary_metrics_by_round.png", dpi=150); plt.close()

log(f"\nTotal time: {(time.time() - start_all) / 60:.1f} minutes")
with open(f"{OUT}/three_rounds_report.txt", "w", encoding="utf-8") as fh:
    fh.write("\n".join(report))
print(f"\nSaved everything in {OUT}/")
