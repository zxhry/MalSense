"""
Information about the deployed scanner model for the admin "ML model" page (Figure 5.13, UC09),
plus retraining.
"""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime

BASE = os.path.join(os.path.dirname(__file__), "..")
MODEL = os.path.join(BASE, "models", "malsense_scanner.joblib")
METRICS = os.path.join(BASE, "models", "scanner_metrics.json")
DATA = os.path.join(BASE, "data", "processed", "kd_features.csv")
BACKUP = os.path.join(BASE, "models", "backup")


def _compute_metrics(bundle):
    """Evaluate the current model on the same 20% test split used in training (if no saved metrics yet)."""
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
    df = pd.read_csv(DATA, low_memory=False)
    X, y = df[bundle["features"]], df["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, stratify=y, random_state=42)
    prob = bundle["model"].predict_proba(bundle["preprocess"].transform(X_test))[:, 1]
    pred = (prob >= bundle.get("threshold", 0.5)).astype(int)
    m = {"accuracy": accuracy_score(y_test, pred), "precision": precision_score(y_test, pred),
         "recall": recall_score(y_test, pred), "f1": f1_score(y_test, pred), "roc_auc": roc_auc_score(y_test, prob),
         "n_total": int(len(df)), "n_train": int(len(y_train)), "n_test": int(len(y_test)),
         "n_features": len(bundle["features"]), "n_malware": int(y.sum()), "n_benign": int((y == 0).sum()),
         "trained_at": datetime.fromtimestamp(os.path.getmtime(MODEL)).strftime("%Y-%m-%d %H:%M:%S")}
    json.dump(m, open(METRICS, "w"), indent=2)
    return m


def get_model_info(bundle):
    m = None
    if os.path.exists(METRICS) and os.path.getmtime(METRICS) >= os.path.getmtime(MODEL) - 5:
        m = json.load(open(METRICS))
    elif os.path.exists(DATA):
        m = _compute_metrics(bundle)
    n_perm = sum(1 for f in bundle["features"] if f.isupper())
    params = bundle.get("xgb_params", {})
    return {
        "algorithm": "XGBoost (binary classifier)",
        "dataset": "KronoDroid - real-device version (Guerra-Manzanares et al., 2021)",
        "samples": f"{m['n_total']:,} apps ({m['n_malware']:,} malware / {m['n_benign']:,} benign)" if m else "-",
        "classes": "Malware = 1, Benign = 0",
        "features": f"{len(bundle['features'])} static features ({n_perm} permissions + "
                    f"{len(bundle['features']) - n_perm} counts, e.g. activities, services, file size)",
        "split": f"80% / 20% stratified ({m['n_train']:,} train / {m['n_test']:,} test)" if m else "80% / 20%",
        "params": ", ".join(f"{k}={v}" for k, v in params.items()) or "-",
        "trained": datetime.strptime(m["trained_at"], "%Y-%m-%d %H:%M:%S").strftime("%d %B %Y, %H:%M") if m else
                   datetime.fromtimestamp(os.path.getmtime(MODEL)).strftime("%d %B %Y, %H:%M"),
        "status": "Active",
        "metrics": m,
        "new_samples": _new_samples(m),
        "can_retrain": os.path.exists(DATA),
    }


def _new_samples(m):
    try:
        import new_samples
        s = new_samples.summary(m["trained_at"] if m else None)
    except Exception:
        return None
    s["in_model"] = m.get("n_new_samples", 0) if m else 0
    s["learned"] = m.get("n_new_learned", 0) if m else 0
    return s


def backup_model():
    """Copy the current model + metrics to models/backup/<date-time>/ before retraining."""
    folder = os.path.join(BACKUP, datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(folder, exist_ok=True)
    for f in (MODEL, METRICS):
        if os.path.exists(f):
            shutil.copy2(f, folder)
    return folder


def retrain():
    """Back up the current model, then run the training script again (about 1 minute).
    The training script uses KronoDroid + the new samples in data/new_samples.csv. Returns (ok, message)."""
    folder = backup_model()
    script = os.path.join(BASE, "src", "train_scanner_model.py")
    r = subprocess.run([sys.executable, script], cwd=BASE, capture_output=True, text=True, timeout=900)
    if r.returncode == 2:                                  # safety check in the script refused the new model
        return False, r.stderr.strip()[-300:]
    if r.returncode != 0:
        return False, (r.stderr or r.stdout)[-400:]
    try:
        m = json.load(open(METRICS))
        extra = (f" It learned from {m['n_new_samples']} new sample(s) "
                 f"({m['n_new_learned']} now classified correctly).") if m.get("n_new_samples") else ""
        return True, f"Model retrained successfully - test accuracy {m['accuracy']:.2%}.{extra}"
    except Exception:
        return True, f"Model retrained successfully. Previous model saved in models/backup/{os.path.basename(folder)}."