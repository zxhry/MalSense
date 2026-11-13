"""
Explainable AI demo: explain the model's decision for real apps from the KronoDroid TEST set
(one malware, one benign) - no APK file needed, so no real malware is ever downloaded.
Also checks that the explanation is mathematically consistent with the prediction.
Usage: python src/training/explain_demo.py
"""
import os, sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))   # src/ (explain.py)
from explain import explain
import xgboost as xgb

bundle = joblib.load("models/malsense_scanner.joblib")
df = pd.read_csv("data/processed/kd_features.csv", low_memory=False)
_, test = train_test_split(df, test_size=0.20, stratify=df["label"], random_state=42)  # same split as training

def show(row, title):
    feats = {f: row[f] for f in bundle["features"]}
    X = bundle["preprocess"].transform(pd.DataFrame([feats])[bundle["features"]])
    prob = bundle["model"].predict_proba(X)[0, 1]
    contrib = bundle["model"].get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[0]
    check = 1 / (1 + np.exp(-contrib.sum()))           # SHAP values + base must give the same probability
    print(f"\n=== {title} | true label: {'MALWARE' if row['label'] else 'BENIGN'} | family: {row['MalFamily']} ===")
    print(f"Model malware probability: {prob:.1%}   (rebuilt from explanation: {check:.1%})")
    for e in explain(bundle, feats):
        arrow = "-> MALWARE" if e["direction"] == "malware" else "-> SAFE   "
        print(f"  {arrow} {e['score']:+.2f}  {e['label']} ({e['value']})" + (f"  [lets an app {e['meaning']}]" if e["meaning"] else ""))

mal = test[(test.label == 1) & (test.MalFamily.str.contains("SMS", na=False))].iloc[0]
ben = test[test.label == 0].iloc[0]
show(mal, "Example 1 - a malware app from the test set")
show(ben, "Example 2 - a benign app from the test set")