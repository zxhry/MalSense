"""
Train the FINAL malware type model for the website (after the thesis experiments chose XGBoost).
Trained on ALL 1,913 unique malware apps (the experiments already measured how well it generalises).
Saved in XGBoost's own JSON format, so it loads the same on Windows/Linux and across XGBoost versions.

Input : data/processed/cmd_features.csv.gz, cmd_feature_list.txt, models/cmd_xgb_tuned_params.json
Output: models/cmd_type_model.json (the model), models/cmd_type_model_info.json (types, features, params)
"""
import json
import pandas as pd
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

P = "data/processed"
TYPES = ["Adware", "Banking", "SMS malware", "Riskware"]
df = pd.read_csv(f"{P}/cmd_features.csv.gz")
features = [f for f in open(f"{P}/cmd_feature_list.txt").read().splitlines() if f]
df = df[df["class"] != 5]
X, y = df[features].to_numpy(), (df["class"] - 1).to_numpy()
params = json.load(open("models/cmd_xgb_tuned_params.json"))

model = XGBClassifier(**params, eval_metric="mlogloss", n_jobs=-1, random_state=42)
model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
model.save_model("models/cmd_type_model.json")
json.dump({"types": TYPES, "features": features, "params": params, "n_apps": int(len(y)),
           "per_type": {t: int((y == i).sum()) for i, t in enumerate(TYPES)},
           "dataset": "CICMalDroid 2020 (static: permissions, intents, sensitive API calls)"},
          open("models/cmd_type_model_info.json", "w"), indent=2)
print(f"Saved models/cmd_type_model.json - trained on {len(y):,} malware apps, {len(features)} features")
