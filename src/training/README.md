# Training and research scripts

These scripts were used to build and evaluate the MalSense models (thesis Chapter 4). The website does not
import them. Run them from the project folder, for example:

    python src/training/kd_three_rounds.py

- `load_dataset.py`, `inspect_kronodroid.py`, `clean_dataset.py`, `build_features.py`, `feature_ranking.py`,
  `split_scale.py`, `kd_split_preprocess.py`: prepare the KronoDroid data
- `kd_cv_baseline.py`, `kd_tune_xgb.py`, `kd_final_evaluation.py`, `kd_three_rounds.py`: compare SVM, Random Forest
  and XGBoost (three train/test splits: 70/30, 80/20, 90/10)
- `inspect_cicmaldroid.py`, `cmd_*.py`: CICMalDroid 2020 feature list (intents and API calls)
- `inspect_apk.py`, `explain_demo.py`, `show_examples.py`, `check_env.py`: small checks and demos

`src/train_scanner_model.py` stays in `src/` because the admin "Retrain" button runs it.
