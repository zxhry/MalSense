import sys, os, platform, psutil

print("Python    :", sys.version.split()[0], "|", platform.system())
print("Using venv:", sys.prefix != sys.base_prefix)

for lib in ["pandas", "pyarrow", "numpy", "sklearn", "xgboost", "imblearn", "matplotlib", "seaborn"]:
    try:
        m = __import__(lib)
        print(f"  OK  {lib:<11} {m.__version__}")
    except Exception as e:
        print(f"  FAIL {lib:<11} {e}")

ram = psutil.virtual_memory()
print(f"RAM total {ram.total/1e9:.1f} GB | available now {ram.available/1e9:.1f} GB")

path = "data/raw/cicandmal2020-static.parquet"
print("Dataset found:", os.path.exists(path),
      f"({os.path.getsize(path)/1e6:.1f} MB)" if os.path.exists(path) else "")