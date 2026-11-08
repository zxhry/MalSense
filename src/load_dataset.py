"""
Load CIC-AndMal2020 (static) without running out of memory.
Reads the parquet 250 columns at a time and stores only the non-zero values
(a 'sparse matrix'), because ~99.6% of the dataset is zeros.
"""
import os, time
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy import sparse
import psutil

RAW = "data/raw/cicandmal2020-static.parquet"
OUT = "data/processed"
os.makedirs(OUT, exist_ok=True)

def ram_used_mb():
    return psutil.Process().memory_info().rss / 1e6

start = time.time()
pf = pq.ParquetFile(RAW)
all_cols = pf.schema_arrow.names
feature_cols = [c for c in all_cols if c not in ("F0", "Label")]
print(f"Rows: {pf.metadata.num_rows:,} | Total columns: {len(all_cols):,} | Feature columns: {len(feature_cols):,}")

# 1) Small columns first: the APK hash (F0) and the category label
meta = pq.read_table(RAW, columns=["F0", "Label"]).to_pandas()
meta = meta.rename(columns={"F0": "sha256", "Label": "category"})
meta["label"] = (meta["category"] != "Benign").astype("int8")   # Malware = 1, Benign = 0

# 2) Feature columns in batches -> keep only non-zero cells
rows, cols, vals = [], [], []
missing = {}
BATCH = 250
for start_i in range(0, len(feature_cols), BATCH):
    names = feature_cols[start_i:start_i + BATCH]
    table = pq.read_table(RAW, columns=names)
    for j, col in enumerate(table.columns):
        a = col.to_numpy(zero_copy_only=False).astype("float32")
        n_nan = int(np.isnan(a).sum())
        if n_nan:
            missing[names[j]] = n_nan
        nz = np.flatnonzero(a)            # NaN counts as non-zero, so it is kept
        rows.append(nz.astype("int32"))
        cols.append(np.full(nz.size, start_i + j, dtype="int32"))
        vals.append(a[nz])
    del table
    print(f"  loaded columns {start_i:>5}-{start_i + len(names) - 1:<5} | RAM used {ram_used_mb():,.0f} MB")

X = sparse.csr_matrix(
    (np.concatenate(vals), (np.concatenate(rows), np.concatenate(cols))),
    shape=(len(meta), len(feature_cols)), dtype="float32")
del rows, cols, vals

# 3) Save in a fast, compact format for the next steps
sparse.save_npz(f"{OUT}/X_raw.npz", X)
meta.to_csv(f"{OUT}/meta.csv", index=False)
pd.Series(feature_cols).to_csv(f"{OUT}/feature_names.csv", index=False, header=["feature"])

print("\n===== SUMMARY =====")
print(f"X shape            : {X.shape}")
print(f"Non-zero values    : {X.nnz:,}  (density {X.nnz / (X.shape[0] * X.shape[1]):.4%})")
print(f"Sparse size in RAM : {(X.data.nbytes + X.indices.nbytes + X.indptr.nbytes) / 1e6:,.0f} MB")
print(f"Missing values     : {sum(missing.values())} in columns {missing}")
print("\nCategory counts:")
print(meta["category"].value_counts().to_string())
print("\nBinary label counts (1 = Malware, 0 = Benign):")
print(meta["label"].value_counts().to_string())
print(f"\nPeak RAM used: {ram_used_mb():,.0f} MB | Time: {time.time() - start:.0f} s")
print(f"Saved to: {OUT}/X_raw.npz, meta.csv, feature_names.csv")