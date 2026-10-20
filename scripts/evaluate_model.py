"""Train PhishGuard on a public labeled URL dataset and compare it with the heuristic fallback.

Dataset: faizann24/Using-machine-learning-to-detect-malicious-URLs (data/data.csv, ~420K URLs, labels good/bad).
Usage:  python scripts/evaluate_model.py data.csv --sample 50000
"""
import argparse, json, sys, time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml_pipeline import PhishingDetectionPipeline  # noqa: E402


def metrics(y, p):
    return {"accuracy": round(accuracy_score(y, p), 4), "precision": round(precision_score(y, p, zero_division=0), 4),
            "recall": round(recall_score(y, p, zero_division=0), 4), "f1": round(f1_score(y, p, zero_division=0), 4)}


ap = argparse.ArgumentParser()
ap.add_argument("csv"); ap.add_argument("--sample", type=int, default=50000); ap.add_argument("--seed", type=int, default=42)
a = ap.parse_args()

df = pd.read_csv(a.csv).dropna().drop_duplicates("url")
df["y"] = (df["label"].str.lower() == "bad").astype(int)
pipe = PhishingDetectionPipeline(); pipe.model = None
ok = []
for u in df["url"]:
    try: pipe.extractor.normalize(u); ok.append(True)
    except ValueError: ok.append(False)
df = df[ok]
if a.sample < len(df):
    df, _ = train_test_split(df, train_size=a.sample, random_state=a.seed, stratify=df["y"])
urls, labels = df["url"].tolist(), df["y"].tolist()
print(f"Sample: {len(urls)} URLs, {sum(labels)} malicious ({sum(labels)/len(labels):.1%})")

# Same split train_model uses (test_size=0.25, random_state=42, stratified) -> heuristic baseline on the identical holdout
idx = np.arange(len(urls))
_, test_idx = train_test_split(idx, test_size=0.25, random_state=42, stratify=labels)
t0 = time.perf_counter()
heur = [1 if pipe.predict(urls[i])["prediction"] == "phishing" else 0 for i in test_idx]
heur_s = time.perf_counter() - t0
baseline = metrics([labels[i] for i in test_idx], heur)

t0 = time.perf_counter()
meta = pipe.train_model(urls, labels)
train_s = time.perf_counter() - t0

result = {"samples": len(urls), "heuristic_holdout": baseline, "model": meta["model_name"],
          "cross_validation": meta["cross_validation"], "model_holdout": meta["holdout_metrics"],
          "f1_gain_points": round((meta["holdout_metrics"]["f1"] - baseline["f1"]) * 100, 1),
          "heuristic_urls_per_sec": round(len(test_idx) / heur_s), "train_seconds": round(train_s, 1)}
print(json.dumps(result, indent=2))
Path("models/evaluation.json").write_text(json.dumps(result, indent=2))
