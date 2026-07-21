from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from feature_extractor import URLFeatureExtractor


class PhishingDetectionPipeline:
    MODEL_DIR = Path("models")
    MODEL_PATH = MODEL_DIR / "phishguard.joblib"
    METADATA_PATH = MODEL_DIR / "metadata.json"

    def __init__(self) -> None:
        self.extractor = URLFeatureExtractor()
        self.model: Any | None = None
        self.metadata: dict[str, Any] = {}
        self.MODEL_DIR.mkdir(exist_ok=True)
        self.load_model()

    def load_model(self) -> bool:
        if not self.MODEL_PATH.exists():
            return False
        bundle = joblib.load(self.MODEL_PATH)
        self.model = bundle["model"]
        self.metadata = bundle.get("metadata", {})
        return True

    def save_model(self) -> None:
        joblib.dump({"model": self.model, "metadata": self.metadata}, self.MODEL_PATH)
        self.METADATA_PATH.write_text(json.dumps(self.metadata, indent=2), encoding="utf-8")

    def predict(self, url: str) -> dict[str, Any]:
        normalized = self.extractor.normalize(url)
        features = self.extractor.extract_features(normalized)
        reasons = self.extractor.explain(features)

        if self.model is not None:
            frame = pd.DataFrame([features])
            probability = float(self.model.predict_proba(frame)[0][1])
            engine = "machine_learning"
        else:
            probability = self._heuristic_probability(features, reasons)
            engine = "validated_heuristic_fallback"

        risk_score = int(round(probability * 100))
        prediction = "phishing" if probability >= 0.5 else "legitimate"
        risk_level = "critical" if risk_score >= 85 else "high" if risk_score >= 65 else "medium" if risk_score >= 35 else "low"

        return {
            "url": normalized,
            "prediction": prediction,
            "confidence": round(max(probability, 1 - probability) * 100, 2),
            "phishing_probability": round(probability * 100, 2),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "engine": engine,
            "reasons": reasons[:6],
            "features": features,
            "disclaimer": "This result is a decision-support signal, not a guarantee that a URL is safe or malicious.",
        }

    def predict_batch(self, urls: Iterable[str]) -> list[dict[str, Any]]:
        return [self.predict(url) for url in urls]

    def train_model(self, urls: list[str], labels: list[int]) -> dict[str, Any]:
        if len(urls) != len(labels) or len(urls) < 20:
            raise ValueError("Training requires at least 20 URLs with matching labels")
        if len(set(labels)) < 2:
            raise ValueError("Both legitimate and phishing labels are required")

        frame = pd.DataFrame([self.extractor.extract_features(url) for url in urls])
        target = np.asarray(labels, dtype=int)
        X_train, X_test, y_train, y_test = train_test_split(
            frame, target, test_size=0.25, random_state=42, stratify=target
        )

        candidates = {
            "logistic_regression": Pipeline([
                ("scale", StandardScaler()),
                ("model", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
            ]),
            "random_forest": RandomForestClassifier(
                n_estimators=350, min_samples_leaf=2, class_weight="balanced_subsample",
                random_state=42, n_jobs=-1,
            ),
        }
        folds = min(5, max(2, int(np.bincount(target).min())))
        cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
        comparison: dict[str, Any] = {}
        best_name = ""
        best_score = -1.0
        best_model: Any = None

        for name, candidate in candidates.items():
            scores = cross_validate(candidate, frame, target, cv=cv, scoring=["accuracy", "precision", "recall", "f1", "roc_auc"])
            summary = {metric.replace("test_", ""): round(float(values.mean()), 4) for metric, values in scores.items() if metric.startswith("test_")}
            comparison[name] = summary
            if summary["f1"] > best_score:
                best_score = summary["f1"]
                best_name = name
                best_model = candidate

        best_model.fit(X_train, y_train)
        predictions = best_model.predict(X_test)
        probabilities = best_model.predict_proba(X_test)[:, 1]
        holdout = {
            "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
            "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
            "roc_auc": round(float(roc_auc_score(y_test, probabilities)), 4),
        }
        best_model.fit(frame, target)
        self.model = best_model
        self.metadata = {
            "model_name": best_name,
            "samples": len(urls),
            "feature_count": frame.shape[1],
            "cross_validation": comparison,
            "holdout_metrics": holdout,
            "dataset_note": "Metrics are meaningful only for the dataset supplied during training.",
        }
        self.save_model()
        return self.metadata

    def get_model_info(self) -> dict[str, Any]:
        return {
            "loaded": self.model is not None,
            "engine": "machine_learning" if self.model is not None else "validated_heuristic_fallback",
            **self.metadata,
        }

    @staticmethod
    def _heuristic_probability(features: dict[str, float], reasons: list[dict[str, Any]]) -> float:
        score = sum(item["weight"] for item in reasons)
        if features.get("at_count", 0):
            score += 12
        if features.get("phishing_term_count", 0) >= 2:
            score += 8
        score = min(100, score)
        # Calibrated sigmoid: moderate evidence remains uncertain; stacked signals rise quickly.
        return float(1 / (1 + math.exp(-(score - 34) / 11)))


pipeline = PhishingDetectionPipeline()
