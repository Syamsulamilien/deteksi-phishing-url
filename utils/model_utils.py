"""Utilitas load model, prediksi, dan data pendukung untuk aplikasi Flask."""

import json
import pickle
from pathlib import Path

import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "model_topfeatures"
DATA_DIR = BASE_DIR / "data"

_model = None
_feature_names = None
_metrics = None
_dataset_summary = None
_viz_sample = None


def load_model():
    global _model, _feature_names
    if _model is None:
        _model = joblib.load(MODEL_DIR / "rf_phishing_model_topfeatures.pkl")
        with open(MODEL_DIR / "feature_names_topfeatures.pkl", "rb") as f:
            _feature_names = pickle.load(f)
    return _model, _feature_names


def load_metrics():
    global _metrics
    if _metrics is None:
        with open(DATA_DIR / "model_metrics.json") as f:
            _metrics = json.load(f)
    return _metrics


def load_dataset_summary():
    global _dataset_summary
    if _dataset_summary is None:
        with open(DATA_DIR / "dataset_summary.json") as f:
            _dataset_summary = json.load(f)
    return _dataset_summary


def load_viz_sample():
    global _viz_sample
    if _viz_sample is None:
        _viz_sample = pd.read_csv(DATA_DIR / "viz_sample.csv")
    return _viz_sample


def predict_url(features: dict, model, feature_names: list):
    X = pd.DataFrame([[features[f] for f in feature_names]], columns=feature_names)
    proba = model.predict_proba(X)[0]
    classes = list(model.classes_)
    idx_phish = classes.index(0)
    idx_legit = classes.index(1)
    proba_phish = float(proba[idx_phish])
    proba_legit = float(proba[idx_legit])
    label = "Phishing" if proba_phish >= proba_legit else "Legitimate"
    return label, proba_phish, proba_legit


def top_contributing_features(features: dict, feature_importance: list, top_n: int = 8):
    result = []
    for name, importance in feature_importance[:top_n]:
        result.append({"fitur": name, "nilai": features.get(name), "importance": round(importance, 4)})
    return result
