"""
Script untuk regenerasi seluruh file di folder data/ menggunakan model TOP-15 FITUR
(hasil eksperimen di notebook Eksperimen_Top_Feature_Importance.ipynb).

Jalankan dari root folder proyek flask_app:
    python scripts/precompute_topfeatures.py

Membutuhkan:
    - scripts/PhiUSIIL_Phishing_URL_Dataset.csv (dataset asli)
    - model_topfeatures/rf_phishing_model_topfeatures.pkl
    - model_topfeatures/feature_names_topfeatures.pkl
"""

import json
import pickle
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "scripts" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "model_topfeatures" / "rf_phishing_model_topfeatures.pkl"
FEATURE_NAMES_PATH = ROOT / "model_topfeatures" / "feature_names_topfeatures.pkl"
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

# 50 fitur asli dibutuhkan untuk proses pembersihan data yang konsisten dengan training awal
ALL_50_FEATURES = [
    "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex", "CharContinuationRate",
    "TLDLegitimateProb", "URLCharProb", "TLDLength", "NoOfSubDomain", "HasObfuscation",
    "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL", "NoOfEqualsInURL", "NoOfQMarkInURL",
    "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
    "LineOfCode", "LargestLineLength", "HasTitle", "DomainTitleMatchScore",
    "URLTitleMatchScore", "HasFavicon", "Robots", "IsResponsive", "NoOfURLRedirect",
    "NoOfSelfRedirect", "HasDescription", "NoOfPopup", "NoOfiFrame",
    "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton", "HasHiddenFields",
    "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo", "NoOfImage",
    "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
]


def fix_score(v):
    """Perbaiki nilai skor (URLSimilarityIndex dkk) yang rusak akibat locale/grouping saat ekspor CSV."""
    if pd.isna(v):
        return None
    v = str(v).strip()
    if v == "":
        return None
    if "," in v and v.count(",") == 1 and "." not in v:
        v = v.replace(",", ".")
    ndots = v.count(".")
    if ndots <= 1:
        try:
            return float(v)
        except ValueError:
            return None
    digits = v.replace(".", "").replace(",", "")
    if not digits.isdigit():
        return None
    if len(digits) <= 2:
        return float(digits)
    try:
        return float(digits[:2] + "." + digits[2:])
    except ValueError:
        return None


def load_and_clean():
    print("Membaca CSV...")
    df = pd.read_csv(CSV_PATH, sep=";", low_memory=False, dtype=str)
    df = df.loc[:, ~df.columns.str.startswith("Unnamed")]
    print("Ukuran mentah:", df.shape)

    df = df[df["label"].isin(["0", "1", "0.0", "1.0"])].copy()
    df["label"] = df["label"].astype(float).astype(int)

    score_cols = ["URLSimilarityIndex", "URLTitleMatchScore", "DomainTitleMatchScore"]
    for col in score_cols:
        df[col] = df[col].apply(fix_score).clip(0, 100)

    other_cols = [c for c in ALL_50_FEATURES if c not in score_cols]
    for c in other_cols:
        df[c] = df[c].astype(str).str.replace(",", ".", regex=False)
        df[c] = pd.to_numeric(df[c], errors="coerce")

    before = len(df)
    df = df.dropna(subset=ALL_50_FEATURES)
    print(f"Dibuang {before - len(df)} baris dengan nilai fitur tidak valid, sisa {len(df)}")
    return df


def main():
    with open(FEATURE_NAMES_PATH, "rb") as f:
        top_features = pickle.load(f)
    model = joblib.load(MODEL_PATH)
    print(f"Model dimuat, menggunakan {len(top_features)} fitur: {top_features}")

    df = load_and_clean()

    # ---- Ringkasan dataset ----
    summary = {
        "total_rows": int(len(df)),
        "total_features_raw": int(df.shape[1]),
        "total_model_features": len(top_features),
        "label_counts": {
            "Legitimate (1)": int((df["label"] == 1).sum()),
            "Phishing (0)": int((df["label"] == 0).sum()),
        },
        "label_pct": {
            "Legitimate": round(float((df["label"] == 1).mean() * 100), 2),
            "Phishing": round(float((df["label"] == 0).mean() * 100), 2),
        },
        "top_tlds": df["TLD"].value_counts().head(10).to_dict(),
    }
    with open(DATA_DIR / "dataset_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("dataset_summary.json disimpan")

    # ---- Evaluasi model (top-N fitur) ----
    X, y = df[top_features], df["label"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pred = model.predict(Xte)
    proba = model.predict_proba(Xte)[:, 1]

    metrics = {
        "n_test": len(yte),
        "accuracy": accuracy_score(yte, pred),
        "precision": precision_score(yte, pred),
        "recall": recall_score(yte, pred),
        "f1": f1_score(yte, pred),
        "auc": roc_auc_score(yte, proba),
        "confusion_matrix": confusion_matrix(yte, pred).tolist(),
        "label_map": {"0": "Phishing", "1": "Legitimate"},
        "feature_importance": sorted(
            zip(top_features, model.feature_importances_.tolist()), key=lambda x: -x[1]
        ),
    }
    with open(DATA_DIR / "model_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    print("model_metrics.json disimpan")

    # ---- Sampel untuk visualisasi (hanya top-N fitur + label + TLD) ----
    cols_for_viz = list(dict.fromkeys(top_features + ["label", "TLD", "IsHTTPS"]))
    n_per_class = min(8000, (df["label"] == 0).sum(), (df["label"] == 1).sum())
    leg = df[df["label"] == 1].sample(n_per_class, random_state=42)
    phi = df[df["label"] == 0].sample(n_per_class, random_state=42)
    sample = pd.concat([leg, phi], ignore_index=True)[cols_for_viz]
    sample.to_csv(DATA_DIR / "viz_sample.csv", index=False)
    print("viz_sample.csv disimpan, shape:", sample.shape)

    print("\nSelesai! Semua file di folder data/ sudah diperbarui untuk model top-N fitur.")


if __name__ == "__main__":
    main()
