import sys
import json
import time
from pathlib import Path

import numpy as np
from flask import Flask, render_template, request, jsonify

sys.path.append(str(Path(__file__).resolve().parent))
from utils.model_utils import (
    load_model, load_metrics, load_dataset_summary, load_viz_sample,
    predict_url, top_contributing_features,
)
from utils.feature_extraction import extract_all_features

app = Flask(__name__)

# Muat model & data sekali saat aplikasi start
model, feature_names = load_model()
metrics = load_metrics()
dataset_summary = load_dataset_summary()
viz_df = load_viz_sample()

with open(Path(__file__).resolve().parent / "data" / "feature_labels_id.json", encoding="utf-8") as f:
    FEATURE_LABELS_ID = json.load(f)


def label_id(name: str) -> str:
    """Nama Indonesia untuk sebuah fitur, fallback ke nama asli kalau tidak ada di kamus."""
    return FEATURE_LABELS_ID.get(name, {}).get("label", name)


app.jinja_env.globals["label_id"] = label_id
app.jinja_env.globals["FEATURE_LABELS"] = FEATURE_LABELS_ID


@app.route("/api/feature-labels")
def api_feature_labels():
    return jsonify(FEATURE_LABELS_ID)


@app.route("/")
def home():
    return render_template(
        "index.html", active="home",
        summary=dataset_summary, metrics=metrics,
    )


@app.route("/cek-url")
def check_url_page():
    return render_template("check_url.html", active="check")


@app.route("/api/cek-url", methods=["POST"])
def api_check_url():
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"error": "URL kosong."}), 400

    t0 = time.time()
    try:
        features, meta, domain = extract_all_features(url, feature_names)
        label, proba_phish, proba_legit = predict_url(features, model, feature_names)
    except Exception as e:
        return jsonify({"error": f"Gagal memproses URL: {e}"}), 400
    elapsed = round(time.time() - t0, 2)

    top_feats = top_contributing_features(features, metrics["feature_importance"], top_n=8)
    for item in top_feats:
        item["fitur_id"] = label_id(item["fitur"])

    # Model sekarang hanya memakai 15 fitur (hasil seleksi top feature importance), sehingga
    # seluruh fitur yang dipakai model sudah relevan untuk ditampilkan sebagai "fitur kunci" —
    # tidak perlu lagi kurasi subset seperti pada versi 50-fitur sebelumnya.
    key_features = [
        {"nama": k, "nama_id": label_id(k), "nilai": features.get(k)}
        for k in feature_names
    ]
    all_features_id = [
        {"nama": k, "nama_id": label_id(k), "nilai": v}
        for k, v in features.items()
    ]

    return jsonify({
        "label": label,
        "proba_phish": round(proba_phish * 100, 1),
        "proba_legit": round(proba_legit * 100, 1),
        "domain": domain,
        "meta": meta,
        "top_features": top_feats,
        "key_features": key_features,
        "all_features": features,
        "all_features_id": all_features_id,
        "elapsed": elapsed,
    })


@app.route("/dataset")
def dataset_page():
    return render_template("dataset_summary.html", active="dataset", summary=dataset_summary)


@app.route("/visualisasi")
def visualisasi_page():
    def hist(col, bins=30):
        leg = viz_df[viz_df["label"] == 1][col].to_numpy()
        phi = viz_df[viz_df["label"] == 0][col].to_numpy()
        lo = float(min(leg.min(), phi.min()))
        hi = float(max(leg.max(), phi.max()))
        if hi == lo:
            hi = lo + 1
        edges = np.linspace(lo, hi, bins + 1)
        leg_counts, _ = np.histogram(leg, bins=edges)
        phi_counts, _ = np.histogram(phi, bins=edges)
        labels = [f"{edges[i]:.0f}" for i in range(bins)]
        return {"labels": labels, "legit": leg_counts.tolist(), "phish": phi_counts.tolist()}

    charts = {
        "urllength": hist("URLLength"),
        "noofexternalref": hist("NoOfExternalRef"),
        "lineofcode": hist("LineOfCode"),
    }

    https_ct = viz_df.groupby(["label", "IsHTTPS"]).size().unstack(fill_value=0)
    https_data = {
        "legit_https": int(https_ct.loc[1, 1]) if 1 in https_ct.columns and 1 in https_ct.index else 0,
        "legit_no": int(https_ct.loc[1, 0]) if 0 in https_ct.columns and 1 in https_ct.index else 0,
        "phish_https": int(https_ct.loc[0, 1]) if 1 in https_ct.columns and 0 in https_ct.index else 0,
        "phish_no": int(https_ct.loc[0, 0]) if 0 in https_ct.columns and 0 in https_ct.index else 0,
    }

    numeric_cols = sorted([
        c for c in viz_df.columns
        if c not in ("label", "TLD") and viz_df[c].dtype != object
    ])
    numeric_cols_labeled = [(c, label_id(c)) for c in numeric_cols]

    return render_template(
        "visualisasi.html", active="visualisasi",
        charts=charts, https_data=https_data, numeric_cols=numeric_cols_labeled,
        label_urllength=label_id("URLLength"), label_extref=label_id("NoOfExternalRef"),
        label_loc=label_id("LineOfCode"),
    )


@app.route("/api/histogram/<col>")
def api_histogram(col):
    if col not in viz_df.columns:
        return jsonify({"error": "kolom tidak ditemukan"}), 404
    bins = 30
    leg = viz_df[viz_df["label"] == 1][col].to_numpy()
    phi = viz_df[viz_df["label"] == 0][col].to_numpy()
    lo = float(min(leg.min(), phi.min()))
    hi = float(max(leg.max(), phi.max()))
    if hi == lo:
        hi = lo + 1
    edges = np.linspace(lo, hi, bins + 1)
    leg_counts, _ = np.histogram(leg, bins=edges)
    phi_counts, _ = np.histogram(phi, bins=edges)
    labels = [f"{edges[i]:.1f}" for i in range(bins)]
    return jsonify({"labels": labels, "legit": leg_counts.tolist(), "phish": phi_counts.tolist(), "label_id": label_id(col)})


@app.route("/evaluasi")
def evaluasi_page():
    cm = metrics["confusion_matrix"]
    return render_template("evaluasi.html", active="evaluasi", metrics=metrics, cm=cm)


@app.route("/feature-importance")
def feature_importance_page():
    fi = metrics["feature_importance"]
    explanations = {
        "NoOfExternalRef": "Jumlah link yang mengarah ke domain lain. Situs phishing sering menyalin resource dari situs asli yang ditirunya, sehingga polanya berbeda dari situs legitimate.",
        "LineOfCode": "Jumlah baris kode HTML halaman. Situs phishing seringkali punya halaman lebih sederhana karena hanya meniru tampilan login, bukan seluruh situs.",
        "NoOfSelfRef": "Jumlah link internal (ke halaman lain di domain yang sama). Situs legitimate umumnya punya struktur navigasi internal lebih kaya.",
        "NoOfImage": "Jumlah gambar pada halaman, berkaitan dengan kompleksitas dan kelengkapan desain situs.",
        "NoOfJS": "Jumlah script JavaScript, mencerminkan kompleksitas fungsionalitas halaman.",
        "HasSocialNet": "Apakah halaman menautkan ke media sosial resmi. Situs legitimate umumnya menautkan akun sosial resminya.",
        "NoOfCSS": "Jumlah file/style CSS yang dimuat, mencerminkan kompleksitas desain visual.",
        "HasCopyrightInfo": "Apakah halaman mencantumkan info hak cipta — sering absen pada situs phishing yang buru-buru dibuat.",
        "IsHTTPS": "Apakah situs menggunakan koneksi terenkripsi HTTPS — banyak (bukan semua) situs phishing tidak memakainya.",
        "HasDescription": "Apakah halaman punya meta description — indikasi situs dikelola/dioptimasi secara profesional.",
    }
    top15 = fi[:15]
    top15_labeled = [(name, importance, label_id(name)) for name, importance in top15]
    top8_labeled = [(name, importance, label_id(name)) for name, importance in fi[:8]]
    return render_template(
        "feature_importance.html", active="feature-importance",
        top15=top15, top8=fi[:8], top15_labeled=top15_labeled, top8_labeled=top8_labeled,
        explanations=explanations,
    )


@app.route("/insight")
def insight_page():
    https_phish = float(viz_df[viz_df["label"] == 0]["IsHTTPS"].mean())
    https_legit = float(viz_df[viz_df["label"] == 1]["IsHTTPS"].mean())
    image_phish = float(viz_df[viz_df["label"] == 0]["NoOfImage"].mean())
    image_legit = float(viz_df[viz_df["label"] == 1]["NoOfImage"].mean())
    extref_phish = float(viz_df[viz_df["label"] == 0]["NoOfExternalRef"].mean())
    extref_legit = float(viz_df[viz_df["label"] == 1]["NoOfExternalRef"].mean())

    stats = {
        "https_phish": round(https_phish * 100), "https_legit": round(https_legit * 100),
        "image_phish": round(image_phish, 2), "image_legit": round(image_legit, 2),
        "extref_phish": round(extref_phish, 1), "extref_legit": round(extref_legit, 1),
    }
    return render_template("insight.html", active="insight", stats=stats, metrics=metrics)


@app.route("/dokumentasi")
def dokumentasi_page():
    return render_template("dokumentasi.html", active="dokumentasi")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
