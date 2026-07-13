# 🛡️ Aplikasi Deteksi Phishing URL (Versi Flask — Top 15 Fitur)

Versi Flask dari aplikasi deteksi phishing URL, dengan desain custom (bukan Streamlit default).
Menggunakan model Random Forest yang dilatih pada dataset PhiUSIIL Phishing URL Dataset, **kini
hanya memakai 15 fitur dengan feature importance tertinggi** (hasil eksperimen feature
selection — lihat notebook `Eksperimen_Top_Feature_Importance.ipynb`), bukan 50 fitur seperti
versi sebelumnya.

## Cara Menjalankan

```bash
# 1. Buat virtual environment (opsional tapi disarankan)
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 2. Install dependencies Python
pip install -r requirements.txt

# 3. WAJIB: install browser Chromium untuk Playwright (headless browser)
playwright install chromium

# 4. Jalankan aplikasi
python app.py
```

Buka `http://localhost:5000` di browser.

**Penting:** Langkah `playwright install chromium` WAJIB dijalankan sekali setelah
`pip install`, karena `pip install playwright` hanya menginstall library Python-nya saja,
belum termasuk browser binary-nya. Kalau langkah ini terlewat, fitur Cek URL akan otomatis
fallback ke HTTP request biasa (kurang akurat untuk situs berat JavaScript), bukan error —
tapi kualitas deteksinya akan menurun. Cek panel "render_method" pada hasil Cek URL untuk
memastikan apakah Playwright dipakai (`playwright`) atau fallback (`requests_fallback`).

## Struktur Folder

```
flask_app/
├── app.py                          # Aplikasi Flask utama (semua routes)
├── templates/                      # Template HTML (Jinja2)
│   ├── base.html                    # Kerangka + sidebar navigasi
│   ├── index.html                   # Beranda
│   ├── check_url.html               # Cek URL (fitur utama)
│   ├── dataset_summary.html         # Ringkasan Dataset
│   ├── visualisasi.html             # Visualisasi Data
│   ├── evaluasi.html                # Evaluasi Model
│   ├── feature_importance.html      # Feature Importance
│   ├── insight.html                 # Insight & Rekomendasi
│   └── dokumentasi.html             # Dokumentasi + Analisis Keamanan
├── static/
│   ├── css/style.css                # Desain custom (dark navy + teal/coral accent)
│   └── js/
│       ├── main.js                   # Tab switcher
│       ├── gauge.js                  # Gauge radial (canvas) untuk skor risiko
│       └── check_url.js              # Logic AJAX untuk Cek URL
├── utils/
│   ├── feature_extraction.py        # Ekstraksi 15 fitur dari URL live (disederhanakan)
│   └── model_utils.py               # Load model, prediksi, load data pendukung
├── model_topfeatures/                # Model AKTIF (15 fitur) — dipakai aplikasi
│   ├── rf_phishing_model_topfeatures.pkl
│   ├── feature_names_topfeatures.pkl
│   └── comparison_result.json        # Hasil perbandingan vs model 50-fitur
├── model_50features_backup/          # Model LAMA (50 fitur) — disimpan sebagai arsip/referensi
│   ├── rf_phishing_model.pkl
│   └── feature_names.pkl
├── data/                              # Data hasil precompute untuk model AKTIF (15 fitur)
│   ├── dataset_summary.json
│   ├── model_metrics.json
│   ├── feature_labels_id.json         # Terjemahan Indonesia (superset 50 nama, aman dipakai)
│   └── viz_sample.csv
├── scripts/
│   ├── precompute_topfeatures.py     # Script AKTIF — regenerasi data/ untuk model 15-fitur
│   └── precompute_50features_legacy.py  # Script lama (50-fitur), disimpan sebagai referensi
└── requirements.txt
```

## 🔑 Perubahan Besar: Model 50 Fitur → 15 Fitur

Setelah eksperimen feature selection (lihat notebook terpisah), aplikasi ini bermigrasi dari
model 50-fitur ke model **top-15 fitur** dengan importance tertinggi. Alasan dan dampaknya:

1. **Fitur `URLSimilarityIndex` sengaja dikecualikan** — analisis menemukan fitur ini
   berkorelasi hampir sempurna dengan label (99,4%–100%), indikasi kuat data leakage bawaan
   metodologi dataset asli, bukan sinyal yang independen dan dapat digeneralisasi ke URL baru.
   Tanpa pengecualian ini, model historisnya akan menunjukkan akurasi ~100% yang menyesatkan.
2. **Tidak ada lagi fitur yang memakai heuristik/estimasi kasar.** Versi 50-fitur sebelumnya
   harus mengestimasi `URLSimilarityIndex`, `TLDLegitimateProb`, dan `URLCharProb` secara kasar
   karena algoritma aslinya butuh basis data referensi jutaan URL yang tidak tersedia publik.
   Karena ketiganya tidak termasuk top-15, **`utils/feature_extraction.py` kini jauh lebih
   sederhana** — seluruh 15 fitur yang dipakai dihitung secara langsung dan akurat, tanpa
   pendekatan/tebakan sama sekali.
3. **Performa pada data historis nyaris tidak berubah** (akurasi turun dari 99,99% ke 99,97%,
   selisih ~0,03%), namun **performa pada URL dunia nyata justru membaik** — contoh nyata:
   `pypi.org` yang sebelumnya salah diprediksi Phishing oleh model 50-fitur, kini diprediksi
   **Legitimate dengan benar** oleh model 15-fitur.

Detail lengkap proses eksperimen (termasuk analisis data leakage) ada di notebook
`Eksperimen_Top_Feature_Importance.ipynb` (file terpisah, tidak disertakan dalam folder ini).

## Desain

Desain memakai konsep "laporan hasil scan" ala security operations:
- **Warna:** navy gelap (`#0B1220`) dengan aksen teal (`#35C79A`, aman) dan koral (`#FF5D5D`,
  bahaya) — warna ini fungsional, langsung merepresentasikan skor risiko.
- **Tipografi:** Space Grotesk (judul), Inter (body), JetBrains Mono (URL/data teknis).
- **Signature element:** gauge radial di halaman Cek URL yang menunjukkan skor risiko phishing,
  berubah warna teal → kuning → merah sesuai skor.

Untuk mengubah warna/tema, edit variabel CSS di bagian atas `static/css/style.css`
(`:root { --ink: ...; --safe: ...; --danger: ...; }`).

## Catatan Penting untuk Laporan

1. **Kualitas data mentah**: CSV asli punya bug locale export (koma vs titik desimal, skor
   similarity yang rusak grouping-nya) — sudah diperbaiki di kedua script precompute.
2. **Fitur pada halaman Cek URL** memakai **headless browser (Playwright + Chromium)** sebagai
   metode utama — JavaScript benar-benar dieksekusi sebelum fitur diekstrak (termasuk mencoba
   menutup cookie-consent wall otomatis dan mengumpulkan konten dari dalam iframe), jauh lebih
   akurat untuk situs modern (SPA) dibanding HTTP request biasa. Kalau Playwright gagal
   dijalankan, sistem otomatis fallback ke HTTP request biasa — cek field `render_method` pada
   hasil Cek URL (`playwright` atau `requests_fallback`).
3. **Temuan data leakage pada `URLSimilarityIndex`** (lihat bagian di atas) — cocok dibahas
   sebagai bagian analisis kritis di laporan (Bab IV/V terkait metode ML dan evaluasi model).
4. **Keterbatasan yang masih berlaku**: situs legitimate dengan desain sangat sederhana/minimalis
   tetap berisiko salah diprediksi, karena distribusi fitur pada data training bersifat
   bimodal/ekstrem (situs legitimate rata-rata punya puluhan-ratusan link eksternal/gambar,
   situs phishing rata-rata mendekati nol). Ini keterbatasan karakteristik data, bukan bug.
5. **Analisis keamanan TI** sudah disusun otomatis di halaman **Dokumentasi** — silakan
   salin/tulis ulang dengan bahasa sendiri ke laporan (poin 10 rancangan tugas, minimal 5 risiko).

## Regenerasi Data Precompute

Untuk model aktif (15 fitur) — perlu file `PhiUSIIL_Phishing_URL_Dataset.csv` di folder `scripts/`:
```bash
python scripts/precompute_topfeatures.py
```

Untuk model lama (50 fitur, referensi/perbandingan saja):
```bash
python scripts/precompute_50features_legacy.py
```
