document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("scan-form");
  const input = document.getElementById("url-input");
  const btn = document.getElementById("scan-btn");
  const btnLabel = document.getElementById("btn-label");
  const resultArea = document.getElementById("result-area");
  const errorArea = document.getElementById("error-area");
  const errorText = document.getElementById("error-text");
  const fetchWarning = document.getElementById("fetch-warning");

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return;

    resultArea.style.display = "none";
    errorArea.style.display = "none";
    fetchWarning.innerHTML = "";
    btn.disabled = true;
    btnLabel.innerHTML = '<span class="spinner"></span>';

    try {
      const resp = await fetch("/api/cek-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url }),
      });
      const data = await resp.json();

      if (!resp.ok) {
        errorText.textContent = data.error || "Terjadi kesalahan.";
        errorArea.style.display = "block";
        return;
      }

      renderResult(data);
      resultArea.style.display = "block";
    } catch (err) {
      errorText.textContent = "Gagal menghubungi server: " + err.message;
      errorArea.style.display = "block";
    } finally {
      btn.disabled = false;
      btnLabel.textContent = "Cek";
    }
  });

  function renderResult(data) {
    const badge = document.getElementById("verdict-badge");
    const verdictText = document.getElementById("verdict-text");
    const domainCaption = document.getElementById("domain-caption");
    const gaugeValue = document.getElementById("gauge-value");
    const gaugeCaption = document.getElementById("gauge-caption");

    const isPhish = data.label === "Phishing";
    badge.className = "verdict-badge " + (isPhish ? "phish" : "legit");
    verdictText.textContent = isPhish ? "🚨 PHISHING" : "✅ LEGITIMATE";
    domainCaption.textContent = data.domain || "";

    const renderBadge = document.getElementById("render-method-badge");
    const meta0 = data.meta || {};
    if (meta0.render_method === "playwright") {
      renderBadge.innerHTML = "🌐 Dirender dengan headless browser (JavaScript dieksekusi penuh)";
    } else if (meta0.render_method === "requests_fallback") {
      renderBadge.innerHTML = "⚡ Fallback: HTTP request biasa (browser gagal dijalankan, JavaScript tidak dieksekusi)";
    } else {
      renderBadge.textContent = "";
    }

    const scoreShown = isPhish ? data.proba_phish : data.proba_legit;
    const gaugeScore = data.proba_phish; // gauge selalu representasikan skor risiko phishing

    const color = drawGauge("gauge-canvas", gaugeScore);
    gaugeValue.textContent = gaugeScore.toFixed(1) + "%";
    gaugeValue.style.color = color;
    gaugeCaption.textContent = "SKOR RISIKO PHISHING · " + (isPhish ? "TERINDIKASI PHISHING" : "TERINDIKASI AMAN");

    // Fetch / bot-block warning
    fetchWarning.innerHTML = "";
    const meta = data.meta || {};
    if (meta.fetched === false) {
      fetchWarning.innerHTML = `<div class="callout warn">⚠️ Halaman tidak berhasil diakses langsung (${meta.error || "tidak diketahui"}). Prediksi tetap dilakukan menggunakan fitur berbasis URL saja; fitur berbasis konten HTML diisi nilai default netral, sehingga akurasi bisa lebih rendah.</div>`;
    } else if (meta.bot_blocked) {
      fetchWarning.innerHTML = `<div class="callout warn">⚠️ <strong>Halaman kemungkinan memblokir akses otomatis (anti-bot) atau merupakan aplikasi web modern yang kontennya dimuat lewat JavaScript</strong> (halaman HTML yang diterima sangat singkat/berisi indikasi CAPTCHA). Ini sering terjadi pada situs besar seperti e-commerce (Shopee, Tokopedia, Booking.com dll) yang punya proteksi bot ketat. <strong>Akibatnya, fitur berbasis konten tidak terbaca dengan benar dan bisa membuat situs legitimate salah diprediksi sebagai phishing.</strong> Jangan jadikan hasil ini sebagai satu-satunya acuan — verifikasi manual domain resminya.</div>`;
    } else if (meta.consent_wall) {
      fetchWarning.innerHTML = `<div class="callout warn">⚠️ <strong>Sistem mendeteksi halaman "cookie consent" / persetujuan privasi</strong>, bukan konten asli situs (umum terjadi pada situs Microsoft seperti MSN, atau situs Eropa yang menerapkan GDPR). Halaman consent ini sangat sederhana sehingga fitur berbasis konten (jumlah gambar, script, link) jadi rendah — mirip pola situs phishing. <strong>Hasil prediksi untuk kasus ini kemungkinan besar tidak akurat</strong> — verifikasi manual domain resminya.</div>`;
    }

    // Top features
    const topFeaturesEl = document.getElementById("top-features");
    topFeaturesEl.innerHTML = "";
    const maxImportance = Math.max(...data.top_features.map((f) => f.importance));
    data.top_features.forEach((f) => {
      const pct = (f.importance / maxImportance) * 100;
      const row = document.createElement("div");
      row.className = "feat-row";
      row.innerHTML = `
        <div class="name">${f.fitur_id || f.fitur}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
        <div class="pct">${f.nilai}</div>
      `;
      topFeaturesEl.appendChild(row);
    });

    // Key features (sekarang menampilkan seluruh 15 fitur model)
    const keyFeaturesEl = document.getElementById("key-features");
    keyFeaturesEl.innerHTML = "";
    data.key_features.forEach((kf) => {
      const item = document.createElement("div");
      item.className = "kv-item";
      item.innerHTML = `<div class="k">${kf.nama_id}</div><div class="v">${kf.nilai}</div>`;
      keyFeaturesEl.appendChild(item);
    });

    document.getElementById("meta-info").textContent = JSON.stringify(data.meta, null, 2);
  }
});
