"""
Ekstraksi fitur dari sebuah URL "hidup" (live) agar bisa diprediksi oleh model Random Forest
versi TOP-15 FITUR (hasil eksperimen feature selection — lihat notebook
Eksperimen_Top_Feature_Importance.ipynb).

PERUBAHAN PENTING dibanding versi 50-fitur sebelumnya:
Model versi ini HANYA memakai 15 fitur dengan feature importance tertinggi. Setelah dianalisis
(lihat notebook, bagian 3.6), fitur `URLSimilarityIndex` sengaja DIKECUALIKAN dari pemilihan
karena ditemukan berkorelasi hampir sempurna dengan label (indikasi data leakage bawaan
metodologi dataset asli) — fitur ini juga salah satu yang sebelumnya hanya bisa diestimasi
kasar (heuristik) secara real-time, sehingga membuang fitur ini sekaligus menghilangkan
kebutuhan akan seluruh pendekatan heuristik yang dipakai versi sebelumnya:
    - TLDLegitimateProb (lookup tabel TLD) -> TIDAK DIPAKAI LAGI
    - URLCharProb (distribusi karakter)     -> TIDAK DIPAKAI LAGI
    - URLSimilarityIndex (heuristik similarity) -> TIDAK DIPAKAI LAGI

Seluruh 15 fitur yang tersisa dapat dihitung secara LANGSUNG dan AKURAT (bukan estimasi),
baik dari string URL maupun dari konten HTML halaman:

    Berbasis URL (5 fitur): URLLength, IsHTTPS, DegitRatioInURL, NoOfDegitsInURL,
                             NoOfOtherSpecialCharsInURL
    Berbasis HTML (10 fitur): NoOfExternalRef, LineOfCode, NoOfSelfRef, NoOfImage, NoOfJS,
                              HasSocialNet, NoOfCSS, HasCopyrightInfo, LargestLineLength,
                              HasDescription

Ini adalah penyederhanaan besar dibanding versi 50-fitur: tidak ada lagi pendekatan/estimasi
yang perlu didokumentasikan sebagai keterbatasan model — seluruh fitur dihitung dengan cara
yang identik dengan bagaimana fitur tersebut dihitung pada dataset training.

Metode pengambilan halaman tetap memakai headless browser (Playwright + Chromium) sebagai
metode utama, karena kebutuhan menjalankan JavaScript dan mengumpulkan konten dari dalam
<iframe> tetap relevan untuk fitur-fitur berbasis HTML (lihat riwayat perbaikan Bab IX laporan:
domain-matching, bot-block detection, iframe aggregation, dsb — seluruh perbaikan itu tetap
dipertahankan pada versi ini).
"""

import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

SOCIAL_DOMAINS = [
    "facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com",
    "youtube.com", "tiktok.com", "pinterest.com", "whatsapp.com", "telegram.org",
    "reddit.com", "snapchat.com",
]

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
}

BOT_BLOCK_MARKERS = [
    "captcha", "verify you are human", "unusual traffic", "access denied",
    "checking your browser", "just a moment", "cf-browser-verification",
    "are you a robot", "enable javascript and cookies", "robot check",
    "pardon our interruption", "reference error", "request unsuccessful",
    "incident id", "distil", "perimeterx", "px-captcha", "datadome",
    "access to this page has been denied", "bot detection", "automated access",
]

CONSENT_WALL_MARKERS = [
    "before you continue", "we value your privacy", "accept all cookies",
    "cookie consent", "manage cookies", "consent.microsoft.com",
    "we use cookies", "privacy preference", "accept cookies to continue",
    "gdpr", "onetrust", "cookiebot",
]

CONSENT_BUTTON_TEXTS = [
    "Accept all", "Accept All", "Accept All Cookies", "Accept cookies", "Accept",
    "I agree", "I Agree", "Agree", "Allow all", "Allow All", "Got it", "OK",
    "Setuju", "Terima Semua", "Terima semua", "Saya Setuju", "Terima",
]


def _normalize_domain(d: str) -> str:
    d = d.lower()
    return d[4:] if d.startswith("www.") else d


def _looks_bot_blocked(html: str) -> bool:
    stripped = html.strip()
    if len(stripped) < 800:
        return True
    # Kata kunci block/interstitial cuma relevan untuk halaman PENDEK (ciri khas halaman
    # CAPTCHA/challenge beneran). Halaman besar yang kebetulan mengandung kata seperti
    # "access denied" di footer/ToS TIDAK dianggap bot-blocked.
    if len(stripped) < 6000:
        text = html.lower()
        return any(marker in text for marker in BOT_BLOCK_MARKERS)
    return False


def _looks_consent_wall(html: str) -> bool:
    text = html.lower()
    if len(html.strip()) < 3000 and any(marker in text for marker in CONSENT_WALL_MARKERS):
        return True
    return False


def extract_url_string_features(url: str) -> dict:
    """Hitung 5 fitur berbasis string URL yang termasuk dalam top-15 fitur model."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    scheme = parsed.scheme or "http"
    domain = parsed.netloc.split("@")[-1].split(":")[0]
    full_url = url

    digits = sum(c.isdigit() for c in full_url)
    n = len(full_url) if full_url else 1
    other_special = len(re.findall(r"[^a-zA-Z0-9:/.\-_%?=&]", full_url))

    feats = {
        "URLLength": len(full_url),
        "IsHTTPS": 1 if scheme == "https" else 0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / n,
        "NoOfOtherSpecialCharsInURL": other_special,
    }
    return feats, domain, scheme


def _fetch_page(url: str, timeout: int = 10):
    """Fallback: HTTP request biasa (tidak menjalankan JavaScript)."""
    try:
        resp = requests.get(url, headers=BROWSER_HEADERS, timeout=timeout, allow_redirects=True)
        return resp.text, resp.status_code, resp.url, len(resp.history), None
    except requests.exceptions.RequestException as e:
        return None, None, None, 0, str(e)


def _fetch_page_playwright(url: str, timeout_ms: int = 20000):
    """
    Metode utama: render halaman pakai headless Chromium (Playwright), termasuk
    menjalankan JavaScript dan mencoba menutup cookie-consent wall otomatis.
    Return (html, status_code, final_url, n_redirect, error).
    """
    if not PLAYWRIGHT_AVAILABLE:
        return None, None, None, 0, "Playwright tidak terinstall"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
            context = browser.new_context(
                user_agent=BROWSER_HEADERS["User-Agent"],
                viewport={"width": 1366, "height": 768},
                locale="id-ID",
            )
            page = context.new_page()

            status_code = None
            n_redirect = 0
            try:
                response = page.goto(url, timeout=timeout_ms, wait_until="load")
            except Exception:
                try:
                    response = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                except Exception as e2:
                    browser.close()
                    return None, None, None, 0, str(e2)

            if response is not None:
                status_code = response.status
                req = response.request
                while req.redirected_from is not None:
                    n_redirect += 1
                    req = req.redirected_from

            # Tunggu jaringan idle SEBAGAI BONUS (bukan syarat wajib) — situs dengan aktivitas
            # latar belakang terus-menerus (live ticker, iklan, analytics) tidak akan pernah
            # betul-betul "idle", jadi kita lanjut saja setelah timeout singkat, ditambah buffer
            # waktu tetap untuk memberi kesempatan JavaScript menyelesaikan render.
            try:
                page.wait_for_load_state("networkidle", timeout=6000)
            except Exception:
                pass
            page.wait_for_timeout(2000)

            # Coba tutup cookie-consent wall otomatis kalau ada (best-effort)
            for text in CONSENT_BUTTON_TEXTS:
                try:
                    btn = page.locator(f"button:has-text('{text}')").first
                    if btn.is_visible(timeout=800):
                        btn.click(timeout=1200)
                        page.wait_for_timeout(1200)
                        break
                except Exception:
                    continue

            # Gabungkan HTML dari SEMUA frame (dokumen utama + iframe di dalamnya), karena
            # banyak situs memuat konten utama (feed, gambar, link) di dalam <iframe> yang
            # merupakan dokumen terpisah dari halaman utama.
            frame_htmls = []
            for frame in page.frames:
                try:
                    frame_htmls.append(frame.content())
                except Exception:
                    continue
            html = "\n".join(frame_htmls) if frame_htmls else page.content()
            final_url = page.url
            browser.close()
            return html, status_code, final_url, n_redirect, None
    except Exception as e:
        return None, None, None, 0, str(e)


def _analyze_html(html: str, domain: str) -> dict:
    """Analisis HTML menjadi 10 fitur berbasis konten yang termasuk top-15 fitur model."""
    bot_blocked = _looks_bot_blocked(html)
    consent_wall = _looks_consent_wall(html)
    lines = html.splitlines() or [""]
    soup = BeautifulSoup(html, "html.parser")

    has_description = 1 if soup.find("meta", attrs={"name": "description"}) else 0
    social = 1 if any(s in html.lower() for s in SOCIAL_DOMAINS) else 0

    text_lower = html.lower()
    has_copyright = 1 if ("©" in html or "copyright" in text_lower) else 0

    imgs = soup.find_all("img")
    css_links = soup.find_all("link", rel=lambda x: x and "stylesheet" in x.lower())
    style_tags = soup.find_all("style")
    scripts = soup.find_all("script")

    norm_domain = _normalize_domain(domain)
    links = soup.find_all("a", href=True)
    self_ref = external_ref = 0
    for a in links:
        href = a["href"].strip()
        if href in ("", "#"):
            continue
        elif href.startswith("http") and norm_domain not in _normalize_domain(urlparse(href).netloc):
            external_ref += 1
        elif href.startswith("//") and norm_domain not in _normalize_domain(href[2:].split("/")[0]):
            external_ref += 1
        else:
            self_ref += 1

    feats = {
        "LineOfCode": len(lines),
        "LargestLineLength": max(len(l) for l in lines),
        "HasDescription": has_description,
        "HasSocialNet": social,
        "HasCopyrightInfo": has_copyright,
        "NoOfImage": len(imgs),
        "NoOfCSS": len(css_links) + len(style_tags),
        "NoOfJS": len(scripts),
        "NoOfSelfRef": self_ref,
        "NoOfExternalRef": external_ref,
    }
    extra = {"bot_blocked": bot_blocked, "consent_wall": consent_wall, "html_length": len(html)}
    return feats, extra


def extract_html_features(url: str, domain: str) -> dict:
    """
    Ambil fitur berbasis konten HTML. Prioritas: headless browser (Playwright, JS dijalankan
    penuh) -> fallback HTTP request biasa kalau browser gagal.
    """
    default = {
        "LineOfCode": 50, "LargestLineLength": 200, "HasDescription": 0, "HasSocialNet": 0,
        "HasCopyrightInfo": 0, "NoOfImage": 0, "NoOfCSS": 0, "NoOfJS": 0, "NoOfSelfRef": 0,
        "NoOfExternalRef": 0,
    }

    render_method = "playwright"
    html, status_code, final_url, n_redirect, error = _fetch_page_playwright(url)

    if html is None:
        render_method = "requests_fallback"
        html, status_code, final_url, n_redirect, error = _fetch_page(url)

    if html is None or (status_code is not None and status_code >= 400):
        return default, {
            "fetched": False, "error": error, "status_code": status_code,
            "render_method": render_method,
        }

    feats, extra = _analyze_html(html, domain)

    meta = {
        "fetched": True, "status_code": status_code, "final_url": final_url,
        "bot_blocked": extra["bot_blocked"], "consent_wall": extra["consent_wall"],
        "html_length": extra["html_length"], "render_method": render_method,
    }
    return feats, meta


def extract_all_features(url: str, feature_names: list):
    """Ekstraksi lengkap: gabungkan fitur URL + fitur HTML, urutkan sesuai feature_names model."""
    url = url.strip()
    if not url:
        raise ValueError("URL kosong")
    if "://" not in url:
        url = "http://" + url

    string_feats, domain, scheme = extract_url_string_features(url)
    html_feats, meta = extract_html_features(url, domain)

    all_feats = {**string_feats, **html_feats}
    ordered = {name: all_feats.get(name, 0) for name in feature_names}
    return ordered, meta, domain
