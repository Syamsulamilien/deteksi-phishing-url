import os
from pathlib import Path
from urllib.parse import urlparse
import requests

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

try:
    from dotenv import load_dotenv
    load_dotenv(ENV_PATH, override=True)
except ImportError:
    pass

API_URL = "https://safebrowsing.googleapis.com/v5/urls:search"

THREAT_LABELS = {
    "SOCIAL_ENGINEERING": "Phishing / rekayasa sosial",
    "TYPE_SOCIAL_ENGINEERING": "Phishing / rekayasa sosial",
    "MALWARE": "Malware",
    "TYPE_MALWARE": "Malware",
    "UNWANTED_SOFTWARE": "Perangkat lunak tidak diinginkan",
    "TYPE_UNWANTED_SOFTWARE": "Perangkat lunak tidak diinginkan",
    "POTENTIALLY_HARMFUL_APPLICATION": "Aplikasi berpotensi berbahaya",
    "TYPE_POTENTIALLY_HARMFUL_APPLICATION": "Aplikasi berpotensi berbahaya",
}

THREAT_ENUMS = {
    0: "THREAT_TYPE_UNSPECIFIED",
    1: "MALWARE",
    2: "SOCIAL_ENGINEERING",
    3: "UNWANTED_SOFTWARE",
    4: "POTENTIALLY_HARMFUL_APPLICATION",
}


def _parse_varint(data: bytes, offset: int):
    """Decode integer varint dari data bytes protobuf."""
    res = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, offset


def _parse_protobuf(data: bytes):
    """Parser lightweight untuk struktur wire format Protobuf Google API."""
    fields = []
    offset = 0
    while offset < len(data):
        tag_wire, offset = _parse_varint(data, offset)
        wire_type = tag_wire & 0x07
        field_num = tag_wire >> 3
        if wire_type == 0:  # varint
            val, offset = _parse_varint(data, offset)
            fields.append((field_num, wire_type, val))
        elif wire_type == 1:  # 64-bit
            val = data[offset : offset + 8]
            offset += 8
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:  # length-delimited
            length, offset = _parse_varint(data, offset)
            val = data[offset : offset + length]
            offset += length
            fields.append((field_num, wire_type, val))
        elif wire_type == 5:  # 32-bit
            val = data[offset : offset + 4]
            offset += 4
            fields.append((field_num, wire_type, val))
        else:
            break
    return fields


def _parse_search_urls_protobuf(raw_bytes: bytes):
    """
    Ekstrak daftar ancaman dari response protobuf Google Safe Browsing v5:
    message SearchUrlsResponse {
      repeated ThreatUrl threats = 1;
      google.protobuf.Duration cache_duration = 2;
    }
    message ThreatUrl {
      string url = 1;
      repeated ThreatType threat_types = 2;
    }
    """
    threats = []
    for field_num, wire_type, val in _parse_protobuf(raw_bytes):
        if field_num == 1 and wire_type == 2:  # repeated ThreatUrl
            subfields = _parse_protobuf(val)
            matched_url = ""
            threat_types = []
            for s_num, s_wire, s_val in subfields:
                if s_num == 1 and s_wire == 2:
                    matched_url = s_val.decode("utf-8", errors="ignore")
                elif s_num == 2:
                    if s_wire == 0:
                        threat_types.append(THREAT_ENUMS.get(s_val, "UNKNOWN"))
                    elif s_wire == 2:  # packed repeated enum
                        p_off = 0
                        while p_off < len(s_val):
                            e_val, p_off = _parse_varint(s_val, p_off)
                            threat_types.append(THREAT_ENUMS.get(e_val, "UNKNOWN"))
            threats.append({"url": matched_url, "threatTypes": threat_types})
    return threats


def check_safe_browsing(url: str, timeout: int = 10) -> dict:
    """
    Memeriksa reputasi URL menggunakan Google Safe Browsing API v5.

    Status:
    - threat: URL cocok dengan daftar ancaman Google.
    - no_known_threat: tidak ditemukan dalam daftar ancaman.
    - unavailable: API tidak dapat dihubungi atau gagal.
    - invalid_url: format URL tidak valid.
    """
    try:
        from dotenv import load_dotenv
        load_dotenv(ENV_PATH, override=True)
    except ImportError:
        pass

    api_key = os.getenv("SAFE_BROWSING_API_KEY")

    if not api_key:
        return {
            "status": "unavailable",
            "threats": [],
            "reason": "API key belum diatur",
        }

    url = (url or "").strip()
    if not url:
        return {
            "status": "invalid_url",
            "threats": [],
            "reason": "URL kosong",
        }

    if "://" not in url:
        url = "http://" + url

    # Validasi format URL
    try:
        parsed = urlparse(url)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or " " in url
        ):
            return {
                "status": "invalid_url",
                "threats": [],
                "reason": "Format URL tidak valid",
            }
    except (ValueError, TypeError):
        return {
            "status": "invalid_url",
            "threats": [],
            "reason": "Format URL tidak valid",
        }

    params = {
        "key": api_key,
        "urls": url,
    }

    try:
        response = requests.get(
            API_URL,
            params=params,
            timeout=timeout,
        )
        response.raise_for_status()

        # Google Safe Browsing v5 mengembalikan response berformat protobuf
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            data = response.json()
            matches = data.get("threats", [])
        else:
            matches = _parse_search_urls_protobuf(response.content)

    except requests.RequestException as e:
        reason = "Layanan Safe Browsing tidak dapat dihubungi"
        if getattr(e, "response", None) is not None:
            if e.response.status_code in (400, 403):
                reason = "API key Safe Browsing tidak valid atau tidak memiliki izin"
        return {
            "status": "unavailable",
            "threats": [],
            "reason": reason,
        }
    except Exception:
        return {
            "status": "unavailable",
            "threats": [],
            "reason": "Gagal mengurai respons Safe Browsing",
        }

    if not matches:
        return {
            "status": "no_known_threat",
            "threats": [],
        }

    threats = []
    for match in matches:
        for threat_type in match.get("threatTypes", []):
            threats.append({
                "type": threat_type,
                "label": THREAT_LABELS.get(threat_type, threat_type),
                "matched_url": match.get("url"),
            })

    unique_threats = {
        (item["type"], item["matched_url"]): item
        for item in threats
    }

    return {
        "status": "threat",
        "threats": list(unique_threats.values()),
    }
