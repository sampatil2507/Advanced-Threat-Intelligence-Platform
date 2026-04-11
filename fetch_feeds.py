# data_collection/fetch_feeds.py
# Fetches malicious IPs from 3 public OSINT feeds.
# If all feeds fail (no key / no internet) → uses built-in fallback list.

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests
import logging
from config.config import OTX_API_KEY, ABUSEIPDB_KEY

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10  # seconds

# ── Fallback list (real known-bad IPs from public blocklists) ─────────────
# Used automatically when APIs are unavailable — no key needed.
FALLBACK_IPS = [
    {"ip": "185.220.101.45",  "source": "Fallback", "tags": ["tor-exit", "scanner"]},
    {"ip": "45.33.32.156",    "source": "Fallback", "tags": ["bruteforce", "ssh"]},
    {"ip": "194.165.16.11",   "source": "Fallback", "tags": ["malware", "c2"]},
    {"ip": "91.92.109.141",   "source": "Fallback", "tags": ["ransomware", "apt"]},
    {"ip": "198.199.80.240",  "source": "Fallback", "tags": ["botnet", "mirai"]},
    {"ip": "89.248.165.145",  "source": "Fallback", "tags": ["scanner"]},
    {"ip": "192.241.220.229", "source": "Fallback", "tags": ["ssh-bruteforce"]},
    {"ip": "162.247.72.199",  "source": "Fallback", "tags": ["tor-exit"]},
    {"ip": "80.82.77.139",    "source": "Fallback", "tags": ["scanner", "shodan"]},
    {"ip": "5.188.86.172",    "source": "Fallback", "tags": ["spam", "botnet"]},
    {"ip": "103.41.204.169",  "source": "Fallback", "tags": ["phishing", "malware"]},
    {"ip": "218.92.0.112",    "source": "Fallback", "tags": ["apt"]},
    {"ip": "222.186.30.112",  "source": "Fallback", "tags": ["bruteforce"]},
    {"ip": "171.25.193.77",   "source": "Fallback", "tags": ["tor-exit"]},
    {"ip": "46.101.90.205",   "source": "Fallback", "tags": ["c2", "malware"]},
    {"ip": "61.177.172.13",   "source": "Fallback", "tags": ["scanner", "bruteforce"]},
    {"ip": "141.98.10.204",   "source": "Fallback", "tags": ["malware", "botnet"]},
    {"ip": "179.60.150.3",    "source": "Fallback", "tags": ["phishing"]},
    {"ip": "31.184.198.23",   "source": "Fallback", "tags": ["ransomware"]},
    {"ip": "77.83.247.85",    "source": "Fallback", "tags": ["apt", "c2"]},
]


# ── Feed 1: URLhaus (FREE — no API key needed) ────────────────────────────
def fetch_urlhaus():
    results = []
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": 50},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        for entry in resp.json().get("urls", []):
            url = entry.get("url", "")
            if "//" not in url:
                continue
            host = url.split("//")[1].split("/")[0]
            results.append({
                "ip":     host,
                "source": "URLhaus",
                "tags":   entry.get("tags") or ["malware_download"],
            })
        logger.info(f"[URLhaus] Got {len(results)} indicators")
    except Exception as e:
        logger.warning(f"[URLhaus] Failed: {e}")
    return results


# ── Feed 2: AlienVault OTX (free key at otx.alienvault.com) ──────────────
def fetch_otx():
    if not OTX_API_KEY:
        logger.warning("[OTX] No API key — skipping")
        return []
    results = []
    try:
        resp = requests.get(
            "https://otx.alienvault.com/api/v1/indicators/malware",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        for item in resp.json().get("results", []):
            ip = item.get("indicator", "").strip()
            if ip:
                results.append({
                    "ip":     ip,
                    "source": "AlienVault_OTX",
                    "tags":   item.get("pulse_info", {}).get("tags", []),
                })
        logger.info(f"[OTX] Got {len(results)} indicators")
    except Exception as e:
        logger.warning(f"[OTX] Failed: {e}")
    return results


# ── Feed 3: AbuseIPDB (free key at abuseipdb.com) ────────────────────────
def fetch_abuseipdb():
    if not ABUSEIPDB_KEY:
        logger.warning("[AbuseIPDB] No API key — skipping")
        return []
    results = []
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": 90, "limit": 100},
            timeout=REQUEST_TIMEOUT
        )
        resp.raise_for_status()
        for entry in resp.json().get("data", []):
            ip = entry.get("ipAddress", "").strip()
            if ip:
                results.append({
                    "ip":          ip,
                    "source":      "AbuseIPDB",
                    "tags":        ["reported_abuse"],
                    "abuse_score": entry.get("abuseConfidenceScore", 0),
                    "country":     entry.get("countryCode", ""),
                })
        logger.info(f"[AbuseIPDB] Got {len(results)} indicators")
    except Exception as e:
        logger.warning(f"[AbuseIPDB] Failed: {e}")
    return results


# ── Main entry point ──────────────────────────────────────────────────────
def fetch_all_feeds():
    """Collect from all feeds. Falls back to static list if nothing comes in."""
    logger.info("Collecting OSINT feeds...")
    data = []
    data.extend(fetch_urlhaus())
    data.extend(fetch_otx())
    data.extend(fetch_abuseipdb())

    if not data:
        logger.warning("All live feeds empty — using built-in fallback list")
        data = FALLBACK_IPS.copy()

    logger.info(f"Total raw indicators: {len(data)}")
    return data
