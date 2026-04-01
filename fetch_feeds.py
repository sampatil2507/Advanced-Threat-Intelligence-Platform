# =============================================================
# data_collection/fetch_feeds.py
# Fetches malicious IPs and domains from public OSINT feeds.
# Falls back to a static sample list if APIs are unreachable.
# =============================================================

import requests
import logging
from datetime import datetime, timezone

# Import central config
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.config import (
    OTX_API_KEY, OTX_URL,
    ABUSEIPDB_KEY, ABUSEIPDB_URL,
    URLHAUS_URL, REQUEST_TIMEOUT
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# FALLBACK DATA
# Used when APIs are unavailable (no key or network issue).
# These are real known-bad IPs from public blocklists.
# ─────────────────────────────────────────────────────────────
FALLBACK_IPS = [
    {"ip": "185.220.101.45", "source": "Fallback_List", "type": "ip",   "tags": ["tor-exit", "scanner"]},
    {"ip": "45.33.32.156",   "source": "Fallback_List", "type": "ip",   "tags": ["bruteforce", "ssh"]},
    {"ip": "194.165.16.11",  "source": "Fallback_List", "type": "ip",   "tags": ["malware", "c2"]},
    {"ip": "91.92.109.141",  "source": "Fallback_List", "type": "ip",   "tags": ["ransomware", "apt"]},
    {"ip": "198.199.80.240", "source": "Fallback_List", "type": "ip",   "tags": ["botnet", "mirai"]},
    {"ip": "89.248.165.145", "source": "Fallback_List", "type": "ip",   "tags": ["scanner", "masscan"]},
    {"ip": "192.241.220.229","source": "Fallback_List", "type": "ip",   "tags": ["ssh-bruteforce"]},
    {"ip": "162.247.72.199", "source": "Fallback_List", "type": "ip",   "tags": ["tor-exit"]},
    {"ip": "80.82.77.139",   "source": "Fallback_List", "type": "ip",   "tags": ["scanner", "shodan"]},
    {"ip": "5.188.86.172",   "source": "Fallback_List", "type": "ip",   "tags": ["spam", "botnet"]},
    {"ip": "103.41.204.169", "source": "Fallback_List", "type": "ip",   "tags": ["phishing", "malware"]},
    {"ip": "218.92.0.112",   "source": "Fallback_List", "type": "ip",   "tags": ["apt", "china"]},
    {"ip": "222.186.30.112", "source": "Fallback_List", "type": "ip",   "tags": ["bruteforce"]},
    {"ip": "171.25.193.77",  "source": "Fallback_List", "type": "ip",   "tags": ["tor-exit", "scanner"]},
    {"ip": "46.101.90.205",  "source": "Fallback_List", "type": "ip",   "tags": ["c2", "malware"]},
]


# ─────────────────────────────────────────────────────────────
# FEED 1: AlienVault OTX
# ─────────────────────────────────────────────────────────────
def fetch_alienvault_otx():
    """
    Pulls malicious indicators from AlienVault OTX.
    Requires OTX_API_KEY environment variable.
    Returns list of indicator dicts.
    """
    if not OTX_API_KEY:
        logger.warning("[OTX] API key not set. Skipping AlienVault OTX feed.")
        return []

    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    results = []

    try:
        response = requests.get(OTX_URL, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        for item in data.get("results", []):
            ip = item.get("indicator", "").strip()
            if not ip:
                continue

            results.append({
                "ip":     ip,
                "source": "AlienVault_OTX",
                "type":   item.get("type", "ip").lower(),
                "tags":   item.get("pulse_info", {}).get("tags", []),
            })

        logger.info(f"[OTX] Fetched {len(results)} indicators.")

    except requests.exceptions.ConnectionError:
        logger.warning("[OTX] Connection failed — network unreachable.")
    except requests.exceptions.Timeout:
        logger.warning(f"[OTX] Request timed out after {REQUEST_TIMEOUT}s.")
    except requests.exceptions.HTTPError as e:
        logger.warning(f"[OTX] HTTP error: {e}")
    except Exception as e:
        logger.error(f"[OTX] Unexpected error: {e}")

    return results


# ─────────────────────────────────────────────────────────────
# FEED 2: URLhaus (No API key required)
# ─────────────────────────────────────────────────────────────
def fetch_urlhaus():
    """
    Pulls recent malicious URLs from URLhaus (abuse.ch).
    Completely free — no API key needed.
    Extracts IP/domain from each malicious URL.
    """
    results = []

    try:
        response = requests.post(
            URLHAUS_URL,
            data={"limit": 100},
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        for entry in data.get("urls", []):
            url = entry.get("url", "").strip()
            if not url:
                continue

            # Extract host from URL (e.g. http://1.2.3.4/evil → 1.2.3.4)
            try:
                host = url.split("//")[1].split("/")[0]
            except IndexError:
                continue

            results.append({
                "ip":     host,
                "source": "URLhaus",
                "type":   "url",
                "tags":   entry.get("tags") or ["malware_download"],
            })

        logger.info(f"[URLhaus] Fetched {len(results)} indicators.")

    except requests.exceptions.ConnectionError:
        logger.warning("[URLhaus] Connection failed — network unreachable.")
    except requests.exceptions.Timeout:
        logger.warning(f"[URLhaus] Timed out after {REQUEST_TIMEOUT}s.")
    except Exception as e:
        logger.error(f"[URLhaus] Unexpected error: {e}")

    return results


# ─────────────────────────────────────────────────────────────
# FEED 3: AbuseIPDB
# ─────────────────────────────────────────────────────────────
def fetch_abuseipdb():
    """
    Pulls top reported malicious IPs from AbuseIPDB.
    Requires ABUSEIPDB_API_KEY environment variable.
    Only fetches IPs with confidence >= 90%.
    """
    if not ABUSEIPDB_KEY:
        logger.warning("[AbuseIPDB] API key not set. Skipping AbuseIPDB feed.")
        return []

    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params  = {"confidenceMinimum": 90, "limit": 200}
    results = []

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        for entry in data.get("data", []):
            ip = entry.get("ipAddress", "").strip()
            if not ip:
                continue

            results.append({
                "ip":          ip,
                "source":      "AbuseIPDB",
                "type":        "ip",
                "tags":        ["reported_abuse"],
                "abuse_score": entry.get("abuseConfidenceScore", 0),
                "country":     entry.get("countryCode", ""),
            })

        logger.info(f"[AbuseIPDB] Fetched {len(results)} indicators.")

    except requests.exceptions.ConnectionError:
        logger.warning("[AbuseIPDB] Connection failed — network unreachable.")
    except requests.exceptions.Timeout:
        logger.warning(f"[AbuseIPDB] Timed out after {REQUEST_TIMEOUT}s.")
    except requests.exceptions.HTTPError as e:
        logger.warning(f"[AbuseIPDB] HTTP error: {e}")
    except Exception as e:
        logger.error(f"[AbuseIPDB] Unexpected error: {e}")

    return results


# ─────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────
def fetch_all_feeds():
    """
    Calls all OSINT feeds and merges results.
    If all live feeds fail, returns fallback static list.
    Returns a list of raw indicator dicts.
    """
    logger.info("Starting OSINT feed collection...")

    all_indicators = []
    all_indicators.extend(fetch_alienvault_otx())
    all_indicators.extend(fetch_urlhaus())
    all_indicators.extend(fetch_abuseipdb())

    # Use fallback if no live data was fetched
    if not all_indicators:
        logger.warning("All live feeds failed or returned no data. Using fallback list.")
        all_indicators = FALLBACK_IPS.copy()

    logger.info(f"Total raw indicators collected: {len(all_indicators)}")
    return all_indicators
