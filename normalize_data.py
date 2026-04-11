# data_processing/normalize_data.py
# Cleans raw indicators: validates IPs, removes duplicates,
# calculates risk score (1-10), labels severity (HIGH/MEDIUM/LOW).

import re
import logging
from datetime import datetime, timezone

sys_path_fix = __import__("sys"); sys_path_fix.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), ".."))
from config.config import RISK_HIGH, RISK_MEDIUM

logger = logging.getLogger(__name__)

# Valid IPv4 pattern
IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# Tag → risk weight table
WEIGHTS = {
    "apt":              3, "ransomware":    3, "c2":            3,
    "malware":          2, "botnet":        2, "phishing":      2,
    "malware_download": 2, "mirai":         2, "emotet":        2,
    "bruteforce":       1, "scanner":       1, "tor-exit":      1,
    "spam":             1, "reported_abuse":1, "ssh":           1,
}


def is_valid_ip(ip: str) -> bool:
    """Accept only valid public IPv4 addresses. Reject private/reserved ranges."""
    m = IPV4.match(ip.strip())
    if not m:
        return False
    o = [int(m.group(i)) for i in range(1, 5)]
    if any(x > 255 for x in o):
        return False
    # Reject private / loopback / reserved
    if o[0] in (10, 127, 0, 255):
        return False
    if o[0] == 172 and 16 <= o[1] <= 31:
        return False
    if o[0] == 192 and o[1] == 168:
        return False
    return True


def score(indicator: dict) -> int:
    """Calculate risk score 1-10 from tags."""
    s = 3  # base
    tag_text = " ".join(str(t) for t in indicator.get("tags", [])).lower()
    for kw, w in WEIGHTS.items():
        if kw in tag_text:
            s += w
    # AbuseIPDB provides a 0-100 confidence — map to 1-10
    abuse = indicator.get("abuse_score", 0)
    if abuse:
        s = max(s, round(abuse / 10))
    return min(s, 10)


def severity(s: int) -> str:
    if s >= RISK_HIGH:
        return "HIGH"
    if s >= RISK_MEDIUM:
        return "MEDIUM"
    return "LOW"


def normalize(raw: list) -> list:
    """
    Full normalization:
    1. Validate IP format
    2. Deduplicate
    3. Score & label
    Returns cleaned list of dicts.
    """
    seen    = set()
    cleaned = []
    bad     = 0

    for item in raw:
        ip = item.get("ip", "").strip()

        # Skip empty / invalid
        if not ip or not is_valid_ip(ip):
            bad += 1
            continue

        # Skip duplicate
        if ip in seen:
            bad += 1
            continue
        seen.add(ip)

        risk = score(item)
        cleaned.append({
            "ip":         ip,
            "source":     item.get("source", "UNKNOWN"),
            "tags":       item.get("tags", []),
            "risk_score": risk,
            "severity":   severity(risk),
            "country":    item.get("country", ""),
            "timestamp":  datetime.now(timezone.utc),
            "blocked":    False,
        })

    high   = sum(1 for x in cleaned if x["severity"] == "HIGH")
    medium = sum(1 for x in cleaned if x["severity"] == "MEDIUM")
    low    = sum(1 for x in cleaned if x["severity"] == "LOW")

    logger.info(f"Normalized: {len(cleaned)} valid | {bad} rejected | HIGH={high} MEDIUM={medium} LOW={low}")
    return cleaned


def high_risk_only(indicators: list) -> list:
    """Return only HIGH severity indicators."""
    return [i for i in indicators if i["severity"] == "HIGH"]
