# =============================================================
# data_processing/normalize_data.py
# Cleans raw indicators, assigns risk scores, removes duplicates,
# and returns only actionable HIGH-risk indicators.
# =============================================================

import re
import logging
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.config import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# RISK SCORING RULES
# Keywords found in tags that raise the risk score.
# ─────────────────────────────────────────────────────────────
RISK_KEYWORD_WEIGHTS = {
    # Critical threats (+3 each)
    "apt":              3,
    "ransomware":       3,
    "nation-state":     3,
    "c2":               3,
    "command-and-control": 3,

    # High threats (+2 each)
    "malware":          2,
    "botnet":           2,
    "mirai":            2,
    "emotet":           2,
    "exploit":          2,
    "phishing":         2,
    "malware_download": 2,

    # Medium threats (+1 each)
    "scanner":          1,
    "bruteforce":       1,
    "ssh":              1,
    "spam":             1,
    "tor-exit":         1,
    "reported_abuse":   1,
    "shodan":           1,
}

# IPv4 validation pattern
IPV4_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────
def is_valid_ipv4(ip: str) -> bool:
    """
    Returns True if string is a valid, routable IPv4 address.
    Rejects private/loopback ranges (10.x, 192.168.x, 127.x).
    """
    match = IPV4_PATTERN.match(ip.strip())
    if not match:
        return False

    octets = [int(match.group(i)) for i in range(1, 5)]

    # All octets must be 0-255
    if any(o > 255 for o in octets):
        return False

    # Reject private/loopback/reserved ranges
    private_ranges = [
        (octets[0] == 10),
        (octets[0] == 127),
        (octets[0] == 172 and 16 <= octets[1] <= 31),
        (octets[0] == 192 and octets[1] == 168),
        (octets[0] == 0),
        (octets[0] == 255),
    ]

    return not any(private_ranges)


def calculate_risk_score(indicator: dict) -> int:
    """
    Calculates a risk score (1–10) based on indicator tags.
    Base score is 3. Each matched keyword adds its weight.
    Score is capped at 10.
    """
    score = 3  # Base score for any threat indicator

    tags = indicator.get("tags", [])
    tag_text = " ".join(str(t) for t in tags).lower()

    for keyword, weight in RISK_KEYWORD_WEIGHTS.items():
        if keyword in tag_text:
            score += weight

    # AbuseIPDB already provides an abuse confidence score (0-100)
    # Map it to our 1-10 scale and use the higher of the two
    abuse_score = indicator.get("abuse_score", 0)
    if abuse_score:
        mapped = round(abuse_score / 10)
        score  = max(score, mapped)

    return min(score, 10)  # Cap at 10


def get_severity_label(score: int) -> str:
    """Maps numeric risk score to severity label."""
    if score >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    elif score >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────────────────────
# MAIN NORMALIZATION PIPELINE
# ─────────────────────────────────────────────────────────────
def normalize(raw_indicators: list) -> list:
    """
    Full normalization pipeline:
      1. Validate IP format
      2. Remove duplicates
      3. Score each indicator
      4. Label severity
      5. Return cleaned list
    """
    seen_ips   = set()
    normalized = []
    rejected   = 0

    for item in raw_indicators:
        ip = item.get("ip", "").strip()

        # ── Step 1: Validate IP ───────────────────────────────
        if not ip:
            rejected += 1
            continue

        # For URL-type entries, the host might be a domain — keep it
        # For IP-type entries, validate strictly
        if item.get("type") == "ip" and not is_valid_ipv4(ip):
            logger.debug(f"Rejected invalid/private IP: {ip}")
            rejected += 1
            continue

        # ── Step 2: Deduplicate ───────────────────────────────
        if ip in seen_ips:
            rejected += 1
            continue
        seen_ips.add(ip)

        # ── Step 3 & 4: Score and Label ───────────────────────
        score    = calculate_risk_score(item)
        severity = get_severity_label(score)

        # ── Build normalized document ─────────────────────────
        normalized.append({
            "ip":           ip,
            "source":       item.get("source", "UNKNOWN"),
            "type":         item.get("type", "ip"),
            "tags":         item.get("tags", []),
            "risk_score":   score,
            "severity":     severity,
            "country":      item.get("country", ""),
            "abuse_score":  item.get("abuse_score", 0),
            "processed_at": datetime.now(timezone.utc).isoformat(),
        })

    logger.info(
        f"Normalization complete → "
        f"valid: {len(normalized)}, rejected: {rejected}"
    )

    # Log severity breakdown
    high   = sum(1 for i in normalized if i["severity"] == "HIGH")
    medium = sum(1 for i in normalized if i["severity"] == "MEDIUM")
    low    = sum(1 for i in normalized if i["severity"] == "LOW")
    logger.info(f"Severity breakdown → HIGH: {high}, MEDIUM: {medium}, LOW: {low}")

    return normalized


def get_high_risk_only(normalized_indicators: list) -> list:
    """
    Filters and returns only HIGH severity indicators.
    These are candidates for immediate firewall blocking.
    """
    high_risk = [i for i in normalized_indicators if i["severity"] == "HIGH"]
    logger.info(f"High-risk indicators for enforcement: {len(high_risk)}")
    return high_risk
