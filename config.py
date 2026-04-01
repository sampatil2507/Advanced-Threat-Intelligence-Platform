# =============================================================
# config/config.py
# Central configuration — all settings in one place.
# Secrets are read from environment variables, never hardcoded.
# =============================================================

import os
from datetime import datetime

# ── MongoDB ───────────────────────────────────────────────────
MONGO_URI       = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME         = "threat_intel"
COLLECTION_NAME = "indicators"

# ── Risk Score Thresholds ─────────────────────────────────────
RISK_HIGH_THRESHOLD   = 7   # score >= 7  → HIGH   → auto-block
RISK_MEDIUM_THRESHOLD = 4   # score 4-6   → MEDIUM → alert only
                             # score < 4   → LOW    → log only

# ── Firewall ──────────────────────────────────────────────────
# Set to True to actually run iptables (needs root on Linux).
# Set to False to simulate (safe for testing / Windows / Mac).
ENFORCE_REAL_FIREWALL = os.environ.get("ENFORCE_REAL_FIREWALL", "false").lower() == "true"

# ── Logging ───────────────────────────────────────────────────
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "activity.log")

# ── OSINT API Keys (optional — fallback data used if missing) ─
OTX_API_KEY      = os.environ.get("OTX_API_KEY", "")
ABUSEIPDB_KEY    = os.environ.get("ABUSEIPDB_API_KEY", "")

# ── Feed URLs ─────────────────────────────────────────────────
OTX_URL       = "https://otx.alienvault.com/api/v1/indicators/malware"
URLHAUS_URL   = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# ── Request Settings ──────────────────────────────────────────
REQUEST_TIMEOUT = 10   # seconds
