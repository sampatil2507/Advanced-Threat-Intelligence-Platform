# config/config.py
# All settings in one place. Read secrets from environment, never hardcode.

import os

# MongoDB
MONGO_URI       = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME         = "threat_intel"
COLLECTION_NAME = "indicators"

# Risk thresholds
RISK_HIGH   = 7   # score >= 7  → HIGH   → block
RISK_MEDIUM = 4   # score 4-6   → MEDIUM → alert
              #   score < 4   → LOW    → log only

# Firewall: set ENFORCE_REAL_FIREWALL=true only on Linux as root
REAL_FIREWALL = os.environ.get("ENFORCE_REAL_FIREWALL", "false").lower() == "true"

# Optional API keys (project works WITHOUT these — fallback list is used)
OTX_API_KEY   = os.environ.get("OTX_API_KEY", "")
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# Logging
import pathlib
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
LOG_FILE = str(BASE_DIR / "logs" / "activity.log")
