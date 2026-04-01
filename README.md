# 🛡️ Threat Intelligence Platform (TIP)
**Infotact Technical Internship — Project 1: Finance & Banking Cybersecurity**

---

## Project Overview

A production-style Threat Intelligence Platform that automatically collects malicious IPs from public OSINT feeds, normalizes and scores them by risk level, stores them in MongoDB, and dynamically enforces firewall rules using Linux iptables — all through a clean, modular Python pipeline.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     main.py (Orchestrator)              │
└────────┬────────────┬───────────────┬───────────────────┘
         │            │               │               │
         ▼            ▼               ▼               ▼
   fetch_feeds   normalize_data  mongo_setup     firewall.py
   .py           .py             .py
         │            │               │               │
   AlienVault    Clean + Score   MongoDB         iptables
   URLhaus       Deduplicate     threat_intel    (or simulate)
   AbuseIPDB     HIGH/MED/LOW    database
   + Fallback
```

---

## Folder Structure

```
threat-intelligence-platform/
│
├── data_collection/
│   └── fetch_feeds.py        # OSINT feed collection (OTX, URLhaus, AbuseIPDB)
│
├── database/
│   └── mongo_setup.py        # MongoDB connect, store, query, mark blocked
│
├── data_processing/
│   └── normalize_data.py     # Clean, deduplicate, risk score, label severity
│
├── policy_enforcer/
│   └── firewall.py           # iptables block/unblock + simulation mode
│
├── logs/
│   └── activity.log          # Auto-generated pipeline log
│
├── config/
│   └── config.py             # All settings (reads from environment variables)
│
├── .env.example              # Copy to .env and fill API keys
├── .gitignore
├── requirements.txt
├── README.md
└── main.py                   # Run this to start the full pipeline
```

---

## Setup Instructions

### Step 1 — Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/threat-intelligence-platform.git
cd threat-intelligence-platform
```

### Step 2 — Create virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Configure environment variables
```bash
cp .env.example .env
# Open .env and optionally add your API keys
```

### Step 5 — Start MongoDB
```bash
# If MongoDB is installed locally
mongod

# Or with Docker (easier)
docker run -d -p 27017:27017 --name tip_mongo mongo:6
```

---

## How to Run

```bash
python main.py
```

**No API keys needed** — the project uses a built-in fallback list of 15 real known-bad IPs if all live feeds are unavailable.

### To enable real iptables blocking (Linux only, root required):
```bash
# In your .env file:
ENFORCE_REAL_FIREWALL=true

# Then run as root:
sudo python main.py
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════╗
║       THREAT INTELLIGENCE PLATFORM (TIP) v1.0           ║
║       Finance & Banking Security — Infotact Internship   ║
╚══════════════════════════════════════════════════════════╝

───────────────────────────────────────────────────────
  STAGE 1 — OSINT DATA COLLECTION
───────────────────────────────────────────────────────
  [✔] Fetched indicators → 15 raw entries

───────────────────────────────────────────────────────
  STAGE 2 — NORMALIZATION & RISK SCORING
───────────────────────────────────────────────────────
  [✔] Cleaned & deduplicated → 13 valid indicators
  [✔] HIGH severity (score≥7) → 7
  [✔] MEDIUM severity         → 4
  [✔] LOW severity            → 2

───────────────────────────────────────────────────────
  STAGE 3 — DATABASE STORAGE (MongoDB)
───────────────────────────────────────────────────────
  [✔] Stored in MongoDB → 13 new entries (duplicates updated)

───────────────────────────────────────────────────────
  STAGE 4 — DYNAMIC POLICY ENFORCEMENT
───────────────────────────────────────────────────────
  Enforcement mode: SIMULATION (safe mode)

  IPs queued for blocking (7 total):
    • 91.92.109.141       score=10 [ransomware, apt]
    • 194.165.16.11       score=9  [malware, c2]
    • 198.199.80.240      score=9  [botnet, mirai]
    • 46.101.90.205       score=8  [c2, malware]
    • 103.41.204.169      score=8  [phishing, malware]
    • 185.220.101.45      score=7  [tor-exit, scanner]
    • 171.25.193.77       score=7  [tor-exit, scanner]

  [✔] Blocked 7 IPs → SIMULATION (safe mode)

───────────────────────────────────────────────────────
  PIPELINE SUMMARY
───────────────────────────────────────────────────────
  Mode             : SIMULATION
  Total in DB      : 13
  HIGH severity    : 7
  MEDIUM severity  : 4
  LOW severity     : 2
  Blocked this run : 7
  Total blocked    : 7
  Log file         : logs/activity.log

  Pipeline completed in 2s
```

---

## Risk Scoring Model

| Score | Severity | Action |
|-------|----------|--------|
| 7–10  | HIGH     | Auto-block via iptables |
| 4–6   | MEDIUM   | Log and alert only |
| 1–3   | LOW      | Log only |

Score is calculated from threat tags:

| Tag | Weight |
|-----|--------|
| apt, ransomware, c2 | +3 |
| malware, botnet, phishing | +2 |
| scanner, bruteforce, spam | +1 |

---

## Free API Keys (Optional)

| Source | URL | Key Needed? |
|--------|-----|-------------|
| URLhaus | abuse.ch | ❌ No — free |
| AbuseIPDB | abuseipdb.com/register | ✅ Free account |
| AlienVault OTX | otx.alienvault.com | ✅ Free account |

The project runs **without any API keys** using the built-in fallback IP list.

---

## Future Improvements

- **ELK Stack** — Push indicators to Elasticsearch, visualize in Kibana dashboards
- **SIEM Integration** — Export normalized events to Splunk or Microsoft Sentinel
- **Geolocation** — Map attacker origins using MaxMind GeoIP
- **DAST / SAST** — Add scanning pipeline for application-layer threats
- **Alerting** — Slack/email notifications for CRITICAL threats
- **Scheduled runs** — Cron job or systemd timer for continuous monitoring
- **REST API** — Flask endpoints for SOC analyst queries and rollback

---

## GitHub Commit Strategy (Evaluation Requirement)

This project maintains **4 weeks of consistent commits**:

```
Week 1: feat: add fetch_feeds.py with OTX, URLhaus, AbuseIPDB integration
Week 1: feat: add MongoDB schema and store_indicators function
Week 2: feat: implement normalize_data.py with risk scoring engine
Week 2: fix: reject private IP ranges in validator
Week 3: feat: add firewall.py with iptables subprocess execution
Week 3: feat: add simulation mode for non-Linux environments
Week 4: feat: add main.py pipeline orchestrator
Week 4: docs: add README with architecture and setup guide
```

---

## Compliance Notes

- No API keys or secrets committed to repository
- All credentials via `.env` / environment variables
- Audit trail maintained in `logs/activity.log` and MongoDB
- `blocked` flag in DB provides PCI-DSS-compatible change record
