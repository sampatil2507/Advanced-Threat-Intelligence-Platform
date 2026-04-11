# 🛡️ Threat Intelligence Platform (TIP)
Infotact Cybersecurity Internship — Project 1: Finance & Banking

---

## What This Project Does

Automatically collects malicious IPs from public OSINT feeds, scores them by risk level, stores them in MongoDB, and blocks HIGH-risk IPs using Linux iptables — or simulates blocking safely on any OS.

```
OSINT Feeds → Normalize & Score → MongoDB → iptables Block
```

---

## Folder Structure

```
threat-intelligence-platform/
├── config/
│   └── config.py              All settings (reads from .env)
├── data_collection/
│   └── fetch_feeds.py         Fetches from URLhaus, OTX, AbuseIPDB + fallback
├── data_processing/
│   └── normalize_data.py      Cleans, deduplicates, scores HIGH/MEDIUM/LOW
├── database/
│   └── mongo_setup.py         MongoDB: store, query, mark blocked
├── policy_enforcer/
│   └── firewall.py            iptables block/unblock + simulation mode
├── logs/
│   └── activity.log           Auto-generated log (created on first run)
├── main.py                    ← Run this
├── requirements.txt
└── .env.example
```

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy environment file
cp .env.example .env

# 3. Start MongoDB (skip if no MongoDB — project still works)
docker run -d -p 27017:27017 mongo:6
# OR install locally: https://www.mongodb.com/try/download/community

# 4. Run the pipeline
python main.py
```

**No API keys needed.** If feeds are unreachable, 20 real known-bad IPs from public blocklists are used automatically.

---

## Sample Output

```
╔══════════════════════════════════════════════════════╗
║   THREAT INTELLIGENCE PLATFORM (TIP)  v1.0          ║
║   Finance & Banking | Infotact Cybersecurity         ║
╚══════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────
  STAGE 1 — OSINT FEED COLLECTION
────────────────────────────────────────────────────────
  [✔]  Fetched 20 raw indicators

────────────────────────────────────────────────────────
  STAGE 2 — NORMALIZATION & RISK SCORING
────────────────────────────────────────────────────────
  [✔]  Valid indicators : 18
  [✔]  HIGH  (score≥7)  : 9  ← these will be blocked
  [✔]  MEDIUM           : 6  ← logged only
  [✔]  LOW              : 3  ← logged only

────────────────────────────────────────────────────────
  STAGE 3 — DATABASE STORAGE  (MongoDB)
────────────────────────────────────────────────────────
  [✔]  Stored 18 new entries in MongoDB

────────────────────────────────────────────────────────
  STAGE 4 — DYNAMIC POLICY ENFORCEMENT  (Firewall)
────────────────────────────────────────────────────────
  [✔]  Mode: SIMULATION (safe mode)

  IP                     Score  Severity  Tags
  ──────────────────────  ─────  ────────  ─────────────────────────
  91.92.109.141              10  HIGH      ransomware, apt
  194.165.16.11               9  HIGH      malware, c2
  198.199.80.240              9  HIGH      botnet, mirai
  46.101.90.205               8  HIGH      c2, malware
  ...

  [✔]  Blocked 9 IPs  [SIMULATION (safe mode)]

────────────────────────────────────────────────────────
  PIPELINE SUMMARY
────────────────────────────────────────────────────────
  Total in DB       : 18
  HIGH severity     : 9
  MEDIUM severity   : 6
  LOW severity      : 3
  Total blocked     : 9
  Log saved to      : logs/activity.log
```

---

## Risk Scoring

| Score | Label  | Action          |
|-------|--------|-----------------|
| 7–10  | HIGH   | Auto-block      |
| 4–6   | MEDIUM | Log + alert     |
| 1–3   | LOW    | Log only        |

Tags used for scoring: `apt` (+3), `ransomware` (+3), `c2` (+3), `malware` (+2), `botnet` (+2), `scanner` (+1), etc.

---

## Enable Real Firewall (Linux only)

```bash
# In .env
ENFORCE_REAL_FIREWALL=true

# Run as root
sudo python main.py
```

This executes: `iptables -A INPUT -s <ip> -j DROP` for each HIGH-risk IP.

---

## Free API Keys (Optional)

| Feed       | URL                        | Free? |
|------------|----------------------------|-------|
| URLhaus    | abuse.ch                   | ✅ No key needed |
| AbuseIPDB  | abuseipdb.com/register     | ✅ Free account  |
| AlienVault | otx.alienvault.com         | ✅ Free account  |

---

## Future Improvements

- Kibana dashboard for visual threat map
- SIEM integration (Splunk / Elastic)
- IP geolocation mapping
- Email/Slack alerts on new HIGH-risk detections
- Scheduled cron job for continuous monitoring
