#!/usr/bin/env python3
# =============================================================
# main.py  —  Threat Intelligence Platform (TIP)
# Run this file to execute the full pipeline:
#   Fetch → Normalize → Store → Block
# =============================================================

import sys
import os
import logging
from datetime import datetime

# ── Setup logging FIRST (before any imports) ──────────────────
LOG_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "activity.log")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("TIP")

# ── Project imports ───────────────────────────────────────────
from data_collection.fetch_feeds      import fetch_all_feeds
from data_processing.normalize_data   import normalize, high_risk_only
from database.mongo_setup             import store_indicators, get_high_risk_ips, get_stats
from policy_enforcer.firewall         import block_all
from config.config                    import RISK_HIGH, REAL_FIREWALL


# ─────────────────────────────────────────────────────────────
# Pretty print helpers
# ─────────────────────────────────────────────────────────────
LINE = "─" * 56

def banner():
    print(f"""
╔══════════════════════════════════════════════════════╗
║   THREAT INTELLIGENCE PLATFORM (TIP)  v1.0          ║
║   Finance & Banking | Infotact Cybersecurity         ║
╚══════════════════════════════════════════════════════╝
  Log file : {LOG_FILE}
  Firewall : {"REAL iptables" if REAL_FIREWALL else "SIMULATION mode (safe)"}
""")

def section(title):
    print(f"\n{LINE}")
    print(f"  {title}")
    print(LINE)

def ok(msg):
    print(f"  [✔]  {msg}")

def warn(msg):
    print(f"  [!]  {msg}")

def show_ip_table(ip_list: list):
    """Print a neat table of IPs to be blocked."""
    print(f"\n  {'IP':<22} {'Score':>5}  {'Severity':<8}  Tags")
    print(f"  {'─'*22}  {'─'*5}  {'─'*8}  {'─'*25}")
    for ind in ip_list[:15]:
        tags = ", ".join(str(t) for t in ind.get("tags", []))[:30]
        print(f"  {ind['ip']:<22} {ind['risk_score']:>5}  {ind['severity']:<8}  {tags}")
    if len(ip_list) > 15:
        print(f"  ... and {len(ip_list)-15} more IPs")


# ─────────────────────────────────────────────────────────────
# Pipeline stages
# ─────────────────────────────────────────────────────────────

def stage1_fetch() -> list:
    section("STAGE 1 — OSINT FEED COLLECTION")
    raw = fetch_all_feeds()
    ok(f"Fetched {len(raw)} raw indicators")
    return raw


def stage2_normalize(raw: list) -> list:
    section("STAGE 2 — NORMALIZATION & RISK SCORING")
    normalized = normalize(raw)

    high   = sum(1 for x in normalized if x["severity"] == "HIGH")
    medium = sum(1 for x in normalized if x["severity"] == "MEDIUM")
    low    = sum(1 for x in normalized if x["severity"] == "LOW")

    ok(f"Valid indicators : {len(normalized)}")
    ok(f"HIGH  (score≥{RISK_HIGH}) : {high}  ← these will be blocked")
    ok(f"MEDIUM           : {medium}  ← logged only")
    ok(f"LOW              : {low}  ← logged only")
    return normalized


def stage3_store(normalized: list) -> int:
    section("STAGE 3 — DATABASE STORAGE  (MongoDB)")
    try:
        n = store_indicators(normalized)
        ok(f"Stored {n} new entries in MongoDB (duplicates updated)")
        return n
    except Exception as e:
        warn(f"MongoDB not available: {e}")
        warn("Continuing without DB — using in-memory data only")
        return 0


def stage4_enforce(normalized: list) -> int:
    section("STAGE 4 — DYNAMIC POLICY ENFORCEMENT  (Firewall)")

    mode = "REAL iptables" if REAL_FIREWALL else "SIMULATION (safe mode)"
    ok(f"Mode: {mode}")

    # Prefer DB query; fall back to in-memory high-risk list
    try:
        targets = get_high_risk_ips()
        if not targets:
            raise ValueError("empty")
    except Exception:
        warn("Using in-memory HIGH-risk list (DB unavailable or empty)")
        targets = high_risk_only(normalized)

    if not targets:
        warn("No HIGH-risk IPs found — nothing to block")
        return 0

    show_ip_table(targets)
    print()

    blocked = block_all(targets)
    ok(f"Blocked {blocked} IPs  [{mode}]")
    return blocked


def summary(normalized: list, blocked: int):
    section("PIPELINE SUMMARY")

    # Try DB stats first
    stats = get_stats()
    if stats:
        print(f"  Total in DB       : {stats.get('total', 0)}")
        print(f"  HIGH severity     : {stats.get('high', 0)}")
        print(f"  MEDIUM severity   : {stats.get('medium', 0)}")
        print(f"  LOW severity      : {stats.get('low', 0)}")
        print(f"  Total blocked     : {stats.get('blocked', 0)}")
    else:
        h = sum(1 for x in normalized if x["severity"] == "HIGH")
        m = sum(1 for x in normalized if x["severity"] == "MEDIUM")
        l = sum(1 for x in normalized if x["severity"] == "LOW")
        print(f"  Total processed   : {len(normalized)}")
        print(f"  HIGH severity     : {h}")
        print(f"  MEDIUM severity   : {m}")
        print(f"  LOW severity      : {l}")
        print(f"  Blocked this run  : {blocked}")

    print(f"\n  Log saved to      : {LOG_FILE}")
    print()


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    start = datetime.now()
    banner()

    logger.info("=" * 56)
    logger.info("TIP Pipeline started")
    logger.info("=" * 56)

    raw        = stage1_fetch()
    normalized = stage2_normalize(raw)
    stage3_store(normalized)
    blocked    = stage4_enforce(normalized)
    summary(normalized, blocked)

    secs = (datetime.now() - start).seconds
    logger.info(f"Pipeline finished in {secs}s")
    print(f"  Done! Finished in {secs}s\n")


if __name__ == "__main__":
    main()
