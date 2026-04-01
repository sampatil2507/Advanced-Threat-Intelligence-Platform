# =============================================================
# main.py
# Master pipeline orchestrator for the Threat Intelligence Platform.
# Runs the full sequence: Fetch → Store → Normalize → Enforce
# =============================================================

import sys
import os
import logging
from datetime import datetime

# ── Logging Setup (must happen before any module imports) ─────
LOG_DIR  = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "activity.log")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("TIP.main")

# ── Project Module Imports ────────────────────────────────────
from data_collection.fetch_feeds  import fetch_all_feeds
from database.mongo_setup         import store_indicators, get_high_risk_ips, get_db_stats
from data_processing.normalize_data import normalize, get_high_risk_only
from policy_enforcer.firewall     import block_all
from config.config                import RISK_HIGH_THRESHOLD, ENFORCE_REAL_FIREWALL


# ─────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────
def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║       THREAT INTELLIGENCE PLATFORM (TIP) v1.0           ║
║       Finance & Banking Security — Infotact Internship   ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_step(step: str, detail: str = ""):
    line = f"  [✔] {step}"
    if detail:
        line += f" → {detail}"
    print(line)
    logger.info(f"STEP: {step} {detail}")


def print_error(step: str, error: str):
    line = f"  [✘] {step} FAILED: {error}"
    print(line)
    logger.error(f"FAILED: {step} — {error}")


def print_section(title: str):
    print(f"\n{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}")


def print_summary(stats: dict, blocked: int, mode: str):
    print_section("PIPELINE SUMMARY")
    print(f"  Mode             : {mode}")
    print(f"  Total in DB      : {stats.get('total', 0)}")
    print(f"  HIGH severity    : {stats.get('high', 0)}")
    print(f"  MEDIUM severity  : {stats.get('medium', 0)}")
    print(f"  LOW severity     : {stats.get('low', 0)}")
    print(f"  Blocked this run : {blocked}")
    print(f"  Total blocked    : {stats.get('blocked', 0)}")
    print(f"  Log file         : logs/activity.log")
    print()


# ─────────────────────────────────────────────────────────────
# PIPELINE STAGES
# ─────────────────────────────────────────────────────────────
def stage_1_fetch() -> list:
    """Stage 1: Collect raw OSINT data from feeds."""
    print_section("STAGE 1 — OSINT DATA COLLECTION")
    try:
        raw_data = fetch_all_feeds()
        print_step("Fetched indicators", f"{len(raw_data)} raw entries")
        return raw_data
    except Exception as e:
        print_error("OSINT fetch", str(e))
        return []


def stage_2_normalize(raw_data: list) -> list:
    """Stage 2: Clean, deduplicate and score all indicators."""
    print_section("STAGE 2 — NORMALIZATION & RISK SCORING")
    try:
        normalized = normalize(raw_data)

        high   = sum(1 for i in normalized if i["severity"] == "HIGH")
        medium = sum(1 for i in normalized if i["severity"] == "MEDIUM")
        low    = sum(1 for i in normalized if i["severity"] == "LOW")

        print_step("Cleaned & deduplicated",   f"{len(normalized)} valid indicators")
        print_step("HIGH severity (score≥{})".format(RISK_HIGH_THRESHOLD), str(high))
        print_step("MEDIUM severity",          str(medium))
        print_step("LOW severity",             str(low))

        return normalized
    except Exception as e:
        print_error("Normalization", str(e))
        return []


def stage_3_store(normalized: list) -> int:
    """Stage 3: Persist normalized indicators to MongoDB."""
    print_section("STAGE 3 — DATABASE STORAGE (MongoDB)")
    try:
        inserted = store_indicators(normalized)
        print_step("Stored in MongoDB", f"{inserted} new entries (duplicates updated)")
        return inserted
    except Exception as e:
        print_error("MongoDB storage", str(e))
        logger.warning("Continuing without DB storage — using in-memory data.")
        return 0


def stage_4_enforce(normalized: list) -> int:
    """Stage 4: Block all HIGH-risk IPs via iptables (or simulation)."""
    print_section("STAGE 4 — DYNAMIC POLICY ENFORCEMENT")

    mode = "REAL iptables" if ENFORCE_REAL_FIREWALL else "SIMULATION (safe mode)"
    print(f"  Enforcement mode: {mode}")

    try:
        # Get high-risk IPs (try DB first, fall back to in-memory)
        try:
            high_risk = get_high_risk_ips()
        except Exception:
            logger.warning("DB unavailable — using in-memory high-risk list.")
            high_risk = get_high_risk_only(normalized)

        if not high_risk:
            print_step("No HIGH-risk IPs found", "nothing to block")
            return 0

        print(f"\n  IPs queued for blocking ({len(high_risk)} total):")
        for ind in high_risk[:10]:   # Show first 10
            tags = ", ".join(ind.get("tags", []))[:40]
            print(f"    • {ind['ip']:<20} score={ind['risk_score']} [{tags}]")
        if len(high_risk) > 10:
            print(f"    ... and {len(high_risk)-10} more")

        print()
        blocked_count = block_all(high_risk)
        print_step(f"Blocked {blocked_count} IPs", mode)
        return blocked_count

    except Exception as e:
        print_error("Policy enforcement", str(e))
        return 0


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    start_time = datetime.now()
    print_banner()
    logger.info("=" * 60)
    logger.info("TIP Pipeline started")
    logger.info("=" * 60)

    # ── Run all 4 stages ─────────────────────────────────────
    raw_data   = stage_1_fetch()
    normalized = stage_2_normalize(raw_data)
    stage_3_store(normalized)
    blocked    = stage_4_enforce(normalized)

    # ── Final summary ─────────────────────────────────────────
    try:
        stats = get_db_stats()
    except Exception:
        # MongoDB not available — build stats from memory
        stats = {
            "total":   len(normalized),
            "high":    sum(1 for i in normalized if i["severity"] == "HIGH"),
            "medium":  sum(1 for i in normalized if i["severity"] == "MEDIUM"),
            "low":     sum(1 for i in normalized if i["severity"] == "LOW"),
            "blocked": blocked,
        }

    mode = "REAL iptables" if ENFORCE_REAL_FIREWALL else "SIMULATION"
    print_summary(stats, blocked, mode)

    elapsed = (datetime.now() - start_time).seconds
    logger.info(f"Pipeline completed in {elapsed}s")
    print(f"  Pipeline completed in {elapsed}s\n")


if __name__ == "__main__":
    main()
