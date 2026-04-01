# =============================================================
# database/mongo_setup.py
# Handles all MongoDB operations:
#   - Connection setup
#   - Storing indicators (with duplicate prevention)
#   - Querying high-risk indicators
# =============================================================

import logging
from datetime import datetime, timezone
from pymongo import MongoClient, ASCENDING
from pymongo.errors import DuplicateKeyError, ConnectionFailure, BulkWriteError

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.config import MONGO_URI, DB_NAME, COLLECTION_NAME, RISK_HIGH_THRESHOLD

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────────────────────
def get_collection():
    """
    Creates and returns the MongoDB collection object.
    Also ensures the unique index on 'ip' exists (prevents duplicates).
    Raises ConnectionFailure if MongoDB is not reachable.
    """
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        # Force connection check
        client.admin.command("ping")

        db         = client[DB_NAME]
        collection = db[COLLECTION_NAME]

        # Unique index on 'ip' — MongoDB will reject duplicate IPs automatically
        collection.create_index([("ip", ASCENDING)], unique=True)

        logger.info(f"Connected to MongoDB → database: '{DB_NAME}', collection: '{COLLECTION_NAME}'")
        return collection

    except ConnectionFailure as e:
        logger.error(f"MongoDB connection failed: {e}")
        raise


# ─────────────────────────────────────────────────────────────
# STORE INDICATORS
# ─────────────────────────────────────────────────────────────
def store_indicators(indicators: list) -> int:
    """
    Stores a list of indicator dicts into MongoDB.
    Skips duplicates (same IP already in DB).
    Returns the count of newly inserted documents.
    """
    if not indicators:
        logger.warning("store_indicators called with empty list.")
        return 0

    collection  = get_collection()
    inserted    = 0
    skipped     = 0

    for indicator in indicators:
        ip = indicator.get("ip", "").strip()
        if not ip:
            continue

        # Build the document to store
        document = {
            "ip":         ip,
            "source":     indicator.get("source", "UNKNOWN"),
            "type":       indicator.get("type", "ip"),
            "tags":       indicator.get("tags", []),
            "risk_score": indicator.get("risk_score", 0),
            "severity":   indicator.get("severity", "UNSCORED"),
            "country":    indicator.get("country", ""),
            "timestamp":  datetime.now(timezone.utc),
            "blocked":    False,
        }

        try:
            collection.insert_one(document)
            inserted += 1
        except DuplicateKeyError:
            # IP already exists — update last_seen and risk_score
            collection.update_one(
                {"ip": ip},
                {"$set": {
                    "last_seen":  datetime.now(timezone.utc),
                    "risk_score": document["risk_score"],
                    "severity":   document["severity"],
                }}
            )
            skipped += 1

    logger.info(f"DB store complete → inserted: {inserted}, duplicates updated: {skipped}")
    return inserted


# ─────────────────────────────────────────────────────────────
# QUERY HIGH-RISK IPs
# ─────────────────────────────────────────────────────────────
def get_high_risk_ips() -> list:
    """
    Returns all unblocked IPs with risk_score >= HIGH threshold.
    These are the IPs that the policy enforcer will block.
    """
    collection = get_collection()

    results = list(
        collection.find(
            {
                "risk_score": {"$gte": RISK_HIGH_THRESHOLD},
                "blocked":    False,
            },
            {"_id": 0, "ip": 1, "risk_score": 1, "severity": 1, "source": 1, "tags": 1}
        ).sort("risk_score", -1)
    )

    logger.info(f"Found {len(results)} high-risk unblocked IPs in DB.")
    return results


# ─────────────────────────────────────────────────────────────
# MARK IPs AS BLOCKED
# ─────────────────────────────────────────────────────────────
def mark_as_blocked(ip: str):
    """
    Updates the 'blocked' flag for an IP in the database.
    Called after a successful iptables block.
    """
    collection = get_collection()
    collection.update_one(
        {"ip": ip},
        {"$set": {
            "blocked":    True,
            "blocked_at": datetime.now(timezone.utc),
        }}
    )
    logger.debug(f"Marked {ip} as blocked in DB.")


# ─────────────────────────────────────────────────────────────
# SUMMARY STATS
# ─────────────────────────────────────────────────────────────
def get_db_stats() -> dict:
    """Returns a summary of what's stored in the database."""
    collection = get_collection()
    return {
        "total":    collection.count_documents({}),
        "high":     collection.count_documents({"severity": "HIGH"}),
        "medium":   collection.count_documents({"severity": "MEDIUM"}),
        "low":      collection.count_documents({"severity": "LOW"}),
        "blocked":  collection.count_documents({"blocked": True}),
    }
