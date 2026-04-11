# database/mongo_setup.py
# All MongoDB operations: connect, store, query, mark blocked.
# Handles duplicate prevention and connection errors gracefully.

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import logging
from datetime import datetime, timezone
from config.config import MONGO_URI, DB_NAME, COLLECTION_NAME, RISK_HIGH

logger = logging.getLogger(__name__)

# Try importing pymongo — give clear error if not installed
try:
    from pymongo import MongoClient, ASCENDING
    from pymongo.errors import DuplicateKeyError, ConnectionFailure
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False
    logger.warning("pymongo not installed. Run: pip install pymongo")


def get_collection():
    """Connect to MongoDB and return the indicators collection."""
    if not MONGO_AVAILABLE:
        raise RuntimeError("pymongo is not installed.")

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
    client.admin.command("ping")  # Test connection

    col = client[DB_NAME][COLLECTION_NAME]
    col.create_index([("ip", ASCENDING)], unique=True)  # Prevent duplicates
    return col


def store_indicators(indicators: list) -> int:
    """
    Save normalized indicators to MongoDB.
    - New IP  → insert fresh document
    - Known IP → update risk_score and last_seen only
    Returns count of newly inserted documents.
    """
    if not indicators:
        return 0

    try:
        col = get_collection()
    except Exception as e:
        logger.error(f"MongoDB unavailable: {e}")
        return 0

    inserted = 0
    updated  = 0

    for doc in indicators:
        ip = doc.get("ip", "")
        if not ip:
            continue
        try:
            col.insert_one(doc.copy())
            inserted += 1
        except DuplicateKeyError:
            # IP already exists — just refresh its score and timestamp
            col.update_one(
                {"ip": ip},
                {"$set": {
                    "risk_score": doc["risk_score"],
                    "severity":   doc["severity"],
                    "last_seen":  datetime.now(timezone.utc),
                }}
            )
            updated += 1

    logger.info(f"DB: inserted={inserted}, updated={updated}")
    return inserted


def get_high_risk_ips() -> list:
    """
    Query MongoDB for unblocked HIGH-risk IPs.
    Returns list of dicts with ip, risk_score, severity, tags, source.
    """
    try:
        col = get_collection()
        results = list(
            col.find(
                {"risk_score": {"$gte": RISK_HIGH}, "blocked": False},
                {"_id": 0, "ip": 1, "risk_score": 1, "severity": 1, "tags": 1, "source": 1}
            ).sort("risk_score", -1)
        )
        logger.info(f"DB query: {len(results)} high-risk unblocked IPs")
        return results
    except Exception as e:
        logger.error(f"DB query failed: {e}")
        return []


def mark_blocked(ip: str):
    """Set blocked=True for an IP after it has been firewalled."""
    try:
        col = get_collection()
        col.update_one(
            {"ip": ip},
            {"$set": {"blocked": True, "blocked_at": datetime.now(timezone.utc)}}
        )
    except Exception as e:
        logger.warning(f"Could not mark {ip} as blocked in DB: {e}")


def get_stats() -> dict:
    """Return a summary count by severity and blocked status."""
    try:
        col = get_collection()
        return {
            "total":   col.count_documents({}),
            "high":    col.count_documents({"severity": "HIGH"}),
            "medium":  col.count_documents({"severity": "MEDIUM"}),
            "low":     col.count_documents({"severity": "LOW"}),
            "blocked": col.count_documents({"blocked": True}),
        }
    except Exception:
        return {}
