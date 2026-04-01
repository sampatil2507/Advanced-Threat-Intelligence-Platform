# =============================================================
# policy_enforcer/firewall.py
# Dynamic Security Policy Enforcer.
# Reads high-risk IPs and blocks them via iptables.
# Falls back to simulation mode if not running as root on Linux.
# =============================================================

import subprocess
import platform
import logging
from datetime import datetime, timezone

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.config import ENFORCE_REAL_FIREWALL
from database.mongo_setup import mark_as_blocked

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# PLATFORM CHECK
# ─────────────────────────────────────────────────────────────
def _is_linux_root() -> bool:
    """Returns True only if running as root on Linux."""
    return platform.system() == "Linux" and os.geteuid() == 0


def _can_use_iptables() -> bool:
    """
    Returns True if real iptables enforcement should run.
    Conditions: ENFORCE_REAL_FIREWALL=true AND root on Linux.
    """
    if not ENFORCE_REAL_FIREWALL:
        return False
    if not _is_linux_root():
        logger.warning(
            "ENFORCE_REAL_FIREWALL is true but not running as root on Linux. "
            "Falling back to simulation."
        )
        return False
    return True


# ─────────────────────────────────────────────────────────────
# IPTABLES COMMANDS
# ─────────────────────────────────────────────────────────────
def _rule_exists(ip: str) -> bool:
    """Checks if an iptables DROP rule already exists for this IP."""
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0


def _apply_iptables_block(ip: str) -> bool:
    """
    Executes: iptables -A INPUT -s <ip> -j DROP
    Returns True on success, False on failure.
    """
    if _rule_exists(ip):
        logger.debug(f"[iptables] Rule already exists for {ip}. Skipping.")
        return True

    try:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            logger.info(f"[iptables] BLOCKED: {ip}")
            return True
        else:
            logger.error(f"[iptables] Failed for {ip}: {result.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"[iptables] Timeout while blocking {ip}")
        return False
    except FileNotFoundError:
        logger.error("[iptables] iptables binary not found.")
        return False


def _apply_iptables_unblock(ip: str) -> bool:
    """
    Executes: iptables -D INPUT -s <ip> -j DROP
    Returns True on success.
    """
    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"[iptables] Unblock error for {ip}: {e}")
        return False


# ─────────────────────────────────────────────────────────────
# SIMULATION MODE
# ─────────────────────────────────────────────────────────────
def _simulate_block(ip: str, risk_score: int, tags: list):
    """
    Simulates a firewall block — logs the action without
    actually touching iptables. Safe on any OS.
    """
    tag_str = ", ".join(str(t) for t in tags) if tags else "none"
    logger.info(
        f"[SIMULATED] Would block: {ip} | "
        f"score={risk_score} | tags=[{tag_str}]"
    )


# ─────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────
def block_ip(ip: str, risk_score: int = 0, tags: list = None, source: str = "") -> bool:
    """
    Main blocking function called by main.py.
    - Tries real iptables if conditions are met.
    - Otherwise simulates and logs.
    - Updates MongoDB 'blocked' flag on success.
    Returns True if block was applied (real or simulated).
    """
    tags = tags or []

    if _can_use_iptables():
        # Real iptables enforcement
        success = _apply_iptables_block(ip)
        if success:
            mark_as_blocked(ip)
        return success
    else:
        # Simulation mode — safe for demo/testing
        _simulate_block(ip, risk_score, tags)
        mark_as_blocked(ip)   # Still mark in DB for audit trail
        return True


def unblock_ip(ip: str) -> bool:
    """
    Removes the iptables DROP rule for an IP (rollback).
    Only works in real enforcement mode.
    """
    if _can_use_iptables():
        success = _apply_iptables_unblock(ip)
        if success:
            logger.info(f"[iptables] UNBLOCKED (rollback): {ip}")
        return success
    else:
        logger.info(f"[SIMULATED] Would unblock: {ip}")
        return True


def block_all(high_risk_ips: list) -> int:
    """
    Iterates over a list of high-risk indicator dicts and blocks each IP.
    Returns the count of successfully blocked IPs.
    """
    if not high_risk_ips:
        logger.info("No high-risk IPs to block.")
        return 0

    mode = "REAL iptables" if _can_use_iptables() else "SIMULATION"
    logger.info(f"Starting enforcement in {mode} mode for {len(high_risk_ips)} IPs...")

    blocked_count = 0

    for indicator in high_risk_ips:
        ip         = indicator.get("ip", "")
        risk_score = indicator.get("risk_score", 0)
        tags       = indicator.get("tags", [])
        source     = indicator.get("source", "")

        if not ip:
            continue

        success = block_ip(ip, risk_score=risk_score, tags=tags, source=source)
        if success:
            blocked_count += 1

    logger.info(f"Enforcement complete → blocked: {blocked_count}/{len(high_risk_ips)} IPs")
    return blocked_count
