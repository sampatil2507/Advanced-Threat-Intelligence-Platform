# policy_enforcer/firewall.py
# Blocks malicious IPs using iptables (Linux root) or simulation mode.
# Simulation mode is safe on Windows / Mac / non-root Linux.

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import subprocess
import platform
import logging
from datetime import datetime, timezone
from config.config import REAL_FIREWALL

logger = logging.getLogger(__name__)


def _is_root_linux() -> bool:
    return platform.system() == "Linux" and os.geteuid() == 0


def _use_real_iptables() -> bool:
    """Only use iptables if flag is true AND we are root on Linux."""
    if not REAL_FIREWALL:
        return False
    if not _is_root_linux():
        logger.warning("ENFORCE_REAL_FIREWALL=true but not root on Linux. Using simulation.")
        return False
    return True


def _already_blocked(ip: str) -> bool:
    """Check if iptables DROP rule already exists for this IP."""
    r = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True
    )
    return r.returncode == 0


def _iptables_block(ip: str) -> bool:
    """Run: iptables -A INPUT -s <ip> -j DROP"""
    if _already_blocked(ip):
        return True
    try:
        r = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            logger.info(f"[iptables] BLOCKED {ip}")
            return True
        else:
            logger.error(f"[iptables] Error blocking {ip}: {r.stderr.strip()}")
            return False
    except FileNotFoundError:
        logger.error("[iptables] iptables not found on this system.")
        return False
    except Exception as e:
        logger.error(f"[iptables] Exception: {e}")
        return False


def _iptables_unblock(ip: str) -> bool:
    """Run: iptables -D INPUT -s <ip> -j DROP"""
    try:
        r = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=10
        )
        return r.returncode == 0
    except Exception as e:
        logger.error(f"[iptables] Unblock error: {e}")
        return False


def block_ip(ip: str, risk_score: int = 0, tags: list = None, source: str = "") -> bool:
    """
    Block one IP.
    - Real mode: executes iptables command
    - Simulation: logs what WOULD happen (safe for demo)
    """
    tags = tags or []
    tag_str = ", ".join(str(t) for t in tags)

    if _use_real_iptables():
        success = _iptables_block(ip)
    else:
        # Simulation — print what the command would be
        logger.info(
            f"[SIMULATED] iptables -A INPUT -s {ip} -j DROP  "
            f"| score={risk_score} | tags=[{tag_str}] | source={source}"
        )
        success = True

    # Always update DB flag regardless of mode
    if success:
        from database.mongo_setup import mark_blocked
        mark_blocked(ip)

    return success


def unblock_ip(ip: str) -> bool:
    """Rollback — remove iptables rule for a false-positive IP."""
    if _use_real_iptables():
        ok = _iptables_unblock(ip)
        if ok:
            logger.info(f"[iptables] UNBLOCKED {ip}")
        return ok
    else:
        logger.info(f"[SIMULATED] Would unblock {ip}")
        return True


def block_all(high_risk_list: list) -> int:
    """
    Block every IP in the list.
    Returns count of successfully blocked IPs.
    """
    if not high_risk_list:
        return 0

    mode = "REAL iptables" if _use_real_iptables() else "SIMULATION"
    logger.info(f"Enforcement mode: {mode} | {len(high_risk_list)} IPs to block")

    count = 0
    for ind in high_risk_list:
        ip = ind.get("ip", "")
        if not ip:
            continue
        ok = block_ip(
            ip,
            risk_score=ind.get("risk_score", 0),
            tags=ind.get("tags", []),
            source=ind.get("source", ""),
        )
        if ok:
            count += 1

    logger.info(f"Blocked {count}/{len(high_risk_list)} IPs")
    return count
