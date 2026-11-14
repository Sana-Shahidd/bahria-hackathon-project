"""
Firewall actions (iptables), shared by the sensor and the dashboard.

Changes from CyberPulse:
- one shared module instead of two copies (sniffer.py and app.py)
- subprocess with argument lists instead of os.system string commands
- DEMO_MODE: blocks are simulated, so the project runs safely on any laptop
"""
import ipaddress
import os
import subprocess

from config import DEMO_MODE, LOGS_DIR

BLOCKED_FILE = os.path.join(LOGS_DIR, "blocked_ips.txt")


def _valid(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _iptables(*args):
    try:
        return subprocess.run(["iptables", *args], capture_output=True).returncode
    except FileNotFoundError:
        print("[FIREWALL] iptables not found on this system")
        return 1


def block_ip_iptables(ip):
    if not _valid(ip):
        print(f"[FIREWALL] refused to block invalid IP: {ip}")
        return

    if DEMO_MODE:
        print(f"[FIREWALL][DEMO] would block {ip}")
        return

    if _iptables("-C", "INPUT", "-s", ip, "-j", "DROP") != 0:
        _iptables("-A", "INPUT", "-s", ip, "-j", "DROP")
        print(f"[FIREWALL] {ip} blocked")
    else:
        print(f"[FIREWALL] {ip} already blocked")


def unblock_ip_iptables(ip):
    if not _valid(ip):
        return

    if DEMO_MODE:
        print(f"[FIREWALL][DEMO] would unblock {ip}")
        return

    for chain in ("INPUT", "FORWARD"):
        while _iptables("-D", chain, "-s", ip, "-j", "DROP") == 0:
            pass

    print(f"[FIREWALL] {ip} unblocked")


# ---------------------------------------------------------------- blocked_ips.txt helpers

def _ensure_logs():
    os.makedirs(LOGS_DIR, exist_ok=True)


def read_blocked_file():
    _ensure_logs()
    if not os.path.exists(BLOCKED_FILE):
        open(BLOCKED_FILE, "w").close()
        return []
    with open(BLOCKED_FILE, "r") as file:
        return [line.strip() for line in file if line.strip()]


def save_blocked_ip_to_file(ip):
    if ip not in read_blocked_file():
        with open(BLOCKED_FILE, "a") as file:
            file.write(ip + "\n")


def remove_ip_from_blocked_file(ip):
    remaining = [line for line in read_blocked_file() if line != ip]
    with open(BLOCKED_FILE, "w") as file:
        file.writelines(line + "\n" for line in remaining)


def clear_blocked_ip_file():
    _ensure_logs()
    open(BLOCKED_FILE, "w").close()
