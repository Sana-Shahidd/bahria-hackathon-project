"""
Detection engine (the "eyes" of IncidentPilot).

Kept from CyberPulse: SQLi / XSS signatures, time-window port-scan and
high-traffic detection, dynamic severity, whitelist / blacklist, duplicate
suppression and configurable thresholds.

Changed for IncidentPilot:
- packet parsing is separated from analysis (`analyze_traffic`) so the same
  rules run on live packets AND on replayed demo traffic (replay.py)
- "Analyst approval" mode: when a threshold is hit the engine *recommends* a
  block and IncidentPilot's AI triage + analyst decide (default). Set
  `require_analyst_approval` to false in Settings for the old auto-block.
- iptables calls go through firewall.py (safe in DEMO_MODE)
- network / interface / sensor IP come from config instead of being hard-coded
- scapy is imported lazily, so demo mode works without it
"""
from datetime import datetime
import ipaddress
import json
import os
import re
import time
from urllib.parse import unquote_plus

from config import (
    IDS_INTERFACE, MONITORED_NETWORK as MONITORED_NETWORK_CIDR, IDS_HOST_IP,
    RULES_FILE, LOGS_DIR, DASHBOARD_HOST_IP,
)
from db import save_blocked_ip_to_db, get_ip_list, save_to_db
import firewall


MONITORED_NETWORK = ipaddress.ip_network(MONITORED_NETWORK_CIDR)

PORT_SCAN_TIME_WINDOW = 5
HIGH_TRAFFIC_TIME_WINDOW = 5
DUPLICATE_TIME_WINDOW = 15
RULES_REFRESH_SECONDS = 2
DEBUG = False

DEFAULT_RULES = {
    "sql_block_threshold": 3,
    "xss_block_threshold": 3,
    "high_traffic_threshold": 40,
    "port_scan_threshold": 5,
    "sql_block_enabled": True,
    "xss_block_enabled": True,
    "high_traffic_block_enabled": True,
    "port_scan_block_enabled": True,
    "require_analyst_approval": True
}


def load_rules():
    try:
        with open(RULES_FILE, "r") as file:
            rules = json.load(file)

        for key, value in DEFAULT_RULES.items():
            if key not in rules:
                rules[key] = value

        return rules

    except Exception as error:
        print("Rules config read error:", error)
        return DEFAULT_RULES.copy()


_last_refresh = 0.0


def refresh_rules(force=False):
    global HIGH_TRAFFIC_THRESHOLD
    global PORT_SCAN_THRESHOLD
    global SQL_BLOCK_THRESHOLD
    global XSS_BLOCK_THRESHOLD
    global SQL_BLOCK_ENABLED
    global XSS_BLOCK_ENABLED
    global HIGH_TRAFFIC_BLOCK_ENABLED
    global PORT_SCAN_BLOCK_ENABLED
    global REQUIRE_ANALYST_APPROVAL
    global _last_refresh

    # CyberPulse re-read the JSON file on every packet; throttle it.
    if not force and time.time() - _last_refresh < RULES_REFRESH_SECONDS:
        return
    _last_refresh = time.time()

    rules = load_rules()

    HIGH_TRAFFIC_THRESHOLD = int(rules.get("high_traffic_threshold", 40))
    PORT_SCAN_THRESHOLD = int(rules.get("port_scan_threshold", 5))
    SQL_BLOCK_THRESHOLD = int(rules.get("sql_block_threshold", 3))
    XSS_BLOCK_THRESHOLD = int(rules.get("xss_block_threshold", 3))

    SQL_BLOCK_ENABLED = bool(rules.get("sql_block_enabled", True))
    XSS_BLOCK_ENABLED = bool(rules.get("xss_block_enabled", True))
    HIGH_TRAFFIC_BLOCK_ENABLED = bool(rules.get("high_traffic_block_enabled", True))
    PORT_SCAN_BLOCK_ENABLED = bool(rules.get("port_scan_block_enabled", True))
    REQUIRE_ANALYST_APPROVAL = bool(rules.get("require_analyst_approval", True))

    # pick up blocks approved from the dashboard (separate process)
    for ip in firewall.read_blocked_file():
        if ip not in blocked_ips:
            blocked_ips.append(ip)


packet_times = {}
port_tracker = {}
attack_counter = {}
blocked_ips = []
last_logged_attacks = {}

WHITELIST = []
BLACKLIST = []

refresh_rules(force=True)


SQL_INJECTION_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s*'1'\s*=\s*'1",
    r'"?\s*or\s*"1"\s*=\s*"1',
    r"admin'\s*--",
    r"drop\s+table",
    r"delete\s+from",
    r"insert\s+into",
    r"update\s+users",
    r"select\s+\*\s+from",
    r"information_schema",
    r"sleep\s*\(",
    r"benchmark\s*\("
]

XSS_PATTERNS = [
    r"<\s*script",
    r"<\s*/\s*script\s*>",
    r"javascript\s*:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"<\s*img",
    r"<\s*iframe"
]


def is_duplicate_attack(source_ip, attack_type):
    current_time = datetime.now().timestamp()
    attack_key = (source_ip, attack_type)

    if attack_key in last_logged_attacks:
        last_time = last_logged_attacks[attack_key]

        if current_time - last_time < DUPLICATE_TIME_WINDOW:
            if DEBUG:
                print(f"[DUPLICATE] {attack_type} from {source_ip} ignored")
            return True

    last_logged_attacks[attack_key] = current_time
    return False


def increase_attack_counter(source_ip, attack_type):
    key = (source_ip, attack_type)
    attack_counter[key] = attack_counter.get(key, 0) + 1
    return attack_counter[key]


def save_alert(message):
    os.makedirs(LOGS_DIR, exist_ok=True)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(os.path.join(LOGS_DIR, "alerts.txt"), "a") as file:
        file.write(f"[{current_time}] {message}\n")


def load_blocked_ips():
    for ip in firewall.read_blocked_file():
        if ip not in blocked_ips:
            blocked_ips.append(ip)


def is_in_monitored_network(ip):
    try:
        return ipaddress.ip_address(ip) in MONITORED_NETWORK
    except ValueError:
        return False


def get_payload(packet):
    if packet.haslayer("Raw"):
        return packet["Raw"].load.decode(errors="ignore")

    try:
        return bytes(packet["TCP"].payload).decode(errors="ignore")
    except Exception:
        return ""


def detect_web_attack(payload):
    decoded_payload = unquote_plus(payload.lower())

    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, decoded_payload, re.IGNORECASE):
            return "SQL Injection"

    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded_payload, re.IGNORECASE):
            return "XSS Attack"

    return None


def auto_block_ip(ip, reason):
    print(f"[AUTO BLOCK] {ip} - {reason}")

    firewall.block_ip_iptables(ip)

    if ip not in blocked_ips:
        blocked_ips.append(ip)

    firewall.save_blocked_ip_to_file(ip)
    save_blocked_ip_to_db(ip, reason)
    save_alert(f"[BLOCKED] {ip} - {reason}")


def enforce_or_recommend(source_ip, reason):
    """
    Threshold reached. Either block now (CyberPulse behaviour) or hand the
    decision to IncidentPilot's AI triage + analyst (default).
    Returns (status, action_taken, description_suffix).
    """
    if REQUIRE_ANALYST_APPROVAL:
        print(f"[RECOMMEND] Block {source_ip} - {reason} (awaiting analyst approval)")
        save_alert(f"[BLOCK RECOMMENDED] {source_ip} - {reason}")
        return "pending_approval", "block_recommended", "Block recommended - awaiting analyst approval."

    auto_block_ip(source_ip, reason)
    return "blocked", "blocked", "IP blocked."


def load_ip_lists():
    global WHITELIST, BLACKLIST

    WHITELIST = [ip[1] for ip in get_ip_list("whitelist")]
    BLACKLIST = [ip[1] for ip in get_ip_list("blacklist")]


def should_block_web_attack(web_attack_type, attack_count):
    if web_attack_type == "SQL Injection":
        return SQL_BLOCK_ENABLED and attack_count >= SQL_BLOCK_THRESHOLD

    if web_attack_type == "XSS Attack":
        return XSS_BLOCK_ENABLED and attack_count >= XSS_BLOCK_THRESHOLD

    return attack_count >= 3


def get_web_threshold(web_attack_type):
    if web_attack_type == "SQL Injection":
        return SQL_BLOCK_THRESHOLD

    if web_attack_type == "XSS Attack":
        return XSS_BLOCK_THRESHOLD

    return 3


def get_dynamic_severity(attack_count, block_threshold):
    if attack_count >= block_threshold:
        return "High"

    if attack_count == block_threshold - 1:
        return "Medium"

    return "Low"


def _short_payload(payload, limit=120):
    text = " ".join((payload or "").split())
    return text if len(text) <= limit else text[:limit] + "..."


def handle_web_attack(web_attack_type, source_ip, target_ip, source_port, target_port, payload=""):
    refresh_rules()

    attack_count = increase_attack_counter(source_ip, web_attack_type)
    block_threshold = get_web_threshold(web_attack_type)
    severity = get_dynamic_severity(attack_count, block_threshold)
    evidence = f" Payload: {_short_payload(payload)}" if payload else ""

    if should_block_web_attack(web_attack_type, attack_count):
        if REQUIRE_ANALYST_APPROVAL and is_duplicate_attack(source_ip, web_attack_type + ":threshold"):
            return

        status, action_taken, suffix = enforce_or_recommend(
            source_ip, f"{web_attack_type} threshold reached"
        )
        description = (
            f"{web_attack_type} pattern detected {attack_count} times. "
            f"Threshold reached. {suffix}{evidence}"
        )

        print(f"[WEB ATTACK] {web_attack_type} detected from {source_ip} ({attack_count} attempts)")

        save_to_db(web_attack_type, source_ip, target_ip, source_port, target_port,
                   "TCP", severity, description, status, action_taken)
        return

    if web_attack_type == "SQL Injection" and not SQL_BLOCK_ENABLED:
        description = f"{web_attack_type} pattern detected. Blocking is disabled by rule settings.{evidence}"
    elif web_attack_type == "XSS Attack" and not XSS_BLOCK_ENABLED:
        description = f"{web_attack_type} pattern detected. Blocking is disabled by rule settings.{evidence}"
    else:
        description = (
            f"{web_attack_type} pattern detected. "
            f"Attempt {attack_count}/{block_threshold}. IP is monitored.{evidence}"
        )

    if is_duplicate_attack(source_ip, web_attack_type):
        return

    print(f"[WEB ATTACK] {web_attack_type} detected from {source_ip} ({attack_count}/{block_threshold})")
    print("[ACTION] Monitoring only")

    save_to_db(web_attack_type, source_ip, target_ip, source_port, target_port,
               "TCP", severity, description, "detected", "monitored")


def handle_port_scan(source_ip, target_ip, source_port, target_port):
    current_time = datetime.now().timestamp()

    port_tracker.setdefault(source_ip, []).append((target_port, current_time))

    port_tracker[source_ip] = [
        item for item in port_tracker[source_ip]
        if current_time - item[1] <= PORT_SCAN_TIME_WINDOW
    ]

    recent_ports = sorted(set(item[0] for item in port_tracker[source_ip]))

    if len(recent_ports) > PORT_SCAN_THRESHOLD:
        if is_duplicate_attack(source_ip, "Port Scan"):
            port_tracker[source_ip].clear()
            return

        print(f"[PORT SCAN] Detected from {source_ip}")
        base = (
            f"The source IP accessed {len(recent_ports)} different ports in "
            f"{PORT_SCAN_TIME_WINDOW} seconds (threshold {PORT_SCAN_THRESHOLD}). "
            f"Ports: {', '.join(str(p) for p in recent_ports[:20])}."
        )

        if PORT_SCAN_BLOCK_ENABLED:
            status, action_taken, suffix = enforce_or_recommend(source_ip, "Port scan detected")
            description = f"{base} {suffix}"
        else:
            print("[ACTION] Monitoring port scan only")
            status, action_taken = "detected", "monitored"
            description = f"{base} Blocking is disabled by rule settings."

        save_to_db("Port Scan", source_ip, target_ip, source_port, target_port,
                   "TCP", "Medium", description, status, action_taken)

        port_tracker[source_ip].clear()


def handle_high_traffic(source_ip, target_ip, source_port, target_port):
    current_time = datetime.now().timestamp()

    packet_times.setdefault(source_ip, []).append(current_time)

    packet_times[source_ip] = [
        time_value
        for time_value in packet_times[source_ip]
        if current_time - time_value <= HIGH_TRAFFIC_TIME_WINDOW
    ]

    if len(packet_times[source_ip]) > HIGH_TRAFFIC_THRESHOLD:
        if is_duplicate_attack(source_ip, "High Traffic"):
            return

        print(f"[HIGH TRAFFIC] Detected from {source_ip}")
        base = (
            f"More than {HIGH_TRAFFIC_THRESHOLD} packets were sent in "
            f"{HIGH_TRAFFIC_TIME_WINDOW} seconds (target port {target_port})."
        )

        if HIGH_TRAFFIC_BLOCK_ENABLED:
            status, action_taken, suffix = enforce_or_recommend(source_ip, "High traffic detected")
            description = f"{base} {suffix}"
        else:
            print("[ACTION] Monitoring high traffic only")
            status, action_taken = "detected", "monitored"
            description = f"{base} Blocking is disabled by rule settings."

        save_to_db("High Traffic", source_ip, target_ip, source_port, target_port,
                   "TCP", "High", description, status, action_taken)


def record_brute_force(source_ip, target_ip=DASHBOARD_HOST_IP, target_port=5000, attempts=5):
    """Brute-force on the dashboard login (called by app.py and replay.py)."""
    refresh_rules()
    base = f"{attempts} failed login attempts within 60 seconds."
    status, action_taken, suffix = enforce_or_recommend(source_ip, "Brute force attack")
    return save_to_db("Brute Force", source_ip, target_ip, None, target_port,
                      "HTTP", "High", f"{base} {suffix}", status, action_taken)


def analyze_traffic(source_ip, target_ip, source_port, target_port, payload=""):
    """Run every detection rule on one TCP packet / request."""
    refresh_rules()

    if source_ip == IDS_HOST_IP:
        return

    if not (is_in_monitored_network(source_ip) or is_in_monitored_network(target_ip)):
        return

    if source_ip in WHITELIST:
        return

    if source_ip in blocked_ips:
        return  # already blocked (iptables drops it on a real sensor)

    if source_ip in BLACKLIST:
        auto_block_ip(source_ip, "Manual blacklist")
        return

    # 1) Web attack detection
    if payload:
        web_attack_type = detect_web_attack(payload)

        if web_attack_type:
            handle_web_attack(web_attack_type, source_ip, target_ip, source_port, target_port, payload)
            return

    # 2) Time-based port scan detection
    handle_port_scan(source_ip, target_ip, source_port, target_port)

    # 3) Time-based high traffic detection
    handle_high_traffic(source_ip, target_ip, source_port, target_port)


def packet_info(packet):
    if not packet.haslayer("IP") or not packet.haslayer("TCP"):
        return

    analyze_traffic(
        packet["IP"].src,
        packet["IP"].dst,
        packet["TCP"].sport,
        packet["TCP"].dport,
        get_payload(packet),
    )


def prepare_engine():
    refresh_rules(force=True)
    load_blocked_ips()
    load_ip_lists()


def start_sniffer():
    from scapy.all import sniff  # needs root + scapy; not needed for demo replay

    prepare_engine()

    print("Traffic monitoring started!")
    print("Whitelist:", WHITELIST)
    print("Blacklist:", BLACKLIST)
    print("Loaded blocked IPs:", blocked_ips)
    print("SQL / XSS block threshold:", SQL_BLOCK_THRESHOLD, "/", XSS_BLOCK_THRESHOLD)
    print("High traffic threshold:", HIGH_TRAFFIC_THRESHOLD, "packets /", HIGH_TRAFFIC_TIME_WINDOW, "s")
    print("Port scan threshold:", PORT_SCAN_THRESHOLD, "ports /", PORT_SCAN_TIME_WINDOW, "s")
    print("Analyst approval required:", REQUIRE_ANALYST_APPROVAL)

    sniff(prn=packet_info, store=False, iface=IDS_INTERFACE)


if __name__ == "__main__":
    start_sniffer()
