"""
Bring-your-own-logs: analyse a web server access log (Nginx / Apache
"combined" or "common" format) with the same detection rules, then let Pilot
triage the resulting incidents.

Detects
- SQL injection / XSS in the request line      (same signatures as the sensor)
- Brute force: >= 5 failed logins (401/403 on a login URL) within 60 s,
  and flags a SUCCESSFUL login right after the failures (possible compromise)
- Web scan: >= 15 different 404 paths within 60 s (gobuster / dirbuster style)
- High traffic: more requests in 5 s than the high-traffic threshold
- Known attack-tool user agents (sqlmap, nikto, gobuster, hydra...) are noted as evidence

Use from the dashboard (Logs -> Upload access log) or the command line:
    python source/log_ingest.py data/sample_access.log
"""
import re
import sys
from collections import defaultdict, deque
from datetime import datetime
from urllib.parse import unquote_plus

import db
import sniffer
from config import WEB_SERVER_IP

LINE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?'
)
LOGIN_RE = re.compile(r"/(wp-login\.php|login|signin|sign-in|auth|admin/login|user/login)\b", re.I)
TOOL_RE = re.compile(r"sqlmap|nikto|gobuster|dirbuster|dirb|wfuzz|ffuf|hydra|wpscan|nmap|masscan|acunetix|nessus", re.I)

BRUTE_FAILS, BRUTE_WINDOW = 5, 60
SCAN_404S, SCAN_WINDOW = 15, 60
FLOOD_WINDOW = 5


def parse_line(line):
    match = LINE_RE.match(line.strip())
    if not match:
        return None
    entry = match.groupdict()
    try:
        entry["time"] = datetime.strptime(entry["time"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
    except ValueError:
        entry["time"] = datetime.now()
    parts = entry["request"].split(" ")
    entry["method"] = parts[0] if parts else ""
    entry["path"] = parts[1] if len(parts) > 1 else entry["request"]
    entry["status"] = int(entry["status"])
    entry["agent"] = entry.get("agent") or ""
    return entry


def _tool_note(agent):
    match = TOOL_RE.search(agent or "")
    return f" User-Agent reveals attack tool: {match.group(0)}." if match else ""


def ingest_lines(lines, source_name="access.log"):
    sniffer.prepare_engine()
    before = db._run("SELECT COALESCE(MAX(id), 0) FROM attacks", fetch="one")[0]

    stats = {"lines": 0, "parsed": 0, "skipped_trusted": 0}
    fails = defaultdict(deque)          # ip -> times of failed logins
    brute_reported = set()
    notfound = defaultdict(deque)       # ip -> (time, path)
    scan_reported = set()
    rate = defaultdict(deque)           # ip -> times
    flood_reported = set()
    tools = {}

    for raw in lines:
        stats["lines"] += 1
        entry = parse_line(raw)
        if not entry:
            continue
        stats["parsed"] += 1
        ip, when = entry["ip"], entry["time"]

        if ip in sniffer.WHITELIST or ip in sniffer.blocked_ips:
            stats["skipped_trusted"] += 1
            continue

        if TOOL_RE.search(entry["agent"]):
            tools[ip] = entry["agent"]
        port = 443 if entry["path"].startswith("https") else 80

        # 1) SQLi / XSS in the URL (same signatures as the live sensor)
        attack = sniffer.detect_web_attack(entry["request"])
        if attack:
            payload = f"{entry['request']} (HTTP {entry['status']}, {when:%H:%M:%S}){_tool_note(entry['agent'])}"
            sniffer.handle_web_attack(attack, ip, WEB_SERVER_IP, None, port, payload)

        # 2) Brute force (+ success after failures)
        if LOGIN_RE.search(entry["path"]) and entry["method"] == "POST":
            q = fails[ip]
            if entry["status"] in (401, 403):
                q.append(when)
                while q and (when - q[0]).total_seconds() > BRUTE_WINDOW:
                    q.popleft()
                if len(q) >= BRUTE_FAILS and ip not in brute_reported:
                    brute_reported.add(ip)
                    sniffer.record_brute_force(ip, WEB_SERVER_IP, port, len(q))
            elif entry["status"] in (200, 302) and len(q) >= BRUTE_FAILS:
                status, action, suffix = sniffer.enforce_or_recommend(ip, "Login succeeded after brute force")
                db.save_to_db("Brute Force", ip, WEB_SERVER_IP, None, port, "HTTP", "High",
                              f"SUCCESSFUL login on {entry['path']} at {when:%H:%M:%S} right after {len(q)} failed "
                              f"attempts - possible account compromise.{_tool_note(entry['agent'])} {suffix}",
                              status, action)
                q.clear()

        # 3) Web content scan (many distinct 404s)
        if entry["status"] == 404:
            q = notfound[ip]
            q.append((when, entry["path"]))
            while q and (when - q[0][0]).total_seconds() > SCAN_WINDOW:
                q.popleft()
            paths = {p for _, p in q}
            if len(paths) >= SCAN_404S and ip not in scan_reported:
                scan_reported.add(ip)
                status, action, suffix = sniffer.enforce_or_recommend(ip, "Web content scan")
                sample = ", ".join(sorted(paths)[:8])
                db.save_to_db("Web Scan", ip, WEB_SERVER_IP, None, port, "HTTP", "Medium",
                              f"{len(paths)} different missing paths requested within {SCAN_WINDOW} s "
                              f"(e.g. {sample}).{_tool_note(entry['agent'])} {suffix}", status, action)

        # 4) Request flood (log time based)
        q = rate[ip]
        q.append(when)
        while q and (when - q[0]).total_seconds() > FLOOD_WINDOW:
            q.popleft()
        if len(q) > sniffer.HIGH_TRAFFIC_THRESHOLD and ip not in flood_reported:
            flood_reported.add(ip)
            status, action, suffix = sniffer.enforce_or_recommend(ip, "HTTP request flood")
            db.save_to_db("High Traffic", ip, WEB_SERVER_IP, None, port, "HTTP", "High",
                          f"{len(q)} HTTP requests in {FLOOD_WINDOW} s (threshold {sniffer.HIGH_TRAFFIC_THRESHOLD}) "
                          f"in {source_name}.{_tool_note(entry['agent'])} {suffix}", status, action)

    after = db._run("SELECT COALESCE(MAX(id), 0) FROM attacks", fetch="one")[0]
    stats["alerts"] = after - before
    stats["tools_seen"] = tools
    return stats


def ingest_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        return ingest_lines(file, source_name=path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python source/log_ingest.py <access.log>")
        sys.exit(1)
    from ai.triage import run_pending_triage
    result = ingest_file(sys.argv[1])
    print(f"Parsed {result['parsed']}/{result['lines']} lines, {result['alerts']} alert(s) created.")
    if result["tools_seen"]:
        print("Attack tools seen:", ", ".join(f"{ip} ({ua})" for ip, ua in result["tools_seen"].items()))
    print(f"Pilot triaged {run_pending_triage(limit=50)} incident(s).")
