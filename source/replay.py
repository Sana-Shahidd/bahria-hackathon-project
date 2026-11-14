"""
Demo replay: feeds a recorded attack scenario through the REAL detection engine
(sniffer.analyze_traffic), so judges can watch IncidentPilot work on any laptop -
no VM lab, no root, no iptables.

    python source/replay.py                 # replay data/demo_scenario.json
    python source/replay.py --reset         # wipe the database first (fresh demo)
    python source/replay.py --slow          # longer pauses, nice for live demos
    python source/replay.py --file my.json  # your own scenario
"""
import argparse
import json
import os
import time
from datetime import timedelta

import db
import firewall
import incidents
import sniffer
from ai import triage
from config import PROJECT_ROOT


def seed_history(history, web_server):
    for item in history:
        when = db.now() - timedelta(hours=item.get("hours_ago", 24))
        incident_id = None
        for alert in item["alerts"]:
            alert_id = db.save_to_db(
                alert["attack_type"], item["source_ip"], web_server, None, alert.get("target_port"),
                "TCP", alert.get("severity", "Medium"), alert["description"],
                alert.get("status", "detected"), alert.get("action", "monitored"), detected_at=when,
            )
            incident_id = db.get_alert(alert_id)["incident_id"]
        if incident_id:
            triage.triage_incident(incident_id)
            if item.get("analyst_decision") == "dismissed":
                incidents.dismiss_incident(incident_id, item.get("analyst", "analyst"), item.get("notes", ""))
            elif item.get("analyst_decision") == "approved":
                incidents.approve_incident(incident_id, item.get("analyst", "analyst"), item.get("notes", ""), block=False)
            print(f"[HISTORY] INC-{incident_id} {item['source_ip']} -> {item.get('analyst_decision')}")


def run_step(step, web_server, pace):
    kind = step["type"]
    if step.get("comment"):
        print(f"\n>>> {step['comment']}")

    if kind == "pause":
        time.sleep(step.get("seconds", 1) * pace)

    elif kind == "traffic":
        payloads = step.get("payloads") or [""]
        for port in step.get("ports", [80]):
            for payload in payloads:
                sniffer.analyze_traffic(step["src"], step.get("dst", web_server), 40000 + port, port, payload)
                time.sleep(0.05 * pace)

    elif kind == "flood":
        for i in range(step.get("packets", 60)):
            sniffer.analyze_traffic(step["src"], step.get("dst", web_server), 50000 + i, step.get("port", 80), "")

    elif kind == "brute_force":
        sniffer.record_brute_force(step["src"], web_server, 5000, step.get("attempts", 5))


def main():
    parser = argparse.ArgumentParser(description="Replay a demo attack scenario")
    parser.add_argument("--file", default=os.path.join(PROJECT_ROOT, "data", "demo_scenario.json"))
    parser.add_argument("--reset", action="store_true", help="wipe the database before replaying")
    parser.add_argument("--slow", action="store_true", help="3x longer pauses (live demo)")
    parser.add_argument("--no-history", action="store_true", help="skip seeding past analyst decisions")
    args = parser.parse_args()

    if args.reset:
        import init_db
        init_db.init(reset=True)
        firewall.clear_blocked_ip_file()
        sniffer.blocked_ips.clear()  # loaded at import time, before the reset

    with open(args.file, "r", encoding="utf-8") as file:
        scenario = json.load(file)

    web_server = scenario.get("web_server", "192.168.56.104")
    print(f"=== {scenario.get('name', 'Replay')} ===")

    sniffer.prepare_engine()
    if not args.no_history:
        seed_history(scenario.get("history", []), web_server)

    pace = 3 if args.slow else 1
    for step in scenario["steps"]:
        run_step(step, web_server, pace)

    print("\n=== Running AI triage on new incidents ===")
    triage.run_pending_triage(limit=50)
    print("\nDone. Open http://127.0.0.1:5000/incidents")


if __name__ == "__main__":
    main()
