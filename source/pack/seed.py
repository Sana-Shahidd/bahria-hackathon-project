"""
Load the Orbit data-pack incidents into the IncidentPilot database so the Dashboard,
Incident queue, Logs and incident pages show them (not only the Orbit board).

Idempotent: incidents created here carry ai_engine "Orbit data-pack engine (IR-n)" and are
never created twice. Alert times are the real UTC times from the logs.
"""
import json
import re

import db
from pack import service

ENGINE = "Orbit data-pack engine"
ENGINE_RE = re.compile(r"\((IR-\d+|CL-\d+)\)")

# IDS alert -> how it appears in the alerts table
ALERT_MAP = {
    "ALT-9001": ("Port Scan", "Low", "192.0.2.88", "203.0.113.10", 443),
    "ALT-9002": ("Phishing Click", "Medium", "10.20.5.14", "198.51.100.77", 443),
    "ALT-9003": ("Account Takeover", "High", "198.51.100.77", "203.0.113.20", 443),
    "ALT-9004": ("SQL Injection", "High", "192.0.2.150", "203.0.113.10", 443),
    "ALT-9005": ("Data Exfiltration", "High", "198.51.100.77", "10.10.1.20", 445),
    "ALT-9006": ("Port Scan", "Low", "10.10.9.50", "10.10.1.0/24", None),
    "ALT-9007": ("Remote Desktop", "Low", "10.10.3.18", "10.10.1.5", 3389),
    "ALT-9008": ("Account Lockout", "Medium", "198.51.100.77", "10.10.1.5", 88),
}
MITRE = {
    "phish": [("T1566.002", "Phishing: Spearphishing Link"), ("T1621", "MFA Request Generation"), ("T1078", "Valid Accounts"), ("T1021.002", "SMB/Windows Admin Shares")],
    "web": [("T1190", "Exploit Public-Facing Application")],
    "scan": [("T1046", "Network Service Discovery"), ("T1595.002", "Active Scanning: Vulnerability Scanning")],
}
SEV_WORD = {"P1": "High", "P2": "High", "P3": "Medium", "P4": "Low"}


def orbit_ref(incident):
    m = ENGINE_RE.search((incident or {}).get("ai_engine") or "")
    return m.group(1) if m else None


def _naive(ts):
    return ts.replace(tzinfo=None)


def _already_seeded():
    return db._run("SELECT COUNT(*) FROM incidents WHERE ai_engine LIKE %s", (ENGINE + "%",), fetch="one")[0] > 0


def is_empty():
    return db._run("SELECT COUNT(*) FROM attacks", fetch="one")[0] == 0 and db._run("SELECT COUNT(*) FROM incidents", fetch="one")[0] == 0


def _alert_ids_in(timeline):
    ids = []
    for t in timeline:
        for c in t["cites"]:
            m = re.search(r"#(ALT-\d+)\]", c)
            if m and m.group(1) not in ids:
                ids.append(m.group(1))
    return ids


def _insert_alert(aid, ids_event, incident_id, status, action):
    typ, sev, src, dst, port = ALERT_MAP.get(aid, ("Security Alert", "Medium", "0.0.0.0", None, None))
    return db._run("""
        INSERT INTO attacks (attack_type, source_ip, target_ip, source_port, target_port, protocol, severity,
                             description, status, action_taken, detected_at, incident_id)
        VALUES (%s, %s, %s, NULL, %s, 'TCP', %s, %s, %s, %s, %s, %s)
    """, (typ, src, dst, port, sev, f"{aid} ({ids_event['sensor']}): {ids_event['desc']}", status, action,
          _naive(ids_event["ts"]), incident_id), insert_id=True)


def seed(force=False):
    """Insert the Orbit incidents. Returns the number of incidents created."""
    if not service.available():
        return 0
    if _already_seeded() and not force:
        return 0
    pack, analysis = service.get()
    ids_events = {e["alert_id"]: e for e in pack.events if e["src"] == "ids"}
    created = 0
    now = db.now()

    def make_incident(src_ip, alert_ids, **fields):
        evs = [ids_events[a] for a in alert_ids if a in ids_events]
        first, last = min(e["ts"] for e in evs), max(e["ts"] for e in evs)
        types = []
        for a in alert_ids:
            t = ALERT_MAP[a][0]
            if t not in types:
                types.append(t)
        sev_rank = {"Low": 0, "Medium": 1, "High": 2}
        max_sev = max((ALERT_MAP[a][1] for a in alert_ids), key=lambda s: sev_rank[s])
        iid = db._run("""
            INSERT INTO incidents (source_ip, first_seen, last_seen, alert_count, attack_types, max_severity, needs_triage,
                                   triage_status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, 0, 'triaged', %s)
        """, (src_ip, _naive(first), _naive(last), len(evs), ",".join(types), max_sev, now), insert_id=True)
        return iid, evs

    for inc in analysis.incidents:
        alert_ids = _alert_ids_in(inc["timeline"])
        if not alert_ids:
            continue
        src_ip = (inc["compromised"][0]["attacker_ip"] if inc.get("compromised") else str(inc["related_ids"][0]))
        iid, evs = make_incident(src_ip, alert_ids)
        rows = []
        for e in sorted(evs, key=lambda x: x["ts"]):
            a_id = _insert_alert(e["alert_id"], e, iid, "pending_approval", "block_recommended")
            rows.append((a_id, e))
        evidence = [f"alert #{a_id}: {e['alert_id']} - {e['desc']}" for a_id, e in rows]
        steps = [f"{a['cite'].split(' [')[0]}: {a['text']}" + (f" ({a['note']})" if a.get("note") else "") for a in inc["actions"]][:8]
        mitre = [{"id": i, "name": n} for i, n in MITRE.get(inc["kind"], [])]
        db._run("""
            UPDATE incidents SET ai_summary=%s, ai_verdict='true_positive', ai_priority=%s, ai_confidence=%s, ai_mitre=%s,
                                 ai_evidence=%s, ai_next_steps=%s, ai_recommended_action='block_ip', ai_feedback_used='[]',
                                 ai_engine=%s, triaged_at=%s, notified_at=%s
            WHERE id=%s
        """, (inc["summary"], inc["severity"], 0.9 if inc["severity"] in ("P1", "P2") else 0.8, json.dumps(mitre),
              json.dumps(evidence), json.dumps(steps), f"{ENGINE} ({inc['id']})", now, now, iid))
        created += 1

    for c in analysis.closed:
        aid = c["alert"]
        if aid not in ids_events:
            continue
        typ, sev, src, dst, port = ALERT_MAP[aid]
        iid, evs = make_incident(src, [aid])
        a_id = _insert_alert(aid, ids_events[aid], iid, "dismissed", "none")
        notes = f"Approved activity - {c['change_id']} ({c['status']}). " + " ".join(re.sub(r"\s*\[[^\]]+\]", "", r) for r in c["reasons"])
        db._run("""
            UPDATE incidents SET ai_summary=%s, ai_verdict='likely_false_positive', ai_priority='P4', ai_confidence=0.95, ai_mitre='[]',
                                 ai_evidence=%s, ai_next_steps=%s, ai_recommended_action='no_action', ai_feedback_used='[]',
                                 ai_engine=%s, triaged_at=%s, notified_at=%s, analyst_status='dismissed',
                                 analyst_verdict='false_positive', analyst_notes=%s, decided_by='orbit-engine', decided_at=%s
            WHERE id=%s
        """, (f"{c['title']} - closed as approved activity under {c['change_id']}; not escalated (rule 3.2).",
              json.dumps([f"alert #{a_id}: {aid} - {ids_events[aid]['desc']}"]),
              json.dumps([f"{x}" for x in c["runbook"]] or ["No action: approved change."]),
              f"{ENGINE} ({c['id']})", now, now, notes, now, iid))
        created += 1
    return created
