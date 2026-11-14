"""
Incident grouping and analyst decisions.

- Every new alert is attached to an incident: alerts from the same source IP
  within INCIDENT_WINDOW_MINUTES become one incident (one story, one timeline).
- Approve  -> block the IP (firewall + DB), mark alerts blocked, verdict true positive.
- Dismiss  -> mark as false positive (optionally whitelist). The AI uses these
  decisions as feedback for future, similar incidents.
"""
from datetime import timedelta

import db
import firewall
from config import INCIDENT_WINDOW_MINUTES, DEMO_MODE

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a, b):
    return a if SEVERITY_RANK.get((a or "").lower(), 0) >= SEVERITY_RANK.get((b or "").lower(), 0) else b


def attach_alert(alert_id):
    alert = db.get_alert(alert_id)
    if not alert:
        return None

    detected_at = alert["detected_at"]
    window_start = detected_at - timedelta(minutes=INCIDENT_WINDOW_MINUTES)
    incident = db.find_open_incident(alert["source_ip"], window_start)

    if incident:
        types = [t for t in (incident["attack_types"] or "").split(",") if t]
        if alert["attack_type"] not in types:
            types.append(alert["attack_type"])
        db.update_incident_counters(
            incident["id"],
            max(detected_at, incident["last_seen"]),
            ",".join(types),
            _max_severity(incident["max_severity"], alert["severity"]),
        )
        incident_id = incident["id"]
    else:
        incident_id = db.create_incident(
            alert["source_ip"], detected_at, alert["attack_type"], alert["severity"]
        )

    db.set_alert_incident(alert_id, incident_id)
    return incident_id


def _update_pending_alerts(incident_id, status, action):
    db._run("""
        UPDATE attacks SET status=%s, action_taken=%s
        WHERE incident_id=%s AND status='pending_approval'
    """, (status, action, incident_id))


def approve_incident(incident_id, user, notes="", block=True):
    incident = db.get_incident(incident_id)
    if not incident:
        return False, "Incident not found."

    message = "Incident approved as a true positive."
    if block and not db.is_ip_in_list(incident["source_ip"], "whitelist"):
        ip = incident["source_ip"]
        firewall.block_ip_iptables(ip)
        firewall.save_blocked_ip_to_file(ip)
        reason = f"Approved in IncidentPilot (INC-{incident_id})"
        db.save_blocked_ip_to_db(ip, reason[:100])
        _update_pending_alerts(incident_id, "blocked", "blocked")
        message = f"Approved. {ip} has been blocked." + (" (simulated - demo mode)" if DEMO_MODE else "")
    else:
        _update_pending_alerts(incident_id, "detected", "monitored")

    db.set_analyst_decision(incident_id, "approved", "true_positive", notes, user)
    return True, message


def dismiss_incident(incident_id, user, notes="", whitelist=False):
    incident = db.get_incident(incident_id)
    if not incident:
        return False, "Incident not found."

    _update_pending_alerts(incident_id, "dismissed", "dismissed")
    db.set_analyst_decision(incident_id, "dismissed", "false_positive", notes, user)

    message = "Dismissed as a false positive. Pilot will learn from this decision."
    if whitelist:
        db.add_ip_to_list(incident["source_ip"], "whitelist",
                          (notes or f"Whitelisted from INC-{incident_id}")[:100])
        message += f" {incident['source_ip']} added to whitelist."
    return True, message


def reopen_incident(incident_id):
    db.set_analyst_decision(incident_id, "new", None, None, None)
    db.request_retriage(incident_id)
