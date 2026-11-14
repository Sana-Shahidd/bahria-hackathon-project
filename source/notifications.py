"""
P1 alerts: when Pilot triages an incident as P1, notify the team once.

- In-app: every dashboard page polls /api/alerts/critical and shows a toast
  (see _pilot_widget.html). Nothing to configure.
- Webhook (optional): set NOTIFY_WEBHOOK_URL to a Slack or Discord incoming
  webhook (or any URL that accepts JSON). The payload has both `text` (Slack)
  and `content` (Discord).
"""
import json
import urllib.request

import db
from config import NOTIFY_WEBHOOK_URL, PUBLIC_BASE_URL


def build_message(incident):
    link = f"{PUBLIC_BASE_URL.rstrip('/')}/incidents/{incident['id']}"
    action = {"block_ip": "Block recommended - approval needed",
              "monitor": "Monitor", "no_action": "No action"}.get(incident.get("ai_recommended_action"), "-")
    return (f":rotating_light: *IncidentPilot P1* - INC-{incident['id']} from {incident['source_ip']}\n"
            f"{incident.get('ai_summary') or ''}\n"
            f"Attack types: {', '.join(incident['attack_type_list'])} | {action}\n{link}")


def send_webhook(text):
    if not NOTIFY_WEBHOOK_URL:
        return False
    data = json.dumps({"text": text, "content": text[:1900]}).encode("utf-8")
    request = urllib.request.Request(NOTIFY_WEBHOOK_URL, data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return 200 <= response.status < 300


def notify_critical(incident_id):
    incident = db.get_incident(incident_id)
    if not incident or incident.get("notified_at"):
        return False
    db.mark_notified(incident_id)  # mark first so we never spam on retries
    message = build_message(incident)
    print(f"[NOTIFY] P1 INC-{incident_id}: {incident['source_ip']}")
    try:
        if send_webhook(message):
            print("[NOTIFY] webhook delivered")
    except Exception as error:
        print("[NOTIFY] webhook failed:", error)
    return True
