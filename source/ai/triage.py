"""
AI triage: turns an incident (a group of alerts) into an analyst-ready verdict.

Output (same shape from the LLM and from the offline engine):
{
  "summary": str, "verdict": "true_positive|likely_false_positive|needs_review",
  "priority": "P1..P4", "confidence": 0..1, "mitre": [{"id","name"}],
  "evidence": ["alert #12: ..."], "next_steps": [str],
  "recommended_action": "block_ip|monitor|no_action", "feedback_used": [incident ids],
  "reasoning": str
}

Feedback learning: past analyst decisions on similar incidents (same IP or same
attack types) are injected into the prompt, so a dismissed false positive
changes how the next similar incident is triaged. No model training needed.
"""
import json
from datetime import timedelta

import db
from ai import llm

MITRE = {
    "Port Scan": {"id": "T1046", "name": "Network Service Discovery"},
    "SQL Injection": {"id": "T1190", "name": "Exploit Public-Facing Application"},
    "XSS Attack": {"id": "T1059.007", "name": "Command and Scripting Interpreter: JavaScript"},
    "Brute Force": {"id": "T1110", "name": "Brute Force"},
    "High Traffic": {"id": "T1498", "name": "Network Denial of Service"},
    "Web Scan": {"id": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
}

BASE_SCORE = {"SQL Injection": 40, "Brute Force": 35, "XSS Attack": 30, "High Traffic": 25, "Port Scan": 15, "Web Scan": 15}
EXPLOIT_TYPES = {"SQL Injection", "XSS Attack", "Brute Force"}
RECON_TYPES = {"Port Scan", "Web Scan"}

NEXT_STEPS = {
    "SQL Injection": "Review web server and database logs for the targeted endpoint; confirm no data was returned or modified.",
    "XSS Attack": "Check whether the injected script was stored or reflected; validate output encoding on the affected page.",
    "Brute Force": "Check whether any login succeeded from this IP; enforce rate limiting / account lockout and rotate exposed passwords.",
    "Port Scan": "Verify which scanned ports are actually open and whether those services are expected to be exposed.",
    "High Traffic": "Check service availability and bandwidth graphs; apply rate limiting if the flood continues.",
    "Web Scan": "Review which probed paths returned 200; make sure admin panels, backups and .env/.git files are not exposed.",
}

VALID_VERDICTS = {"true_positive", "likely_false_positive", "needs_review"}
VALID_ACTIONS = {"block_ip", "monitor", "no_action"}

SYSTEM_PROMPT = """You are Pilot, the Tier-1 SOC triage analyst inside IncidentPilot, an intrusion
detection system for a small network. You receive ONE incident: a group of alerts from the same
source IP, plus context and the history of analyst decisions on similar incidents.

Your job: decide how urgent it is, whether it is real, and what the analyst should do next.

Rules:
- Use ONLY the data provided. Never invent alerts, IPs, ports, payloads or outcomes.
- Every evidence item MUST start with the alert id it comes from, e.g. "alert #14: UNION SELECT payload on port 80".
- Analyst feedback is ground truth. If analysts dismissed a very similar incident (same IP or same
  pattern) as a false positive, lower the priority and say so. If they confirmed one, treat repeats as more serious.
- A recon -> exploit sequence (e.g. port scan followed by SQL injection or brute force) is more serious than either alone.
- Priority: P1 = active exploitation / likely compromise, act now; P2 = clear attack attempt, act today;
  P3 = suspicious, monitor; P4 = noise / likely benign.
- recommended_action: "block_ip", "monitor" or "no_action".
- Keep the summary to 1-2 plain-English sentences a non-expert understands.

Return ONLY JSON with exactly these keys:
{"summary": str, "verdict": "true_positive"|"likely_false_positive"|"needs_review",
 "priority": "P1"|"P2"|"P3"|"P4", "confidence": number 0-1,
 "mitre": [{"id": str, "name": str}], "evidence": [str], "next_steps": [str],
 "recommended_action": "block_ip"|"monitor"|"no_action",
 "feedback_used": [incident ids you relied on], "reasoning": str}"""


# ---------------------------------------------------------------- context

def _fmt_time(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value, "strftime") else str(value)


def build_context(incident):
    alerts = db.get_incident_alerts(incident["id"])
    feedback = db.get_feedback_examples(
        incident["attack_type_list"], incident["source_ip"], exclude_id=incident["id"]
    )
    since = incident["first_seen"] - timedelta(days=7)
    history = [i for i in db.list_incidents(since=since, limit=50)
               if i["source_ip"] == incident["source_ip"] and i["id"] != incident["id"]]
    return {
        "incident": incident,
        "alerts": alerts,
        "feedback": feedback,
        "history": history,
        "whitelisted": db.is_ip_in_list(incident["source_ip"], "whitelist"),
        "blacklisted": db.is_ip_in_list(incident["source_ip"], "blacklist"),
        "already_blocked": db.is_ip_blocked(incident["source_ip"]),
    }


def context_to_prompt(ctx):
    inc = ctx["incident"]
    lines = [
        f"INCIDENT INC-{inc['id']}",
        f"Source IP: {inc['source_ip']}",
        f"Window: {_fmt_time(inc['first_seen'])} -> {_fmt_time(inc['last_seen'])}",
        f"Alert count: {inc['alert_count']}; attack types: {', '.join(inc['attack_type_list'])}",
        f"IP on whitelist: {ctx['whitelisted']}; on blacklist: {ctx['blacklisted']}; already blocked: {ctx['already_blocked']}",
        "",
        "ALERTS (oldest first):",
    ]
    for a in ctx["alerts"]:
        lines.append(
            f"- alert #{a['id']} | {_fmt_time(a['detected_at'])} | {a['attack_type']} | severity {a['severity']} | "
            f"target {a['target_ip']}:{a['target_port']} | status {a['status']} | {a['description']}"
        )

    lines += ["", "OTHER INCIDENTS FROM THIS IP (last 7 days):"]
    if ctx["history"]:
        for h in ctx["history"][:5]:
            lines.append(f"- INC-{h['id']}: {h['attack_types']} | priority {h.get('ai_priority')} | "
                         f"analyst: {h['analyst_status']} {h.get('analyst_verdict') or ''}")
    else:
        lines.append("- none")

    lines += ["", "ANALYST FEEDBACK ON SIMILAR PAST INCIDENTS (ground truth):"]
    if ctx["feedback"]:
        for f in ctx["feedback"]:
            lines.append(f"- INC-{f['id']} from {f['source_ip']} ({f['attack_types']}): analyst "
                         f"{f['analyst_status']} as {f.get('analyst_verdict')}. Notes: {f.get('analyst_notes') or '-'}")
    else:
        lines.append("- none")
    return "\n".join(lines)


# ---------------------------------------------------------------- offline engine

def heuristic_triage(ctx):
    inc = ctx["incident"]
    alerts = ctx["alerts"]
    types = inc["attack_type_list"]
    ip = inc["source_ip"]

    score = max((BASE_SCORE.get(t, 15) for t in types), default=15)
    multi_stage = bool(RECON_TYPES & set(types)) and bool(EXPLOIT_TYPES & set(types))
    if multi_stage:
        score += 20
    if len(types) > 1:
        score += 5
    score += min(inc["alert_count"] * 3, 15)
    threshold_hit = any(a["status"] in ("pending_approval", "blocked") for a in alerts)
    if threshold_hit:
        score += 10
    compromise = any("successful login" in (a["description"] or "").lower() for a in alerts)
    if compromise:
        score += 30

    verdict = "true_positive" if (EXPLOIT_TYPES & set(types)) or multi_stage or compromise else "needs_review"
    confidence = 0.6 + min(score, 90) / 300
    notes = []
    feedback_used = []

    same_ip_fp = [f for f in ctx["feedback"] if f["source_ip"] == ip and f["analyst_status"] == "dismissed"]
    same_ip_tp = [f for f in ctx["feedback"] if f["source_ip"] == ip and f["analyst_status"] == "approved"]
    pattern_fp = [f for f in ctx["feedback"]
                  if f["source_ip"] != ip and f["analyst_status"] == "dismissed"
                  and set(f["attack_type_list"]) == set(types)]

    if same_ip_fp:
        f = same_ip_fp[0]
        feedback_used.append(f["id"])
        verdict, score, confidence = "likely_false_positive", min(score, 20), 0.85
        notes.append(f"An analyst dismissed INC-{f['id']} from this same IP as a false positive "
                     f"(\"{f.get('analyst_notes') or 'no notes'}\").")
    elif same_ip_tp:
        f = same_ip_tp[0]
        feedback_used.append(f["id"])
        score += 15
        notes.append(f"Repeat offender: INC-{f['id']} from this IP was confirmed as a real attack.")
    elif pattern_fp:
        f = pattern_fp[0]
        feedback_used.append(f["id"])
        score -= 15
        verdict = "needs_review" if verdict == "true_positive" else verdict
        notes.append(f"A similar pattern (INC-{f['id']}) was previously dismissed as a false positive.")

    if ctx["whitelisted"]:
        verdict, score = "likely_false_positive", min(score, 20)
        notes.append("This IP is on the whitelist.")

    priority = "P1" if score >= 70 else "P2" if score >= 45 else "P3" if score >= 25 else "P4"

    if verdict == "likely_false_positive":
        action = "no_action"
    elif priority in ("P1", "P2") and verdict == "true_positive" and not ctx["already_blocked"]:
        action = "block_ip"
    else:
        action = "monitor"

    readable = " then ".join(types) if multi_stage else ", ".join(types)
    summary = f"{ip} triggered {inc['alert_count']} alert(s): {readable}."
    if compromise:
        summary += " A login SUCCEEDED right after the failed attempts - treat the account as compromised."
    elif multi_stage:
        summary += " This looks like reconnaissance followed by an exploitation attempt."
    elif verdict == "likely_false_positive":
        summary += " This matches activity analysts previously marked as benign."
    if notes:
        summary += " " + notes[0]

    evidence = [f"alert #{a['id']}: {a['attack_type']} - {a['description']}" for a in alerts[-5:]]
    steps = []
    if action == "block_ip":
        steps.append(f"Approve the block for {ip}.")
    elif action == "no_action":
        steps.append("Dismiss as false positive (consider whitelisting if this is an authorized tool).")
    if compromise:
        steps.append("Reset the affected account's password, revoke its sessions and review everything it accessed.")
    steps += [NEXT_STEPS[t] for t in types if t in NEXT_STEPS]
    if multi_stage:
        steps.append("Search other hosts for alerts from the same IP to check for lateral movement.")

    return {
        "summary": summary,
        "verdict": verdict,
        "priority": priority,
        "confidence": round(min(confidence, 0.95), 2),
        "mitre": [MITRE[t] for t in types if t in MITRE],
        "evidence": evidence,
        "next_steps": steps[:5],
        "recommended_action": action,
        "feedback_used": feedback_used,
        "reasoning": f"Rule-based score {score}. " + " ".join(notes),
    }


# ---------------------------------------------------------------- main entry

def normalize(result, ctx):
    fallback = heuristic_triage(ctx)
    out = {}
    out["summary"] = str(result.get("summary") or fallback["summary"])[:1000]
    out["verdict"] = result.get("verdict") if result.get("verdict") in VALID_VERDICTS else fallback["verdict"]
    priority = str(result.get("priority") or "").upper()
    out["priority"] = priority if priority in ("P1", "P2", "P3", "P4") else fallback["priority"]
    try:
        out["confidence"] = max(0.0, min(1.0, float(result.get("confidence"))))
    except (TypeError, ValueError):
        out["confidence"] = fallback["confidence"]

    mitre = []
    for item in result.get("mitre") or []:
        if isinstance(item, dict) and item.get("id"):
            mitre.append({"id": str(item["id"]), "name": str(item.get("name", ""))})
        elif isinstance(item, str):
            mitre.append({"id": item, "name": ""})
    out["mitre"] = mitre or fallback["mitre"]

    out["evidence"] = [str(e) for e in (result.get("evidence") or [])][:8] or fallback["evidence"]
    out["next_steps"] = [str(s) for s in (result.get("next_steps") or [])][:6] or fallback["next_steps"]
    action = result.get("recommended_action")
    out["recommended_action"] = action if action in VALID_ACTIONS else fallback["recommended_action"]
    used = []
    for value in result.get("feedback_used") or []:
        try:
            used.append(int(str(value).replace("INC-", "")))
        except ValueError:
            pass
    out["feedback_used"] = used
    out["reasoning"] = str(result.get("reasoning") or "")[:1500]
    return out


def triage_incident(incident_id):
    incident = db.get_incident(incident_id)
    if not incident:
        return None

    ctx = build_context(incident)
    engine = "Pilot offline engine"

    if llm.is_enabled():
        try:
            raw = llm.complete_json(SYSTEM_PROMPT, context_to_prompt(ctx))
            result = normalize(raw, ctx)
            engine = llm.engine_name()
        except Exception as error:
            print(f"[TRIAGE] LLM failed for INC-{incident_id}, using offline engine: {error}")
            result = heuristic_triage(ctx)
            engine = "Pilot offline engine (LLM unavailable)"
    else:
        result = heuristic_triage(ctx)

    db.save_triage(incident_id, result, engine)
    print(f"[TRIAGE] INC-{incident_id} -> {result['priority']} {result['verdict']} ({engine})")

    if result["priority"] == "P1" and incident["analyst_status"] == "new" and not incident.get("notified_at"):
        try:
            from notifications import notify_critical
            notify_critical(incident_id)
        except Exception as error:
            print("[NOTIFY] failed:", error)
    return result


def run_pending_triage(limit=10):
    done = 0
    for incident in db.incidents_needing_triage(limit):
        try:
            triage_incident(incident["id"])
            done += 1
        except Exception as error:
            print(f"[TRIAGE] error on INC-{incident['id']}: {error}")
            db.mark_triage_error(incident["id"], str(error)[:200])
    return done


def triage_as_json(incident):
    """Compact triage view used by chat / briefing / report prompts."""
    return json.dumps({
        "id": f"INC-{incident['id']}", "source_ip": incident["source_ip"],
        "attack_types": incident["attack_type_list"], "alerts": incident["alert_count"],
        "first_seen": _fmt_time(incident["first_seen"]), "last_seen": _fmt_time(incident["last_seen"]),
        "priority": incident.get("ai_priority"), "verdict": incident.get("ai_verdict"),
        "confidence": incident.get("ai_confidence"), "summary": incident.get("ai_summary"),
        "recommended_action": incident.get("ai_recommended_action"),
        "next_steps": incident.get("ai_next_steps"),
        "mitre": [m.get("id") if isinstance(m, dict) else m for m in incident.get("ai_mitre") or []],
        "analyst_status": incident["analyst_status"], "analyst_notes": incident.get("analyst_notes"),
    })
