"""Daily AI briefing shown at the top of the dashboard."""
import time
from datetime import datetime

import db
from ai import llm
from ai.triage import triage_as_json

_cache = {"key": None, "value": None, "at": 0}
CACHE_SECONDS = 60


def briefing_facts(since=None):
    since = since or datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    incidents = db.list_incidents(since=since, limit=300)
    by_priority = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for inc in incidents:
        if inc.get("ai_priority") in by_priority:
            by_priority[inc["ai_priority"]] += 1

    open_incidents = [i for i in incidents if i["analyst_status"] == "new"]
    top = incidents[0] if incidents else None  # list is sorted: open first, then priority
    attackers = {}
    for inc in incidents:
        attackers[inc["source_ip"]] = attackers.get(inc["source_ip"], 0) + inc["alert_count"]
    top_attacker = max(attackers.items(), key=lambda kv: kv[1]) if attackers else None

    return {
        "since": since,
        "total": len(incidents),
        "open": len(open_incidents),
        "awaiting_approval": sum(1 for i in open_incidents if i.get("ai_recommended_action") == "block_ip"),
        "dismissed": sum(1 for i in incidents if i["analyst_status"] == "dismissed"),
        "approved": sum(1 for i in incidents if i["analyst_status"] == "approved"),
        "by_priority": by_priority,
        "alerts": sum(i["alert_count"] for i in incidents),
        "top_incident": top,
        "top_attacker": top_attacker,
        "incidents": incidents,
    }


def _offline_text(f):
    if f["total"] == 0:
        return "All quiet today. No incidents detected so far."
    p = f["by_priority"]
    parts = [f"{f['total']} incident(s) today from {f['alerts']} alert(s)"]
    critical = p["P1"] + p["P2"]
    parts.append(f"{critical} need attention (P1: {p['P1']}, P2: {p['P2']})")
    text = ", ".join(parts) + "."
    if f["top_attacker"]:
        text += f" Most active source: {f['top_attacker'][0]} ({f['top_attacker'][1]} alerts)."
    top = f["top_incident"]
    if top and top["analyst_status"] == "new" and top.get("ai_priority"):
        text += f" Start with INC-{top['id']} ({top['ai_priority']}): {top.get('ai_summary') or ''}"
    if f["awaiting_approval"]:
        text += f" {f['awaiting_approval']} block recommendation(s) are waiting for your approval."
    if f["dismissed"]:
        text += f" {f['dismissed']} false positive(s) dismissed."
    return text.strip()


def get_briefing(force=False):
    facts = briefing_facts()
    key = (facts["total"], facts["open"], facts["alerts"], tuple(facts["by_priority"].values()))
    if not force and _cache["key"] == key and time.time() - _cache["at"] < CACHE_SECONDS:
        return _cache["value"]

    text, engine = _offline_text(facts), "Pilot offline engine"
    if llm.is_enabled() and facts["total"]:
        try:
            incident_lines = "\n".join(triage_as_json(i) for i in facts["incidents"][:15])
            text = llm.complete(
                "You are Pilot, a SOC assistant. Write today's security briefing for the analyst in "
                "at most 3 short sentences: overall picture, the single most urgent incident (cite it "
                "as INC-<id>) and what to do first. Use only the data given. No markdown headings.",
                f"Counts: {facts['total']} incidents, {facts['alerts']} alerts, open {facts['open']}, "
                f"by priority {facts['by_priority']}, awaiting block approval {facts['awaiting_approval']}, "
                f"dismissed {facts['dismissed']}.\nIncidents:\n{incident_lines}",
                temperature=0.3,
            )
            engine = llm.engine_name()
        except Exception as error:
            print("[BRIEFING] LLM failed, using offline text:", error)

    value = {
        "text": text,
        "engine": engine,
        "total": facts["total"],
        "open": facts["open"],
        "alerts": facts["alerts"],
        "by_priority": facts["by_priority"],
        "awaiting_approval": facts["awaiting_approval"],
        "top_attacker": facts["top_attacker"][0] if facts["top_attacker"] else None,
        "top_incident_id": facts["top_incident"]["id"] if facts["top_incident"] else None,
        "generated_at": datetime.now().strftime("%H:%M"),
    }
    _cache.update(key=key, value=value, at=time.time())
    return value
