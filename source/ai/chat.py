"""
"Ask Pilot" - the floating assistant. Answers questions from the real database.

Agents (same brain, different focus):
  triage   -> explain / prioritise / false-positive checks (default)
  report   -> write an incident report
  briefing -> summarise the day

Returns {"answer": markdown, "actions": [...], "engine": str}
Actions are buttons the widget renders (approve / dismiss / open / report).
"""
import re
from datetime import datetime, timedelta

import db
from ai import llm
from ai.briefing import get_briefing
from ai.report import build_report_markdown
from ai.triage import triage_as_json

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
INC_RE = re.compile(r"\b(?:inc[-\s#]?|incident\s*#?)(\d+)\b", re.I)

SYSTEM_PROMPT = """You are Pilot, the AI assistant inside IncidentPilot, a security incident triage
dashboard. You help a security analyst understand alerts and decide what to do.

Rules:
- Answer ONLY from the CONTEXT below (live data from the IDS database). If the answer is not
  there, say you don't see it in the data. Never invent IPs, alerts or incidents.
- Cite sources inline like [INC-12] or [alert #45].
- Be concise: max ~120 words unless asked for a report. Use short bullets when listing.
- Blocking or unblocking is the analyst's decision: recommend, never claim you did it.
- Plain English; explain jargon briefly if you use it."""


def _t(value):
    return value.strftime("%H:%M:%S") if hasattr(value, "strftime") else str(value)


def _incident_actions(inc):
    if not inc:
        return []
    actions = [{"type": "open", "incident_id": inc["id"], "label": f"Open INC-{inc['id']}"}]
    if inc["analyst_status"] == "new":
        if inc.get("ai_recommended_action") == "block_ip":
            actions.append({"type": "approve", "incident_id": inc["id"], "label": f"Approve & block {inc['source_ip']}"})
        else:
            actions.append({"type": "approve", "incident_id": inc["id"], "label": "Confirm as real"})
        actions.append({"type": "dismiss", "incident_id": inc["id"], "label": "Dismiss as false positive"})
    actions.append({"type": "report", "incident_id": inc["id"], "label": "Report"})
    return actions


def _find_incident(message, incident_id, incidents):
    match = INC_RE.search(message)
    if match:
        return db.get_incident(int(match.group(1)))
    ip_match = IP_RE.search(message)
    if ip_match:
        for inc in incidents:  # sorted: open first, then priority
            if inc["source_ip"] == ip_match.group(0):
                return inc
        return None
    if incident_id:
        return db.get_incident(int(incident_id))
    return None


def _build_context(incidents, focus, page):
    now = datetime.now()
    recent_alerts = db.get_alerts_since(now - timedelta(hours=1), limit=40)
    blocked = db.get_blocked_ips(20)
    whitelist = db.get_ip_list("whitelist")
    lines = [
        f"Current time: {now.strftime('%Y-%m-%d %H:%M:%S')}. Analyst is on page: {page or 'dashboard'}.",
        "",
        "INCIDENTS (last 24h, most urgent first):",
    ]
    lines += [triage_as_json(i) for i in incidents[:25]] or ["none"]
    if focus:
        lines += ["", f"FOCUSED INCIDENT INC-{focus['id']} ALERTS:"]
        for a in db.get_incident_alerts(focus["id"]):
            lines.append(f"alert #{a['id']} {_t(a['detected_at'])} {a['attack_type']} {a['severity']} "
                         f"port {a['target_port']} status {a['status']}: {a['description']}")
        lines.append(f"AI reasoning: {focus.get('ai_summary')}")
    lines += ["", "ALERTS IN THE LAST HOUR:"]
    lines += [f"alert #{a['id']} {_t(a['detected_at'])} {a['attack_type']} from {a['source_ip']} "
              f"({a['severity']}, {a['status']}) INC-{a['incident_id']}" for a in recent_alerts] or ["none"]
    lines += ["", "BLOCKED IPS: " + (", ".join(f"{b[1]} ({b[2]})" for b in blocked) or "none")]
    lines += ["WHITELIST: " + (", ".join(f"{w[1]} ({w[3]})" for w in whitelist) or "none")]
    return "\n".join(lines)


# ---------------------------------------------------------------- offline answers

def _describe(inc):
    if not inc.get("ai_priority"):
        return f"[INC-{inc['id']}] from {inc['source_ip']} has not been triaged yet."
    verdict = (inc.get("ai_verdict") or "").replace("_", " ")
    text = (f"**[INC-{inc['id']}] {inc['ai_priority']} - {verdict}** "
            f"({round((inc.get('ai_confidence') or 0) * 100)}% confidence)\n\n{inc.get('ai_summary')}")
    if inc.get("ai_evidence"):
        text += "\n\n**Evidence**\n" + "\n".join(f"- {e}" for e in inc["ai_evidence"][:3])
    return text


def _has(text, words):
    return any(re.search(r"\b" + re.escape(w) + r"\b", text) for w in words)


def _offline_answer(message, agent, focus, incidents):
    q = message.lower()
    explicit = bool(INC_RE.search(message) or IP_RE.search(message))

    if agent == "report" or "report" in q:
        if not focus:
            return "Open an incident (or mention one, e.g. `INC-3`) and I'll write its report.", None
        return build_report_markdown(focus["id"]), focus

    if agent == "briefing" or (not explicit and _has(q, ("brief", "today", "summary", "summarise", "summarize", "overview"))):
        b = get_briefing()
        return f"**Today's briefing**\n\n{b['text']}", db.get_incident(b["top_incident_id"]) if b["top_incident_id"] else None

    if not explicit and _has(q, ("threshold", "thresholds", "noisy", "tune", "tuning")):
        from ai.tuning import suggestions_markdown
        return suggestions_markdown(), None

    if not explicit and _has(q, ("last hour", "what happened", "recent", "right now", "latest", "patterns", "pattern")):
        alerts = db.get_alerts_since(datetime.now() - timedelta(hours=1), limit=200)
        if not alerts:
            return "No alerts in the last hour.", None
        by_ip = {}
        for a in alerts:
            by_ip.setdefault(a["source_ip"], []).append(a)
        lines = [f"**{len(alerts)} alert(s) in the last hour from {len(by_ip)} source(s):**"]
        for ip, items in sorted(by_ip.items(), key=lambda kv: -len(kv[1])):
            types = sorted({a["attack_type"] for a in items})
            lines.append(f"- `{ip}`: {len(items)} alert(s) - {', '.join(types)} [INC-{items[0]['incident_id']}]")
        return "\n".join(lines), None

    if not explicit and _has(q, ("most dangerous", "dangerous", "worst", "top", "urgent", "first", "riskiest")):
        open_inc = [i for i in incidents if i["analyst_status"] == "new" and i.get("ai_priority")]
        if not open_inc:
            return "No open triaged incidents right now. Nice.", None
        top = open_inc[0]
        rest = "\n".join(f"- [INC-{i['id']}] {i['ai_priority']} `{i['source_ip']}` - {', '.join(i['attack_type_list'])}"
                         for i in open_inc[1:4])
        answer = f"Start here:\n\n{_describe(top)}"
        if rest:
            answer += f"\n\n**Next in queue**\n{rest}"
        return answer, top

    if focus is None and IP_RE.search(message):
        return f"I don't see any incident for `{IP_RE.search(message).group(0)}` in the last 24 hours.", None

    if _has(q, ("false positive", "benign", "legit", "real attack", "real", "fp")):
        if not focus:
            return "Which incident? Open one or mention it like `INC-3`.", None
        verdict = focus.get("ai_verdict")
        intro = {"likely_false_positive": "Probably **not** a real attack.",
                 "true_positive": "This looks like a **real attack**.",
                 "needs_review": "**Unclear** - it needs a human look."}.get(verdict, "")
        return f"{intro}\n\n{_describe(focus)}", focus

    if _has(q, ("what should", "next", "do now", "recommend", "steps", "fix")):
        if not focus:
            return "Open an incident or mention one (e.g. `INC-3`) and I'll list the next steps.", None
        steps = "\n".join(f"{n}. {s}" for n, s in enumerate(focus.get("ai_next_steps") or [], 1))
        return f"**Next steps for [INC-{focus['id']}]**\n\n{steps or 'Monitor this source.'}", focus

    if _has(q, ("unblock", "safe to")):
        ip = IP_RE.search(message)
        if not ip:
            return "Which IP do you want to check?", None
        related = [i for i in incidents if i["source_ip"] == ip.group(0)]
        if not related:
            return f"No incidents for `{ip.group(0)}` in the last 24h - unblocking looks low-risk.", None
        worst = related[0]
        return (f"`{ip.group(0)}` is linked to {len(related)} incident(s). Most serious:\n\n{_describe(worst)}\n\n"
                f"I'd keep it blocked unless you know this host."), worst

    if focus:
        return _describe(focus), focus

    return ("I can help with:\n- *What happened in the last hour?*\n- *Which IP is most dangerous?*\n"
            "- *Why is 192.168.56.10 P1?*\n- *Is INC-3 a false positive?*\n- *Brief me on today*\n"
            "- *Write a report for INC-3*"), None


# ---------------------------------------------------------------- entry

def answer(message, page=None, incident_id=None, agent="triage"):
    message = (message or "").strip()[:1000]
    if not message:
        return {"answer": "Ask me anything about your incidents.", "actions": [], "engine": llm.engine_name()}

    incidents = db.list_incidents(since=datetime.now() - timedelta(hours=24), limit=100)
    focus = _find_incident(message, incident_id, incidents)

    # Reports always use the fact-safe report builder.
    if agent == "report" or ("report" in message.lower() and focus):
        if not focus:
            open_inc = [i for i in incidents if i["analyst_status"] == "new" and i.get("ai_priority")]
            focus = open_inc[0] if open_inc else (incidents[0] if incidents else None)
        text, target = _offline_answer(message, "report", focus, incidents)
        return {"answer": text, "actions": _incident_actions(target), "engine": llm.engine_name()}

    if llm.is_enabled():
        try:
            focus_hint = {"briefing": "Focus: give a short briefing of the day.",
                          "triage": "Focus: triage - urgency, real vs false positive, next action."}.get(agent, "")
            text = llm.complete(
                SYSTEM_PROMPT + "\n" + focus_hint,
                f"CONTEXT:\n{_build_context(incidents, focus, page)}\n\nANALYST QUESTION: {message}",
                temperature=0.2,
            )
            target = focus
            if not target:
                ids = [int(x) for x in re.findall(r"INC-(\d+)", text)]
                target = db.get_incident(ids[0]) if ids else None
            return {"answer": text, "actions": _incident_actions(target), "engine": llm.engine_name()}
        except Exception as error:
            print("[CHAT] LLM failed, using offline engine:", error)

    text, target = _offline_answer(message, agent, focus, incidents)
    return {"answer": text, "actions": _incident_actions(target), "engine": "Pilot offline engine"}
