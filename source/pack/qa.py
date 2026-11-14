"""
Question answering over the Problem C data pack.

Two engines, same contract (markdown answer, every claim cited, evidence labels):
  * LLM (Gemini / OpenAI-compatible) - gets the 20 files with line numbers plus the
    deterministic analysis as a worksheet, and must cite [file:line] / [file#ID].
  * Offline engine - routes the question (severity, who to inform, approved changes,
    missing logs, entity look-ups, time conversion ...) to the deterministic analysis.
Every answer is post-checked: each citation is verified against the files.
"""
import re
from datetime import datetime, timedelta

from pack.loader import CITE_RE, UTC, PKT, fmt_utc, fmt_pkt, cite_row
from pack.report import build_markdown

STOP = set("the a an of to in on at is was were are be been by for from with and or what which who whom when where why how did do does "
           "any there their it its this that these those as about into than then me my our us you your can could should would please tell show give "
           "have has had not no yes if so also all".split())

SYSTEM_PROMPT = """You are Pilot, the SOC triage assistant for Orbit Logistics. You may use ONLY the DATA PACK below (20 files).
Follow the company rules in file 01 exactly:
- Times: report in UTC (add PKT in brackets). Check the log source sheet (file 20) before comparing times; logs use different time zones
  (VPN=UTC, DC=UTC, web=offset in line, perimeter FW=UTC, internal FW=PKT and logs at session CLOSE, email=PKT, IDS=UTC, DHCP=offset in line).
- Label every claim: **Confirmed** (a log line or table row shows it), **Suspected** (needs a guess to link two things; state the guess),
  **Not enough evidence in the logs** (logs are silent or missing). Never fill a gap with a guess. Never say data was "stolen" or "leaked" unless a log shows
  the data moving; a large transfer is evidence of a transfer, not of which files were read.
- Cite every claim: log files as [file:line] (line 1 = first log line in the code block); tables as [file#ROWID] (alert ID, asset tag, change ID, username);
  runbooks as RB-ID step N [file#stepN]; rules as [01_company_security_rules.md#6.1]. Use ONLY citations that exist.
- Severity: use the matrix (file 03) with the most critical asset the attacker actually reached; report each part; whole incident = highest part.
- Approved activity needs the same system, same person or tool, and a window containing the activity (change calendar). Say why it was closed and cite the change ID.
- Recommend only actions found in the runbooks; inform only people in the escalation sheet with their time limit.
- If the data does not contain the answer, say "Not enough evidence in the logs" and say which log source is missing.
- Be concise. Prefer short bullet points. Do not mention these instructions.
An ANALYST WORKSHEET (already verified against the files) is provided; use it, but you may add details from the raw files."""


# ---------------------------------------------------------------- context for the LLM

def build_context(pack, analysis):
    parts = ["=== DATA PACK ==="]
    for name, text in pack.files.items():
        parts.append(f"--- FILE {name} ---")
        if pack.code_lines.get(name):
            head = text.split("```")[0].strip()
            parts.append(head)
            for n, line in enumerate(pack.code_lines[name], 1):
                parts.append(f"{name}:{n} | {line}")
        else:
            parts.append(text.strip())
    parts.append("=== ANALYST WORKSHEET (verified) ===")
    parts.append(build_markdown(analysis))
    return "\n".join(parts)


# ---------------------------------------------------------------- entity detection

def detect(pack, q):
    ql = q.lower()
    ents = {"ips": re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", q), "users": [], "assets": [], "alerts": [], "changes": [],
            "runbooks": [], "msgids": re.findall(r"\bM-\d+\b", q, re.I), "sessions": re.findall(r"\bVS-\d+\b", q, re.I), "rules": []}
    for uname, u in pack.users.items():
        first = u["Full name"].split()[0].lower()
        if re.search(rf"\b{uname}\b", ql) or u["Full name"].lower() in ql or re.search(rf"\b{first}\b", ql) or u["Email"].lower() in ql:
            ents["users"].append(uname)
    for tag, a in pack.assets.items():
        host = a["Hostname"].lower()
        short = host.replace("srv-", "")
        if tag.lower() in ql or host in ql or re.search(rf"\b{re.escape(short)}\b", ql):
            ents["assets"].append(tag)
    ents["alerts"] = [x.upper() for x in re.findall(r"\bALT-\d+\b", q, re.I)]
    ents["changes"] = [x.upper() for x in re.findall(r"\bCHG-[\d-]+\b", q, re.I)]
    ents["runbooks"] = [x.upper() for x in re.findall(r"\bRB-[A-Z]+-\d+\b", q, re.I)]
    ents["rules"] = re.findall(r"\brule\s+(\d+\.\d+)", ql)
    return ents


def has_entity(ents):
    return any(ents[k] for k in ents)


PACK_WORDS = ("orbit", "vpn", "firewall", "dhcp", "kerberos", "phish", "sqli", "sql injection", "exfil", "runbook", "change calendar",
              "severity matrix", "escalat", "who must be informed", "who should be informed", "file server", "log source", "change calendar", "approved change", "coverage", "pkt", "utc", "time zone", "nessus", "scan01",
              "fs01", "db01", "dc01", "web01", "mfa", "ids alert", "domain controller")


def matches(pack, q):
    ql = (q or "").lower()
    return has_entity(detect(pack, q)) or any(w in ql for w in PACK_WORDS)


# ---------------------------------------------------------------- helpers

def _ev_line(e):
    t = e["start"] if e["src"] == "fw_int" else e["ts"]
    desc = e.get("desc") if e["src"] == "ids" else e["raw"]
    return f"- {fmt_utc(t)} ({fmt_pkt(t)}) - {desc[:200]} {e['cite']}"


def _inc_for(analysis, ents):
    keys = {k.lower() for k in ents["ips"] + ents["users"] + ents["msgids"] + ents["sessions"]}
    out = []
    for i in analysis.incidents:
        ids = {str(x).lower() for x in i.get("related_ids", [])}
        if ids & keys:
            out.append(i)
    for tag in ents["assets"]:
        for i in analysis.incidents:
            if any(a["asset"]["Asset tag"] == tag and a["reached"] for a in i["assets"]) and i not in out:
                out.append(i)
    return out


def _items(title, items, guess=False):
    lines = [f"**{title}**"]
    for it in items:
        s = f"- {it['text']} {' '.join(it['cites'])}"
        if guess and it.get("guess"):
            s += f" *Guess needed: {it['guess']}.*"
        lines.append(s)
    return "\n".join(lines)


def _dedupe_people(people):
    out, seen = [], {}
    for pe in people:
        key = (pe["severity"], pe["who"])
        if key in seen:
            seen[key]["for"] += "; " + pe["for"]
            continue
        pe = dict(pe)
        seen[key] = pe
        out.append(pe)
    return out


def _people(incs):
    lines = ["**People to inform** (the time limit starts when the SOC first sees the incident):"]
    for i in incs:
        lines.append(f"- *{i['id']} - {i['title']} ({i['severity']})*")
        for pe in _dedupe_people(i["people"]):
            extra = " - only if finance, HR or customer data may be involved (FS01 holds finance and HR shares)" if pe["who"].startswith("Legal") else ""
            lines.append(f"  - {pe['who']} within **{pe['limit']}** ({pe['how']}){extra} {pe['cite']}")
    return "\n".join(lines)


def _severity(pack, incs):
    lines = []
    for i in incs:
        lines.append(f"**{i['id']} - {i['title']}: overall {i['severity']}**")
        for part in sorted(i["parts"], key=lambda x: x["severity"]):
            lines.append(f"- {part['severity']}: {part['name']}")
            for n, st in enumerate(part["steps"], 1):
                lines.append(f"  {n}. {st}")
    return "\n".join(lines)


def _actions(incs):
    lines = []
    for i in incs:
        lines.append(f"**Recommended actions - {i['id']} ({i['severity']})**")
        for a in i["actions"]:
            note = f" - {a['note']}" if a.get("note") else ""
            lines.append(f"- {a['cite']}: {a['text']}{note}")
    return "\n".join(lines)


def _timeline(incs, limit=60):
    lines = []
    for i in incs:
        lines.append(f"**Timeline {i['id']} - {i['title']}** (UTC, PKT in brackets)")
        for t in sorted(i["timeline"], key=lambda x: x["ts"])[:limit]:
            lines.append(f"- {t['utc']} ({t['pkt']}) - {t['text']} {' '.join(t['cites'])}")
    return "\n".join(lines)


def _closed(analysis, ents=None):
    out = []
    analysis_file17, analysis_file05 = analysis.p.file("17"), analysis.p.file("05")
    for c in analysis.closed:
        if ents and (ents["changes"] or ents["alerts"] or ents["ips"] or ents["users"]):
            blob = (c["title"] + c["change_id"] + str(c["alert"]) + " ".join(c["cites"])).lower()
            keys = [k.lower() for k in ents["changes"] + ents["alerts"] + ents["ips"] + ents["users"]]
            if not any(k in blob for k in keys):
                continue
        out.append(f"**{c['id']} - {c['title']} - closed as approved activity, {c['change_id']}** ({c['status']})")
        out += [f"- {r}" for r in c["reasons"]]
        out.append(f"- {c['detail']}")
        out.append(f"- {c['rule']}")
        out.append(f"- Alert {c['alert']}: {cite_row(analysis_file17, c['alert'])} and {cite_row(analysis_file05, c['change_id'])}")
    return "\n".join(out)


def _missing(analysis):
    seen, lines = set(), ["**Missing log sources and blind spots**"]
    for i in analysis.incidents:
        for m in i["missing"]:
            if m["source"] not in seen:
                seen.add(m["source"])
                lines.append(f"- {m['source']}: {m['impact']} {m['cite']}")
    for name, row in analysis.p.coverage_rows.items():
        if row["Notes"]:
            lines.append(f"- Note for {name}: {row['Notes']} {cite_row(analysis.p.file('20'), name)}")
    return "\n".join(lines)


def _timezones(pack):
    lines = ["**Time zone of each source** (file 20) - all times in this system are converted to UTC:"]
    for name, row in pack.coverage_rows.items():
        lines.append(f"- {name}: {row['Time zone / format']} {cite_row(pack.file('20'), name)}"
                     + (f" - {row['Notes']}" if row["Notes"] else ""))
    lines.append(f"- Company local time is PKT = UTC+5, no daylight saving {cite_row(pack.file('01'), '1.1')}. Example: 11:21:19 PKT = 06:21:19 UTC.")
    return "\n".join(lines)


def _search(pack, words, limit=14):
    hits = []
    for e in pack.events:
        blob = (e["raw"] + " " + " ".join(str(v) for k, v in e.items() if k in ("alert_id", "desc"))).lower()
        score = sum(1 for w in words if w in blob)
        if score:
            hits.append((score, e))
    hits.sort(key=lambda x: (-x[0], x[1]["ts"]))
    top = [e for s, e in hits[:limit]]
    top.sort(key=lambda e: e["ts"])
    return top


def _entity_answer(pack, analysis, ents, src_filter=None):
    lines = []
    for ip in ents["ips"]:
        a = pack.asset_by_ip(ip)
        evs = [e for e in pack.events if re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d])", e["raw"] + " " + str(e.get("desc", "")))]
        lines.append(f"**{ip}**" + (f" = {a['Hostname']} ({a['Asset tag']}), {a['Type']}, criticality {a['Criticality']} {cite_row(pack.file('02'), a['Asset tag'])}" if a else
                                    " is not an Orbit asset in the inventory (external address or VPN pool address)" if not ip.startswith("10.") else " is not listed in the asset inventory"))
        if ip.startswith("10.10.3."):
            v = [e for e in pack.events if e.get("assigned_ip") == ip]
            for e in v:
                lines.append(f"- VPN pool address: assigned to {e['user']} (session {e['session']}) from {e['src_ip']} (geo {e['geo']}) {e['cite']}")
        if ip.startswith("10.20."):
            d = [e for e in pack.events if e["src"] == "dhcp" and e.get("ip") == ip]
            for e in d:
                lines.append(f"- DHCP: leased to {e['hostname']} at {fmt_utc(e['ts'])} for {e['lease']} {e['cite']}")
        for i in analysis.incidents:
            if ip in [str(x) for x in i.get("related_ids", [])]:
                lines.append(f"Part of **{i['id']} ({i['severity']})**: {i['summary']}")
        for c in analysis.closed:
            if ip in c["title"]:
                lines.append(f"Closed as approved activity **{c['change_id']}**: {c['title']}")
        lines.append(f"{len(evs)} log lines mention it (UTC):")
        lines += [_ev_line(e) for e in evs[:18]]
    for uname in ents["users"]:
        u = pack.users[uname]
        lap = pack.assets.get(u["Laptop tag"])
        lines.append(f"**{u['Full name']} ({uname})** - {u['Role']}, laptop {lap['Hostname']} {lap['ips'][0]}, manager {u['Manager']}, registered phone {u['Registered phone']} {cite_row(pack.file('18'), uname)}")
        evs = [e for e in pack.events if re.search(rf"\b{uname}\b", e["raw"], re.I) or (e["src"] == "email" and e.get("to", "").startswith(uname))]
        if src_filter:
            evs = [e for e in evs if e["src"] == src_filter] or evs
        lines += [_ev_line(e) for e in evs[:20]]
        inc = [i for i in analysis.incidents if any(c["user"]["Username"] == uname for c in i.get("compromised", []))]
        for i in inc:
            lines.append(f"{uname} is part of {i['id']} ({i['severity']}): {i['summary']}")
        for i in analysis.incidents:
            for part in i["parts"]:
                if part.get("user") == uname and part["type"].startswith("Phishing"):
                    lines.append(f"{uname}: {part['name']} -> {part['severity']} ({i['id']})")
    for tag in ents["assets"]:
        a = pack.assets[tag]
        lines.append(f"**{a['Hostname']} ({tag})** - {a['Type']}, {a['IP address']}, owner {a['Owner']}, criticality **{a['Criticality']}** {cite_row(pack.file('02'), tag)}")
        for i in analysis.incidents:
            for x in i["assets"]:
                if x["asset"]["Asset tag"] == tag:
                    lines.append(f"- {i['id']} ({i['severity']}): {'reached' if x['reached'] else 'not reached'} - {x['why']}")
    for aid in ents["alerts"]:
        row = pack.ids_alerts.get(aid)
        if not row:
            lines.append(f"**{aid}**: Not enough evidence in the logs - no such alert in the IDS summary {cite_row(pack.file('17'), 'ALT-9001')[:0]}")
            continue
        lines.append(f"**{aid}** ({row['Sensor']}, raised {row['Time raised']}): {row['Description']} {cite_row(pack.file('17'), aid)}")
        for i in analysis.incidents:
            if any(aid in c for t in i["timeline"] for c in t["cites"]):
                lines.append(f"- Part of {i['id']} ({i['severity']}): {i['title']}")
        for c in analysis.closed:
            if c["alert"] == aid:
                lines.append(f"- Closed as approved activity under {c['change_id']}: " + c["reasons"][2])
    for cid in ents["changes"]:
        ch = pack.changes.get(cid)
        if not ch:
            lines.append(f"**{cid}**: Not enough evidence - no such change in the calendar.")
            continue
        used = [c for c in analysis.closed if c["change_id"] == cid]
        lines.append(f"**{cid}** - {ch['Date']} {ch['Window (PKT)']} PKT, {ch['System / target']}, by {ch['Performed by']}: {ch['Description']} ({ch['Status']}) {cite_row(pack.file('05'), cid)}")
        lines.append("- Used to close: " + (used[0]["title"] if used else "no alert in the logs matches it (system, person/tool and window do not all match)"))
        if ch["Status"].lower().startswith("postponed"):
            lines.append("- Postponed, not performed: it cannot approve any activity.")
    for sid in ents["sessions"]:
        evs = [e for e in pack.events if sid.upper() in e["raw"].upper()]
        lines.append(f"**{sid.upper()}**")
        lines += [_ev_line(e) for e in evs]
    for mid in ents["msgids"]:
        evs = [e for e in pack.events if mid.upper() in e["raw"].upper()]
        lines.append(f"**{mid.upper()}**: delivered to {', '.join(e['to'] for e in evs)} (score {evs[0].get('score')}, action {evs[0].get('action')})" if evs else f"{mid}: Not enough evidence")
        lines += [_ev_line(e) for e in evs]
    for rb in ents["runbooks"]:
        r = pack.runbooks.get(rb)
        if r:
            lines.append(f"**{rb} - {r['title']}**")
            lines += [f"- step {n}: {t} [{r['file']}#step{n}]" for n, t in r["steps"].items()]
    for rid in ents["rules"]:
        if rid in pack.rules:
            lines.append(f"**Rule {rid}**: {pack.rules[rid]} {cite_row(pack.file('01'), rid)}")
    return "\n".join(lines)


# ---------------------------------------------------------------- offline router

TOPICS = {
    "web": ("sql injection", "sqli", "sqlmap", "web attack", "union select", "web application", "owasp"),
    "phish": ("phish", "payroll", "credential", "account takeover", "compromise", "exfil", "transfer", "stolen", "leaked", "vpn", "mfa",
              "password", "lockout", "smb", "2.4", "gb"),
    "scan": ("port scan", "recon", "probing", "probe", "unapproved scan", "192.0.2.88"),
}
SRC_WORDS = {"vpn": ("vpn",), "fw_edge": ("perimeter",), "fw_int": ("internal firewall",), "dc": ("domain controller", "kerberos", "windows"),
             "email": ("email", "e-mail", "mail gateway", "mailbox"), "web": ("web server", "web log", "access log"),
             "dhcp": ("dhcp", "lease"), "ids": ("ids",)}


def _topic_incidents(analysis, ql):
    out = []
    for topic, words in TOPICS.items():
        if any(w in ql for w in words):
            out += [i for i in analysis.incidents if i["kind"] == topic and i not in out]
    return out


def _filter_missing(text, ql):
    lines = text.splitlines()
    alias = {"database": "db01", "dc": "domain controller", "dates": "other than"}
    keys = [w for w in ("internal firewall", "perimeter", "domain controller", "proxy", "edr", "db01", "database", "fs01", "audit", "dates", "email", "web server") if w in ql]
    keep = [lines[0]] + [l for l in lines[1:] if any(alias.get(k, k) in l.lower() for k in keys)]
    return "\n".join(keep) if len(keep) > 1 and keys else text


def offline_answer(pack, analysis, question):
    ql = question.lower()
    ents = detect(pack, question)
    topic = _topic_incidents(analysis, ql)
    by_entity = _inc_for(analysis, ents)
    incs = by_entity or topic or analysis.incidents
    blocks = []

    def has(*w):
        return any(x in ql for x in w)

    if has("full report", "incident report", "write a report", "generate a report", "what happened", "overview", "executive summary") or ql.strip() in ("report", "summary"):
        return build_markdown(analysis)

    people = has("who must", "who should", "who to", "inform", "notify", "escalat", "contact", "whom", "time limit", "deadline", "call the", "ciso")
    severity = has("severity", "priority", "p1", "p2", "p3", "p4", "how serious", "how bad", "which row", "matrix")
    closed = has("approved", "change", "chg-", "harmless", "benign", "false positive", "closed", "maintenance", "patch", "planned", "legit", "authorised", "authorized")
    theft = has("stolen", "leaked", "steal", "leak", "exfil", "which files", "what files", "what data", "files were", "were files", "how much data", "large transfer", "gigabyte", " gb")
    missing = has("missing", "coverage", "blind", "gap", "not collected", "silent", "cannot tell", "unknown", "audit", "proxy", "edr", "reboot",
                  "not enough evidence", "no logs", "log source")
    actions = has("action", "recommend", "runbook", "step", "what should", "contain", "respond", "remediat", "do next", "isolate", "disable", "block")
    timeline = has("timeline", "sequence", "chronolog", "order of events")
    tz = has("time zone", "timezone", "convert", "local time") or (has("utc", "pkt") and not has_entity(ents))
    checks = has("cross-check", "consistent", "correlat", "do the logs match")

    if theft and not ents["alerts"]:
        i = next((x for x in analysis.incidents if x.get("exfil_asset")), None)
        if i:
            blocks.append(
                "**Answer on data theft.** Rule 2.4: never write that data was stolen or leaked unless a log shows the data moving "
                f"{cite_row(pack.file('01'), '2.4')}.\n"
                + "\n".join(f"- **Confirmed**: {x['text']} {' '.join(x['cites'])}" for x in i["confirmed"] if "Large transfer" in x["text"] or "independently" in x["text"])
                + "\n" + "\n".join(f"- **Not enough evidence in the logs**: {x['text']} {' '.join(x['cites'])}" for x in i["not_enough"] if "Which files" in x["text"])
                + f"\n- {pack.runbook_cite('RB-EXFIL-04', 5)}: record that it is unknown which files were read.")
    if people:
        blocks.append(_people(incs))
    if severity:
        blocks.append(_severity(pack, incs))
    if closed:
        c = _closed(analysis, ents)
        if c:
            blocks.append(c)
        elif not has_entity(ents):
            blocks.append("No alert in the logs was closed under that item.")
    if missing and not theft:
        blocks.append(_filter_missing(_missing(analysis), ql))
    if actions:
        blocks.append(_actions(incs))
    if timeline:
        blocks.append(_timeline(incs))
    if tz:
        blocks.append(_timezones(pack))
    if checks:
        blocks.append("**Cross-checks**\n" + "\n".join(f"- {'OK' if c['ok'] else 'CHECK'}: {c['name']} - {c['detail']} {' '.join(c['cites'])}" for c in analysis.checks))
    if has_entity(ents):
        text = _entity_answer(pack, analysis, ents, src_filter=next((k for k, ws in SRC_WORDS.items() if any(w in ql for w in ws)), None))
        if text:
            blocks.insert(0, text) if not blocks else blocks.append(text)
    if not blocks and topic:
        blocks.append("\n\n".join(f"**{i['id']} - {i['title']} ({i['severity']})**\n{i['summary']}\n" + _items("Confirmed", i["confirmed"][:6]) + "\n" + _items("Not enough evidence in the logs", i["not_enough"][:4]) for i in topic))
    if not blocks:
        words = [w for w in re.findall(r"[a-z0-9_.\-/]+", ql) if w not in STOP and len(w) > 2]
        hits = _search(pack, words)
        if hits and len(words) <= 6:
            blocks.append("**Closest matches in the logs** (UTC):\n" + "\n".join(_ev_line(e) for e in hits))
        else:
            blocks.append("**Not enough evidence in the logs.** Nothing in the 20 files answers this. "
                          "Available sources: VPN, domain controller, web server, perimeter and internal firewall, email gateway, IDS summary, DHCP "
                          f"{cite_row(pack.file('20'), 'VPN gateway')}; file-server audit, DB, proxy and EDR logs are not collected.")
    return "\n\n".join(b for b in blocks if b)


# ---------------------------------------------------------------- public API

def answer(pack, analysis, question, use_llm=True):
    from ai import llm
    question = (question or "").strip()[:1500]
    if not question:
        return {"answer": "Ask a question about the Orbit Logistics data pack.", "engine": "none", "citations": {"total": 0, "valid": 0, "invalid": []}}
    engine = "Pilot offline engine (deterministic, cited)"
    text = None
    if use_llm and llm.is_enabled():
        try:
            text = llm.complete(SYSTEM_PROMPT + "\n\n" + build_context(pack, analysis), f"QUESTION: {question}", temperature=0.1)
            engine = llm.engine_name() + " (grounded on the 20 files)"
            total, valid, bad = pack.check_text(text)
            if bad:   # a hallucinated citation: fall back to the verified offline engine
                text = offline_answer(pack, analysis, question)
                engine = "Pilot offline engine (LLM citations failed verification: " + ", ".join(bad[:3]) + ")"
        except Exception as error:
            print("[PACK] LLM failed, using offline engine:", error)
            text = None
    if text is None:
        text = offline_answer(pack, analysis, question)
    total, valid, bad = pack.check_text(text)
    return {"answer": text, "engine": engine, "citations": {"total": total, "valid": valid, "invalid": bad}}
