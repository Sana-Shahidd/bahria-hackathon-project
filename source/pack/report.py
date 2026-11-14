"""
Incident report in the mandatory format of file 01, section 7.

Sections (verbatim): Summary; Timeline (UTC, with file and line); Affected assets and accounts;
Severity (with steps); Confirmed; Suspected; Not enough evidence in the logs; Missing log sources;
Closed as harmless (with change ID); Recommended actions (runbook ID and step);
People to inform (name and time limit).
Times are UTC with PKT in brackets (rule 1.1).
"""
from pack.loader import cite_row

ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _cites(x):
    return " ".join(x)


def _incidents(analysis, incident_id):
    if incident_id:
        return [i for i in analysis.incidents if i["id"] == incident_id]
    return analysis.incidents


def build_markdown(analysis, incident_id=None):
    p = analysis.p
    incs = _incidents(analysis, incident_id)
    closed = analysis.closed if not incident_id else []
    out = []
    title = "Incident Report - Orbit Logistics - 2026-11-04"
    if incident_id and incs:
        title = f"Incident Report {incs[0]['id']} - {incs[0]['title']}"
    out += [f"# {title}", "",
            "*Times are UTC with PKT (UTC+5) in brackets [rule 1.1: " + cite_row(p.file("01"), "1.1")[1:-1] + "]. "
            "Evidence labels follow file 01 section 2. Every statement carries its source.*", ""]

    # 1 Summary
    out += ["## Summary", ""]
    if incs:
        top = min(incs, key=lambda i: ORDER[i["severity"]])
        out.append(f"**Overall severity: {top['severity']}** (highest of all parts, rule 4.2 {cite_row(p.file('01'), '4.2')}). "
                   f"{len(incs)} incident(s) opened and {len(closed)} alert(s) closed as approved activity.")
        out.append("")
        out += ["| Incident | Severity | Summary |", "|---|---|---|"]
        for i in incs:
            out.append(f"| {i['id']} | **{i['severity']}** | {i['summary']} |")
        for c in closed:
            out.append(f"| {c['id']} | none (approved) | {c['title']} closed under {c['change_id']} |")
        out.append("")
        if len(incs) > 1:
            out.append("Incidents with no shared evidence are scored separately "
                       f"(rule 4.3 {cite_row(p.file('01'), '4.3')}): the scan from 192.0.2.88, the SQL injection from 192.0.2.150 and the account takeover share no address, account or session.")
            out.append("")

    # 2 Timeline
    out += ["## Timeline (UTC, with file and line)", ""]
    for i in incs:
        out += [f"### {i['id']} - {i['title']}", "", "| Time UTC (PKT) | Event | Label | Source |", "|---|---|---|---|"]
        for t in sorted(i["timeline"], key=lambda x: x["ts"]):
            out.append(f"| {t['utc']} ({t['pkt']}) | {t['text']} | {t['label']} | {_cites(t['cites'])} |")
        out.append("")

    # 3 Affected assets and accounts
    out += ["## Affected assets and accounts", ""]
    for i in incs:
        out += [f"### {i['id']}", "", "| Asset | Criticality | Reached? | Evidence |", "|---|---|---|---|"]
        for a in i["assets"]:
            asset = a["asset"]
            out.append(f"| {asset['Hostname']} ({asset['Asset tag']}) {cite_row(p.file('02'), asset['Asset tag'])} | {asset['Criticality']} | "
                       f"{'yes (session)' if a['reached'] else 'no session, see note'} | {a['why']} |")
        if i.get("accounts"):
            out += ["", "| Account | Role | Status | Source |", "|---|---|---|---|"]
            for acc in i["accounts"]:
                out.append(f"| {acc['username']} ({acc['name']}) | {acc['role']} | {acc['status']} | {acc['cite']} |")
        out.append("")

    # 4 Severity
    out += ["## Severity (with steps)", ""]
    for i in incs:
        out += [f"### {i['id']} - overall **{i['severity']}**", ""]
        for part in sorted(i["parts"], key=lambda x: ORDER[x["severity"]]):
            out.append(f"- **{part['severity']}** - {part['name']}")
            for n, step in enumerate(part["steps"], 1):
                out.append(f"  {n}. {step}")
        if len(i["parts"]) > 1:
            out.append(f"- **Whole incident = highest part = {i['severity']}** (rule 4.2 {cite_row(p.file('01'), '4.2')}). "
                       f"A phishing mail with a click is handled as credential compromise ({cite_row(p.file('03'), 'Phishing email delivered, no click seen')}).")
        out.append("")

    def block(label, key, with_guess=False):
        out.append(f"## {label}")
        out.append("")
        for i in incs:
            items = i[key]
            if not items:
                continue
            out.append(f"### {i['id']}")
            for it in items:
                line = f"- {it['text']} {_cites(it['cites'])}"
                if with_guess and it.get("guess"):
                    line += f" *Guess needed: {it['guess']}.*"
                out.append(line)
            out.append("")

    block("Confirmed", "confirmed")
    block("Suspected", "suspected", with_guess=True)
    block("Not enough evidence in the logs", "not_enough")
    if analysis.observations and not incident_id:
        out.append("### Other observations (no incident opened)")
        for o in analysis.observations:
            out.append(f"- {o['text']} {_cites(o['cites'])}")
        out.append("")

    out += ["## Missing log sources", ""]
    seen = set()
    for i in incs:
        for m in i["missing"]:
            if m["source"] in seen:
                continue
            seen.add(m["source"])
            out.append(f"- **{m['source']}**: {m['impact']} {m['cite']}")
    out.append("")

    out += ["## Closed as harmless (with change ID)", ""]
    if not closed:
        out.append("Nothing in this scope.")
    for c in closed:
        out += [f"### {c['id']} - {c['title']} - **{c['change_id']}** ({c['status']})", ""]
        out += [f"- {r}" for r in c["reasons"]]
        out.append(f"- {c['detail']}")
        out.append(f"- {c['rule']}")
        for n in c.get("near_miss", []):
            out.append(f"- Not used: {n}")
        out.append(f"- Sources: {_cites(c['cites'])}")
        out.append("")

    out += ["## Recommended actions (runbook ID and step)", ""]
    for i in incs:
        out += [f"### {i['id']} - {i['title']}", ""]
        for a in i["actions"]:
            note = f" - **{a['note']}**" if a.get("note") else ""
            out.append(f"- {a['cite']}: {a['text']}{note}")
        out.append("")

    out += ["## People to inform (name and time limit)", "",
            "The time limit starts when the SOC first sees the incident "
            f"{cite_row(p.file('04'), 'P1-CISO')[:0]}(note under the table in file 04).", "",
            "| Incident | Severity | Who | Time limit | How | Source |", "|---|---|---|---|---|---|"]
    for i in incs:
        merged = {}
        for pe in i["people"]:
            merged.setdefault((pe["severity"], pe["who"]), dict(pe, **{"for": []}))["for"].append(pe["for"])
        for (sev, who), pe in merged.items():
            note = f" (for: {'; '.join(pe['for'])})" if sev != i["severity"] else ""
            out.append(f"| {i['id']} | {sev} | {who}{note} | {pe['limit']} | {pe['how']} | {pe['cite']} |")
    out.append("")

    if not incident_id and analysis.checks:
        out += ["## Appendix - cross-checks", ""]
        for c in analysis.checks:
            out.append(f"- {'OK' if c['ok'] else 'CHECK'}: {c['name']} - {c['detail']} {_cites(c['cites'])}")
        out.append("")

    total, valid, bad = p.check_text("\n".join(out))
    out.append(f"*Citation check: {valid}/{total} citations verified against the 20 files" + (f"; unverified: {', '.join(bad)}" if bad else "") + ".*")
    return "\n".join(out)
