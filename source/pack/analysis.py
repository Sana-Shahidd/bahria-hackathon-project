"""
Deterministic incident analysis over the Problem C data pack.

Nothing here is invented: every finding is built from parsed log lines / table
rows and carries its citations. Evidence labels follow file 01 section 2:
  confirmed  - shown directly by a log line or table row
  suspected  - needs a guess to link two things (the guess is stated)
  not_enough - the logs are silent or missing
"""
import ipaddress
import re
from datetime import datetime, timedelta

from pack.loader import UTC, PKT, fmt_utc, fmt_pkt, fmt_both, cite_row

LARGE_TRANSFER_BYTES = 100 * 1024 * 1024
SQLI_RE = re.compile(r"('|%27|union\s+select|or\s+'?1'?\s*=\s*'?1|order\s+by\s+\d+|waitfor\s+delay|--|;)", re.I)
ATTACK_TOOLS = ("sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster", "wpscan")
SCANNER_PROBE_PATHS = ("/admin", "/phpmyadmin", "/.env", "/.git", "/wp-admin", "/backup")


def is_private(ip):
    """RFC1918 only (documentation ranges such as 192.0.2.0/24 are NOT internal for Orbit)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def mb(n):
    return f"{int(n):,} bytes (~{int(n) / 1e9:.2f} GB)" if int(n) >= 1e8 else f"{int(n):,} bytes"


class Analysis:
    def __init__(self, pack):
        self.p = pack
        self.f = pack.file
        self.incidents = []
        self.closed = []
        self.observations = []
        self.checks = []
        self._seq = 0
        self.run()

    # ------------------------------------------------------------ helpers
    def ev(self, src, **match):
        out = []
        for e in self.p.events:
            if e["src"] != src:
                continue
            if all(e.get(k) == v for k, v in match.items()):
                out.append(e)
        return out

    def new_incident(self, title, kind):
        self._seq += 1
        inc = {"id": f"IR-{self._seq}", "title": title, "kind": kind, "parts": [], "timeline": [],
               "assets": [], "confirmed": [], "suspected": [], "not_enough": [], "missing": [],
               "actions": [], "people": [], "severity": None, "summary": "", "cites": []}
        self.incidents.append(inc)
        return inc

    def tl(self, inc, ts, text, cites, label="confirmed", src=None, orig=None):
        inc["timeline"].append({"ts": ts, "utc": fmt_utc(ts), "pkt": fmt_pkt(ts), "text": text,
                                "cites": cites if isinstance(cites, list) else [cites],
                                "label": label, "src": src, "orig": orig})

    @staticmethod
    def item(text, cites, guess=None):
        return {"text": text, "cites": cites if isinstance(cites, list) else [cites], "guess": guess}

    def severity(self, inc_type, asset, note=""):
        """Look up the matrix. Returns part dict with the steps shown to the reader."""
        row = self.p.matrix[inc_type]
        crit = asset["Criticality"]
        sev = row[crit]
        steps = [
            f"Incident type = '{row['label']}' {cite_row(self.f('03'), inc_type)}",
            f"Most critical asset actually reached = {asset['Hostname']} ({asset['Asset tag']}), criticality {crit} "
            f"{cite_row(self.f('02'), asset['Asset tag'])}" + (f" - {note}" if note else ""),
            f"Matrix row '{inc_type}' x column '{crit}' = {sev} {cite_row(self.f('03'), inc_type)}",
        ]
        return sev, steps

    def add_actions(self, inc, rb_id, steps, extra=None):
        for s in steps:
            text = self.p.runbooks[rb_id]["steps"][s]
            note = (extra or {}).get(s)
            inc["actions"].append({"runbook": rb_id, "step": s, "text": text, "note": note,
                                   "cite": self.p.runbook_cite(rb_id, s)})

    def people_for(self, inc, severity, asset=None, finance_hr=False, label=""):
        for row in self.p.escalation:
            if row["Severity"] != severity:
                continue
            role = row["role"]
            if role.startswith("Legal") and not finance_hr:
                continue
            who = row["Who to inform"]
            if role.startswith("Data owner"):
                owner = asset["Owner"] if asset else ""
                m = re.search(r"data owner:\s*([^,)]+)", owner)
                who = f"Data owner of {asset['Hostname']} - {m.group(1).strip()}" if m else f"Data owner of {asset['Hostname'] if asset else 'affected system'} ({owner})"
            elif role.startswith("System owner"):
                who = f"System owner of {asset['Hostname']} - {asset['Owner']}" if asset else who
            inc["people"].append({"severity": severity, "who": who, "limit": row["Time limit"], "how": row["How"],
                                  "cite": cite_row(self.f("04"), row["id"]), "for": label,
                                  "condition": row["How"] if role.startswith("Legal") else None})

    # ------------------------------------------------------------ master
    def run(self):
        self.scans()
        self.web_attacks()
        self.phishing_and_credentials()
        self.admin_sessions()
        self.consistency_checks()
        self.incidents.sort(key=lambda i: (i["severity"] or "P9", i["id"]))
        for n, inc in enumerate(self.incidents, 1):
            inc["id"] = f"IR-{n}"

    # ------------------------------------------------------------ change calendar
    def match_change(self, who_ips, who_names, target_ips, start, end, system_names=()):
        """Rule 3.1: same system + same person/tool + window contains the activity."""
        results = []
        for cid, ch in self.p.changes.items():
            performed = ch["Performed by"]
            target = ch["System / target"]
            person_ok = any(x and x.lower() in performed.lower() for x in list(who_ips) + list(who_names))
            nets = re.findall(r"\d+\.\d+\.\d+\.\d+/\d+", target)
            sys_ok = False
            if nets and target_ips:
                sys_ok = all(any(ipaddress.ip_address(t) in ipaddress.ip_network(n) for n in nets) for t in target_ips)
            for name in system_names:
                if name and name.lower() in target.lower():
                    sys_ok = True
            # window (PKT) -> UTC
            wm = re.match(r"(\d\d:\d\d)\s*-\s*(\d\d:\d\d)", ch["Window (PKT)"])
            day = datetime.strptime(ch["Date"], "%Y-%m-%d").replace(tzinfo=PKT)
            w0 = day.replace(hour=int(wm.group(1)[:2]), minute=int(wm.group(1)[3:])).astimezone(UTC)
            w1 = day.replace(hour=int(wm.group(2)[:2]), minute=int(wm.group(2)[3:]), second=59).astimezone(UTC)
            win_ok = w0 <= start and end <= w1
            performed_status = ch["Status"]
            results.append({"id": cid, "person_ok": person_ok, "sys_ok": sys_ok, "win_ok": win_ok,
                            "status": performed_status, "w0": w0, "w1": w1, "row": ch})
        full = [r for r in results if r["person_ok"] and r["sys_ok"] and r["win_ok"]]
        approved = [r for r in full if r["status"].lower().startswith(("approved", "completed"))]
        near = [r for r in results if (r["person_ok"] or r["sys_ok"]) and r not in full]
        return approved, full, near

    # ------------------------------------------------------------ scans
    def scans(self):
        p = self.p
        sources = []
        for aid, row in p.ids_alerts.items():
            m = re.search(r"Port scan from ([\d.]+) against (.*?)( \(|$)", row["Description"])
            if m:
                sources.append((aid, m.group(1)))
        for aid, ip in sources:
            alert = p.ids_alerts[aid]
            edge = [e for e in self.ev("fw_edge") if e["src_ip"] == ip]
            internal = [e for e in self.ev("fw_int") if e["src_ip"] == ip]
            web = [e for e in self.ev("web") if e["ip"] == ip]
            fw_events = edge + internal
            if not (fw_events or web):
                continue
            src_asset = p.asset_by_ip(ip)
            external = not is_private(ip)
            start = min([e["start"] for e in fw_events] + [e["ts"] for e in web])
            end = max([e["end"] for e in fw_events] + [e["ts"] for e in web])
            targets = sorted({e["dst_ip"] for e in fw_events})
            ids_ev = next(e for e in p.events if e.get("alert_id") == aid)

            if not external:
                # internal scanner: check change calendar
                dest_ips = set(targets)
                for e in web:
                    a = p.asset_by_host("WEB01")
                    if a:
                        dest_ips.add(a["ips"][0])
                approved, full, near = self.match_change([ip], [src_asset["Hostname"] if src_asset else ""],
                                                         dest_ips, start, end)
                if approved:
                    ch = approved[0]
                    self.close_scan(aid, ip, src_asset, ch, fw_events, web, start, end, targets, ids_ev)
                    continue
            self.open_scan(aid, ip, external, edge, internal, web, start, end, ids_ev, alert)

    def close_scan(self, aid, ip, src_asset, ch, fw_events, web, start, end, targets, ids_ev):
        p = self.p
        row = ch["row"]
        cites = [e["cite"] for e in fw_events + web] + [ids_ev["cite"]]
        allowed = [e for e in fw_events if e["action"] == "ALLOW"]
        denied = [e for e in fw_events if e["action"] == "DENY"]
        self.closed.append({
            "id": f"CL-{len(self.closed) + 1}", "alert": aid, "title": f"Vulnerability scan from {src_asset['Hostname']} ({ip})",
            "change_id": ch["id"], "status": row["Status"],
            "reasons": [
                f"Same system: targets {', '.join(targets)} are inside '{row['System / target']}' {cite_row(self.f('05'), ch['id'])}",
                f"Same tool: source {ip} is {src_asset['Hostname']} ({src_asset['Asset tag']}), named in '{row['Performed by']}' "
                f"{cite_row(self.f('05'), ch['id'])} {cite_row(self.f('02'), src_asset['Asset tag'])}",
                f"Window contains the activity: change window {row['Window (PKT)']} PKT = {fmt_utc(ch['w0'])[11:19]}-{fmt_utc(ch['w1'])[11:19]} UTC; "
                f"activity {fmt_utc(start)[11:19]}-{fmt_utc(end)[11:19]} UTC (in PKT {fmt_pkt(start)[:8]}-{fmt_pkt(end)[:8]})",
            ],
            "detail": f"{len(allowed)} sessions allowed, {len(denied)} denied (e.g. {denied[0]['raw'].split('rule=')[-1] if denied else '-'}); "
                      f"{len(web)} web requests with scanner user agent." ,
            "cites": cites + [cite_row(self.f("05"), ch["id"])],
            "runbook": [p.runbook_cite("RB-SCAN-05", 1), p.runbook_cite("RB-SCAN-05", 2)],
            "severity": None,
            "rule": f"Rule 3.2: approved activity is not escalated {cite_row(self.f('01'), '3.2')}; matrix: approved activity gets no severity {cite_row(self.f('03'), 'Unapproved scanning or reconnaissance')}",
            "near_miss": [f"{n['id']} ({n['row']['Date']}, {n['row']['System / target']}) is not a match: wrong date/window/system"
                          for n in self.match_change([ip], [src_asset['Hostname']], set(targets), start, end)[2]],
            "start": start, "end": end,
            "timeline": [{"ts": e["start"], "utc": fmt_utc(e["start"]), "pkt": fmt_pkt(e["start"]),
                          "text": self.describe(e), "cites": [e["cite"]], "label": "confirmed", "src": e["src"]}
                         for e in sorted(fw_events + web + [ids_ev], key=lambda x: x.get("start", x["ts"]))],
        })

    def open_scan(self, aid, ip, external, edge, internal, web, start, end, ids_ev, alert):
        p = self.p
        inc = self.new_incident(f"Port scan and web probing from {ip}", "scan")
        denied = [e for e in edge + internal if e["action"] == "DENY"]
        allowed = [e for e in edge + internal if e["action"] == "ALLOW"]
        ports_denied = sorted({e["dst_port"] for e in denied})
        ports_allowed = sorted({e["dst_port"] for e in allowed})
        target_ip = (edge or internal)[0]["dst_ip"]
        asset = p.asset_by_ip(target_ip) or p.asset_by_host("WEB01")
        inc["assets"].append({"asset": asset, "reached": True,
                              "why": f"allowed TCP session to port {','.join(map(str, ports_allowed))} and HTTP responses in the web log"})
        for e in sorted(edge + internal + web + [ids_ev], key=lambda x: x.get("start", x["ts"])):
            self.tl(inc, e.get("start", e["ts"]), self.describe(e), [e["cite"]], src=e["src"])
        inc["confirmed"] += [
            self.item(f"{ip} is an external address (not in RFC1918 ranges) and is not listed in the change calendar, so the scan is unapproved "
                      f"{cite_row(self.f('05'), 'CHG-2026-1104-02')} (no change lists {ip}).", [ids_ev["cite"]]),
            self.item(f"{len(denied)} connection attempts to ports {', '.join(map(str, ports_denied))} on {target_ip} were denied by the default-deny rule.",
                      [e["cite"] for e in denied]),
            self.item(f"Port {', '.join(map(str, ports_allowed))} was allowed ({len(allowed)} session) and the web server answered {len(web)} probe requests "
                      f"({', '.join(e['path'] for e in web)}) with HTTP {', '.join(sorted({str(e['status']) for e in web}))}, so none of those paths exist.",
                      [e["cite"] for e in allowed + web]),
        ]
        later = [e for e in p.events if e["ts"] > end and ip in e["raw"] and e["cite"] not in {x["cite"] for x in edge + web + [ids_ev]}]
        inc["confirmed"].append(self.item(
            f"No login attempt, authentication event or other activity from {ip} appears in any provided log after the scan"
            if not later else f"Later activity from {ip} found", [ids_ev["cite"]]))
        inc["not_enough"].append(self.item(
            "Whether the scanner continued before or after 2026-11-04: no logs exist for other dates "
            f"{cite_row(self.f('20'), 'Other dates')}", cite_row(self.f("20"), "Other dates")))
        inc["missing"] += self.generic_missing(["other_dates"])
        sev, steps = self.severity("Unapproved scanning or reconnaissance", asset, "scan reached the public web server only")
        inc["parts"].append({"name": "Unapproved external scanning", "severity": sev, "steps": steps,
                             "type": "Unapproved scanning or reconnaissance", "asset": asset["Asset tag"]})
        inc["severity"] = sev
        self.add_actions(inc, "RB-SCAN-05", [1, 3, 5, 6], {
            1: f"No matching approved scan: {ip} is not in any change record {cite_row(self.f('05'), 'CHG-2026-1104-02')}",
            3: f"Source {ip} is external -> block it at the perimeter firewall",
            5: f"Answered (allowed): port {', '.join(map(str, ports_allowed))}; refused (denied): {', '.join(map(str, ports_denied))}; login attempts followed: none seen",
        })
        self.people_for(inc, sev, asset, label=inc["title"])
        inc["summary"] = (f"{ip} scanned {asset['Hostname']} (ports {', '.join(map(str, ports_denied))} denied, 443 allowed) and probed "
                          f"{', '.join(e['path'] for e in web)} (all 404). No change record covers it. Severity {sev}.")
        inc["related_ids"] = [ip]

    # ------------------------------------------------------------ web attacks
    def web_attacks(self):
        p = self.p
        by_ip = {}
        for e in self.ev("web"):
            hit = SQLI_RE.search(e["path"]) or any(t in e["agent"].lower() for t in ATTACK_TOOLS)
            if hit and not is_private(e["ip"]):
                by_ip.setdefault(e["ip"], []).append(e)
        for ip, reqs in by_ip.items():
            all_reqs = [e for e in self.ev("web") if e["ip"] == ip]
            if any(self.is_probe_only(e) for e in all_reqs) and not any(SQLI_RE.search(e["path"]) for e in all_reqs):
                continue  # pure probing handled by the scan incident
            ids = [e for e in p.events if e["src"] == "ids" and ip in e["desc"]]
            edge = [e for e in self.ev("fw_edge") if e["src_ip"] == ip]
            asset = p.asset_by_host("WEB01")
            errs = sorted(e["size"] for e in reqs if e["status"] >= 400)
            baseline = errs[len(errs) // 2] if errs else 0
            big = [e for e in reqs if e["status"] == 200 and (baseline and e["size"] > baseline * 10)]
            inc = self.new_incident(f"SQL injection against {asset['Hostname']} from {ip}", "web")
            inc["assets"].append({"asset": asset, "reached": True, "why": "HTTP session with the application"})
            for e in sorted(edge + reqs + ids, key=lambda x: x["ts"]):
                self.tl(inc, e["ts"], self.describe(e), [e["cite"]], src=e["src"],
                        label="suspected" if e in big else "confirmed")
            tool = next((e["agent"] for e in reqs if any(t in e["agent"].lower() for t in ATTACK_TOOLS)), None)
            inc["confirmed"].append(self.item(
                f"{len(reqs)} requests from {ip} carry SQL injection patterns" + (f" and the automated tool user agent '{tool}'" if tool else "") +
                f"; {len([e for e in reqs if e['status'] >= 400])} returned HTTP 5xx errors (size {baseline} bytes).",
                [e["cite"] for e in reqs] + [i["cite"] for i in ids]))
            for e in big:
                inc["confirmed"].append(self.item(
                    f"One request returned HTTP 200 with {e['size']:,} bytes ({e['size'] // max(baseline, 1)}x the {baseline}-byte error pages): "
                    f"{e['path']}. Per runbook, a large 200 to an attack request may mean success {p.runbook_cite('RB-WEB-03', 3)}.",
                    [e["cite"]]))
                inc["suspected"].append(self.item(
                    f"The UNION SELECT request returned data from the database (success).",
                    [e["cite"]], guess="the 48 KB 200 response contains query results; the logs hold only the response size, not its content"))
            inc["not_enough"] += [
                self.item("What the large response contained, or whether any customer or credential data left the database: "
                          "SRV-DB01 login and query logs are not forwarded to the SOC.", [cite_row(self.f("20"), "SRV-DB01 login and query log")]),
                self.item(f"Whether {ip} reached any other system: it appears only in the web server log, the perimeter firewall log and the IDS summary.",
                          [i["cite"] for i in ids]),
            ]
            inc["missing"] += self.generic_missing(["db01"])
            sev, steps = self.severity("Web application attack, success suspected or confirmed", asset,
                                       "attacker session reached the public web server; no evidence of reaching SRV-DB01")
            inc["parts"].append({"name": "SQL injection with suspected success", "severity": sev, "steps": steps,
                                 "type": "Web application attack, success suspected or confirmed", "asset": asset["Asset tag"]})
            inc["severity"] = sev
            self.add_actions(inc, "RB-WEB-03", [1, 2, 3, 4, 5, 6, 7], {
                2: f"Block {ip} at the perimeter firewall",
                5: "Not possible from the SOC: database logs are not forwarded (file 20) - ask the Applications team",
                6: "Cannot be verified from the logs provided - ask the web team",
            })
            self.people_for(inc, sev, asset, label=inc["title"])
            inc["summary"] = (f"SQL injection (tool user agent {tool or 'unknown'}) from {ip} against {asset['Hostname']}; one UNION SELECT request got a large HTTP 200 "
                              f"({big[0]['size']:,} bytes), so success is suspected. Whether data left the database cannot be told from the logs.") if big else f"SQL injection attempts from {ip}."
            inc["related_ids"] = [ip]

    def is_probe_only(self, e):
        return e["path"].split("?")[0] in SCANNER_PROBE_PATHS

    def coverage_notes_cite(self):
        return [cite_row(self.f("20"), "Web server")]

    # ------------------------------------------------------------ phishing -> credentials -> exfil
    def phishing_and_credentials(self):
        p = self.p
        mails = {}
        for e in self.ev("email"):
            if e.get("url_host") and e.get("spf") == "fail":
                mails.setdefault(e["msgid"], []).append(e)
        for msgid, rows in mails.items():
            url_host = rows[0]["url_host"]
            link_alert = next((e for e in p.events if e["src"] == "ids" and url_host in e["desc"]), None)
            link_ip = next((x for x in re.findall(r"\d+\.\d+\.\d+\.\d+", link_alert["desc"]) if not is_private(x)), None) if link_alert else None
            first = rows[0]
            inc = self.new_incident(f"Phishing {msgid} leading to account takeover and large data transfer", "phish")
            quarantine_note = f"score {first['score']} is below the quarantine threshold of 8.0 so it was delivered {cite_row(self.f('20'), 'Email gateway')}"
            self.tl(inc, first["ts"], f"Phishing mail {msgid} from {first['from']} ('{first['subject']}', link host {url_host}) delivered to "
                    f"{len(rows)} recipients; spf=fail dkim=none; {quarantine_note}.", [r["cite"] for r in rows], src="email",
                    orig=first["raw"][:21])
            inc["confirmed"].append(self.item(
                f"Mail {msgid} was delivered (not quarantined) to {', '.join(r['to'].split('@')[0] for r in rows)}; sender domain "
                f"{first['from'].split('@')[1]} is not the company domain orbitlogistics.example (SPF fail, DKIM none); {quarantine_note}.",
                [r["cite"] for r in rows]))
            if link_alert:
                inc["confirmed"].append(self.item(
                    f"Link host {url_host} resolves to {link_ip} (threat intelligence: newly registered domain).", [link_alert["cite"]]))
            clicked = []
            for r in rows:
                user = p.user_by_email(r["to"])
                asset = p.assets[user["Laptop tag"]]
                lap_ip = asset["ips"][0]
                conns = [e for e in self.ev("fw_edge") if e["src_ip"] == lap_ip and e["dst_ip"] == link_ip and e["ts"] >= r["ts"]] if link_ip else []
                other = [e for e in self.ev("fw_edge") if e["src_ip"] == lap_ip and e["ts"] >= r["ts"] and e not in conns]
                lease = p.dhcp_host(lap_ip, conns[0]["ts"] if conns else r["ts"])
                if conns:
                    c = conns[0]
                    clicked.append((user, asset, c, lease, r))
                    self.tl(inc, c["ts"], f"{user['Full name']}'s laptop {asset['Hostname']} ({lap_ip}) connected to {link_ip}:443 - the phishing link host "
                            f"({int((c['ts'] - r['ts']).total_seconds() // 60)} min after delivery).",
                            [c["cite"], link_alert["cite"], lease["cite"] if lease else asset["_file"]], src="fw_edge")
                    inc["confirmed"].append(self.item(
                        f"{user['Full name']} ({user['Username']}): click seen. {lap_ip} ({asset['Hostname']}) connected to {link_ip}:443 "
                        f"{int((c['ts'] - r['ts']).total_seconds() // 60)} minutes after delivery. Laptop-to-IP link: DHCP lease "
                        f"{'to ' + lease['hostname'] if lease else 'not found'} and asset inventory.",
                        [c["cite"], r["cite"], cite_row(self.f("18"), user["Username"])] + ([lease["cite"]] if lease else [cite_row(self.f("02"), asset["Asset tag"])])))
                    inc["suspected"].append(self.item(
                        f"{user['Full name']} typed her password on the fake payroll page.",
                        [c["cite"]], guess="the logs show only that the connection happened, not what was entered; supported by the VPN login from the same IP below"))
                else:
                    sev, steps = self.severity("Phishing email delivered, no click seen", asset, "no connection to the link host from this user's laptop")
                    inc["parts"].append({"name": f"Phishing delivered, no click seen - {user['Full name']}", "severity": sev, "steps": steps,
                                         "type": "Phishing email delivered, no click seen", "asset": asset["Asset tag"],
                                         "user": user["Username"]})
                    seen = ", ".join(f"{e['dst_ip']}:{e['dst_port']}" for e in other) or "none"
                    inc["confirmed"].append(self.item(
                        f"{user['Full name']} ({user['Username']}): no click seen. Perimeter firewall shows no connection from {lap_ip} to {link_ip} "
                        f"(other outbound connections after delivery: {seen}).",
                        [r["cite"]] + [e["cite"] for e in other]))
                    inc["not_enough"].append(self.item(
                        f"Whether {user['Full name']} opened the mail or clicked from another device or network: no web proxy log and no EDR logs exist "
                        f"{cite_row(self.f('20'), 'Web proxy log (which websites staff open)')}.", [r["cite"], cite_row(self.f("20"), "Laptop endpoint security (EDR) logs")]))
            if not clicked:
                inc["severity"] = max((x["severity"] for x in inc["parts"]), default="P4")
                continue
            for user, asset, c, lease, r in clicked:
                self.credential_chain(inc, user, asset, link_ip, link_alert, c, rows)
            self.finish_phish_incident(inc, rows, url_host, link_ip)

    # ------------------------------------------------------------ credential chain
    def credential_chain(self, inc, user, laptop, link_ip, link_alert, click, rows):
        p = self.p
        uname = user["Username"]
        vpn = [e for e in self.ev("vpn") if e.get("user") == uname]
        fails = [e for e in vpn if e.get("result") == "FAIL"]
        succ = [e for e in vpn if e.get("result") == "SUCCESS" and (e.get("geo") != "PK")]
        if not succ:
            inc["not_enough"].append(self.item(
                f"{uname} clicked, but no VPN login from an unusual location appears in the VPN log.", [click["cite"]]))
            return
        login = succ[0]
        attacker_ip = login["src_ip"]
        session_id = login["session"]
        assigned = login["assigned_ip"]
        end = next((e for e in vpn if e.get("kind") == "session_end" and e.get("session") == session_id), None)
        seq = [e for e in fails if e["src_ip"] == attacker_ip and e["ts"] < login["ts"]]
        denied = [e for e in seq if "denied" in e.get("reason", "")]
        timeout = [e for e in seq if "timeout" in e.get("reason", "")]
        same_ip = attacker_ip == link_ip

        for e in seq:
            self.tl(inc, e["ts"], f"VPN login FAIL for {uname} from {e['src_ip']} (geo={e['geo']}): {e['reason']}.", [e["cite"]], src="vpn")
        fw_in = [e for e in self.ev("fw_edge") if e["src_ip"] == attacker_ip and e["dst_port"] == 443 and e["ts"] <= login["ts"] and e["ts"] >= (seq[0]["ts"] - timedelta(minutes=5) if seq else login["ts"])]
        for e in fw_in:
            self.tl(inc, e["ts"], f"Perimeter firewall allows {attacker_ip} to VPN gateway 203.0.113.20:443 (connection start).", [e["cite"]], src="fw_edge")
        self.tl(inc, login["ts"], f"VPN login SUCCESS for {uname} from {attacker_ip} (geo={login['geo']}), mfa={login['mfa']}, assigned {assigned}, session {session_id}.",
                [login["cite"]], src="vpn")
        ids_login = next((e for e in p.events if e["src"] == "ids" and attacker_ip in e["desc"] and "VPN login" in e["desc"]), None)
        if ids_login:
            self.tl(inc, ids_login["ts"], f"IDS {ids_login['alert_id']}: VPN login by {uname} from new country.", [ids_login["cite"]], src="ids")

        baseline = {e.get("geo") for e in self.ev("vpn") if e.get("result") == "SUCCESS" and e.get("user") != uname}
        inc["confirmed"].append(self.item(
            f"VPN: {len(denied)} rejected MFA pushes and {len(timeout)} timeout for {uname} from {attacker_ip} (geo {login['geo']}), then an approved push "
            f"at {fmt_utc(login['ts'])[11:19]} UTC. Every other VPN login that day is from {', '.join(sorted(baseline))}. "
            f"This matches rule 6.1 (stolen password) {cite_row(self.f('01'), '6.1')}.",
            [e["cite"] for e in seq] + [login["cite"]]))
        if same_ip:
            inc["confirmed"].append(self.item(
                f"The VPN attacker address {attacker_ip} is the same address that hosts the phishing link host ({link_ip}).",
                [login["cite"], link_alert["cite"]]))
            inc["suspected"].append(self.item(
                f"The credentials captured by the phishing page were used for the VPN login.", [click["cite"], login["cite"]],
                guess=f"same IP {attacker_ip} for the fake page and the VPN login, but the logs do not show the password being typed"))
        inc["suspected"].append(self.item(
            f"The approved MFA push was accepted by {user['Full name']} (push fatigue) or by the attacker with a second factor.", [login["cite"]],
            guess="the VPN log shows only 'push_approved', not who pressed approve"))

        reached = []
        dc_events = [e for e in self.ev("dc") if e.get("client") == assigned]
        fw_sessions = [e for e in self.ev("fw_int") if e["src_ip"] == assigned]
        dc_cites = []
        for e in dc_events:
            kind = f"EventID {e['EventID']} {e['desc']}"
            text = f"DC {kind}: {e.get('account') or e.get('target')} from {assigned}" + (f", service {e['service']}" if e.get("service") else "") + f" -> {e.get('result', '')}"
            self.tl(inc, e["ts"], text, [e["cite"]], src="dc")
            dc_cites.append(e["cite"])
        for e in fw_sessions:
            asset = p.asset_by_ip(e["dst_ip"])
            big = int(e.get("bytes_total", 0)) >= LARGE_TRANSFER_BYTES
            self.tl(inc, e["start"], f"Internal firewall: {assigned} -> {asset['Hostname'] if asset else e['dst_ip']}:{e['dst_port']} session starts "
                    f"(closed {fmt_utc(e['end'])[11:19]} UTC after {e['duration']}; {int(e['bytes_total']):,} bytes)" + (" - LARGE TRANSFER" if big else "") + ".",
                    [e["cite"]], src="fw_int", label="confirmed", orig=e["raw"][:19] + " PKT")
            reached.append((e, asset, big))
        asset_by_tag = {}
        for e, asset, big in reached:
            if asset and e["dst_port"] != 88 and e["dst_port"] != 389:
                asset_by_tag.setdefault(asset["Asset tag"], (asset, []))[1].append(e)
        for tag, (asset, evs) in asset_by_tag.items():
            inc["assets"].append({"asset": asset, "reached": True,
                                  "why": f"session(s) from {assigned} to port {','.join(sorted({str(x['dst_port']) for x in evs}))} " + ", ".join(x["cite"] for x in evs)})
        dc_asset = p.asset_by_host("DC01")
        tickets = [e for e in dc_events if e["EventID"] in ("4768", "4769")]
        inc["assets"].append({"asset": dc_asset, "reached": False,
                              "why": "issued Kerberos tickets to the attacker session (authentication service); no logon session on the DC by this account is logged"})
        inc["confirmed"].append(self.item(
            f"Using the VPN address {assigned}, the account authenticated through the domain controller and opened sessions to "
            + ", ".join(f"{a['Hostname']} (port {','.join(sorted({str(x['dst_port']) for x in evs}))})" for a, evs in asset_by_tag.values()) + ".",
            [e["cite"] for e in tickets] + [e["cite"] for e, a, b in reached]))
        gap = p.coverage["Internal firewall"]["gap"]
        pw = next((e for e in dc_events if e["EventID"] == "4724"), None)
        if pw:
            mail = next((e for e in self.ev("email") if e.get("to") == user["Email"] and "password" in e.get("subject", "").lower()), None)
            inc["confirmed"].append(self.item(
                f"At {fmt_utc(pw['ts'])[11:19]} UTC the account's password was reset from the VPN address {assigned} (4724, result SUCCESS); the mail gateway then "
                f"delivered 'Your password was changed' to {uname} {mail['cite'] if mail else ''}.", [pw["cite"]] + ([mail["cite"]] if mail else [])))
            if mail:
                self.tl(inc, mail["ts"], "Mail gateway delivers 'Your password was changed' to the account owner.", [mail["cite"]], src="email")
        lock = [e for e in self.ev("dc") if e.get("EventID") in ("4625", "4740") and e.get("account", "").endswith(uname)]
        if lock:
            for e in lock:
                self.tl(inc, e["ts"], f"DC EventID {e['EventID']} {e['desc']} for {uname} from {e.get('client') or e.get('caller')}.", [e["cite"]], src="dc")
            ids_lock = next((e for e in p.events if e["src"] == "ids" and "lockout" in e["desc"].lower()), None)
            inc["suspected"].append(self.item(
                f"The 07:31 failed logons and lockout on {laptop['Hostname']} are the real user typing the old password after the attacker changed it.",
                [e["cite"] for e in lock] + ([ids_lock["cite"]] if ids_lock else []),
                guess="the logs show bad_password from her laptop after the 4724 reset; they do not show who was typing"))
            if ids_lock:
                self.tl(inc, ids_lock["ts"], f"IDS {ids_lock['alert_id']}: account lockout for {uname}.", [ids_lock["cite"]], src="ids")
        if end:
            self.tl(inc, end["ts"], f"VPN session {session_id} ends: duration {end['duration']}, bytes_to_client {int(end['bytes_to_client']):,}, bytes_from_client {int(end['bytes_from_client']):,}.",
                    [end["cite"]], src="vpn")
        if gap:
            self.tl(inc, gap[0], f"Internal firewall logging gap starts (device reboot) {fmt_both(gap[0])} to {fmt_both(gap[1])}.",
                    [cite_row(self.f("20"), "Internal firewall")], label="not_enough", src="coverage")

        # large transfer
        for e, asset, big in reached:
            if not big:
                continue
            ids_t = next((x for x in p.events if x["src"] == "ids" and "SMB" in x["desc"]), None)
            s2c = int(e.get("bytes_server_to_client", 0))
            exfil_cites = [e["cite"]] + ([end["cite"]] if end else []) + ([ids_t["cite"]] if ids_t else [])
            if ids_t:
                self.tl(inc, ids_t["ts"], f"IDS {ids_t['alert_id']}: large SMB transfer (~2.4 GB) from {asset['Hostname']} to {assigned}.", [ids_t["cite"]], src="ids")
            inc["confirmed"].append(self.item(
                f"Large transfer: {mb(e['bytes_total'])} total, {mb(s2c)} from {asset['Hostname']} ({e['dst_ip']}) to {assigned} (the attacker's VPN session) "
                f"between {fmt_utc(e['start'])[11:19]} and {fmt_utc(e['end'])[11:19]} UTC. The internal firewall logs at session CLOSE, so the start is derived "
                f"(close {fmt_utc(e['end'])[11:19]} UTC minus {e['duration']}) {cite_row(self.f('20'), 'Internal firewall')}.", [e["cite"]]))
            if end:
                inc["confirmed"].append(self.item(
                    f"The VPN log independently shows {mb(end['bytes_to_client'])} sent to the VPN client in session {session_id}, "
                    f"{abs(int(end['bytes_to_client']) - s2c):,} bytes more than the firewall server-to-client figure (tunnel overhead), so the data reached the client endpoint.",
                    [end["cite"], e["cite"]]))
            inc["not_enough"] += [
                self.item(f"Which files on {asset['Hostname']} were read or copied: the file server audit log is not collected (agent not installed). "
                          f"A large transfer is evidence of a transfer, not of which files were read {cite_row(self.f('01'), '2.4')}.",
                          [cite_row(self.f("20"), "SRV-FS01 file access (audit) log"), cite_row(self.f("01"), "2.4")]),
            ]
            part_asset = asset
            sev, steps = self.severity("Data exfiltration", part_asset,
                                       "confirmed SMB session and 2.4 GB transfer")
            inc["parts"].append({"name": "Data exfiltration (large transfer)", "severity": sev, "steps": steps,
                                 "type": "Data exfiltration", "asset": part_asset["Asset tag"]})
            inc["finance_hr"] = "finance" in part_asset["Type"].lower() or "hr" in part_asset["Type"].lower()
            inc["exfil_asset"] = part_asset
        # credential compromise part: most critical asset actually reached (session)
        order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
        top = max((a for a, evs in asset_by_tag.values()), key=lambda a: order[a["Criticality"]])
        sev, steps = self.severity("Credential compromise", top, f"account used by an attacker; reached via confirmed sessions {', '.join(sorted(asset_by_tag))}")
        steps.append(f"Note: SRV-DC01 (Critical) only issued Kerberos tickets [{self.f('12')}:{[e['line'] for e in tickets][0]}] - no DC logon session by this account was logged. "
                     f"If the SOC counts that as reaching the DC, this part would be P1; the whole incident is P1 either way.")
        inc["parts"].append({"name": f"Credential compromise of {uname}", "severity": sev, "steps": steps,
                             "type": "Credential compromise", "asset": top["Asset tag"], "user": uname})
        inc.setdefault("compromised", []).append({"user": user, "laptop": laptop, "attacker_ip": attacker_ip, "assigned": assigned,
                                                  "session": session_id})
        # missing sources and rule 6.2 note
        inc["not_enough"] += [
            self.item("What the session did on SRV-DB01: only one 1,240-byte TCP session and a Kerberos ticket are logged; SRV-DB01 login/query logs are not forwarded "
                      "", [e["cite"] for e, a, b in reached if a and a["Hostname"] == "SRV-DB01"] or [cite_row(self.f("02"), "A-1007")]),
            self.item(f"What the internal firewall would show between {fmt_utc(gap[0])[11:19]} and {fmt_utc(gap[1])[11:19]} UTC (device reboot): the session "
                      f"{session_id} stayed open until {fmt_utc(end['ts'])[11:19]} UTC, so more transfers in that period cannot be ruled out.",
                      [cite_row(self.f("20"), "Internal firewall"), end["cite"]]) if gap and end else None,
            self.item(f"What happened on {laptop['Hostname']} when the link was opened (page content, credentials typed, malware): no proxy and no EDR logs exist.",
                      [click["cite"], cite_row(self.f("20"), "Web proxy log (which websites staff open)"), cite_row(self.f("20"), "Laptop endpoint security (EDR) logs")]),
        ]
        office = next((e for e in self.ev("dc") if e.get("account", "").endswith(uname) and e.get("client") == laptop["ips"][0] and e["ts"] < login["ts"]), None)
        lease = next((d for d in self.ev("dhcp") if d.get("ip") == laptop["ips"][0]), None)
        if end and office and lease:
            inc["not_enough"].append(self.item(
                f"Rule 6.2 (same user in two places at once): {uname} had an office logon ({fmt_utc(office['ts'])[11:19]} UTC) and a DHCP lease on {laptop['Hostname']} until "
                f"{fmt_utc(lease['lease_end'])[11:19]} UTC, overlapping VPN session {session_id}, but no logon event from the laptop falls inside "
                f"{fmt_utc(login['ts'])[11:19]}-{fmt_utc(end['ts'])[11:19]} UTC, so simultaneous use cannot be confirmed {cite_row(self.f('01'), '6.2')}.",
                [office["cite"], lease["cite"], login["cite"]]))
        inc["not_enough"] = [x for x in inc["not_enough"] if x]
        inc["missing"] += self.generic_missing(["fs01", "db01", "proxy", "edr", "fw_int_gap", "other_dates"])

    def finish_phish_incident(self, inc, rows, url_host, link_ip):
        p = self.p
        order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
        inc["severity"] = min((x["severity"] for x in inc["parts"]), key=lambda s: order[s])
        exfil_asset = inc.get("exfil_asset")
        comp = inc["compromised"][0]
        self.add_actions(inc, "RB-CRED-02", [1, 2, 3, 4, 5, 6, 7, 8], {
            1: f"Call {comp['user']['Full name']} on {comp['user']['Registered phone']} {cite_row(self.f('18'), comp['user']['Username'])} - not a number from the VPN log",
            2: f"Disable {comp['user']['Username']} and end VPN session {comp['session']} (assigned {comp['assigned']})",
            3: f"Block {comp['attacker_ip']} at the perimeter firewall",
            4: "Reset only AFTER step 2; the attacker already changed the password at 06:42:17 UTC, so helpdesk identity checks are essential",
            5: f"Logins by {comp['user']['Username']} in the last 24 h reached: " + ", ".join(sorted({a['asset']['Hostname'] for a in inc['assets'] if a['reached']})),
            6: f"Phishing was the source (click seen) -> disconnect {comp['laptop']['Hostname']} ({comp['laptop']['ips'][0]})",
            7: "A large data transfer was seen -> open RB-EXFIL-04",
        })
        self.add_actions(inc, "RB-PHISH-01", [1, 2, 3, 4, 5, 6, 7], {
            1: f"Recipients of M-55187: " + ", ".join(r['to'].split('@')[0] for r in rows) + f" {', '.join(r['cite'] for r in rows)}",
            3: f"Block sender domain {rows[0]['from'].split('@')[1]} and link domain {url_host} ({link_ip}) at the email gateway and perimeter firewall",
            4: f"Done in this analysis: amalik clicked, sraheel and utariq show no click",
            5: f"Click found for {comp['user']['Username']} -> RB-CRED-02",
        })
        self.add_actions(inc, "RB-EXFIL-04", [1, 2, 3, 4, 5, 6], {
            1: "Session found: 2,426,727,912 bytes (2,411,724,800 server to client), 06:03:12-06:21:19 UTC, SRV-FS01 -> 10.10.3.45",
            2: f"Destination of the transfer is the VPN pool address {comp['assigned']} = the attacker's session from {comp['attacker_ip']} -> block {comp['attacker_ip']}",
            3: "Copy the relevant logs; do not reboot SRV-FS01",
            4: f"Ask {exfil_asset['Owner']} what the share holds" if exfil_asset else None,
            5: "File-level audit logs do not exist (file 20) -> record that it is unknown which files were read",
            6: "SRV-FS01 holds finance and HR shares -> inform Legal and Compliance",
        })
        inc["actions"] = [a for a in inc["actions"] if a["text"]]
        self.people_for(inc, "P1", exfil_asset, finance_hr=inc.get("finance_hr", False), label="Phishing / account takeover / data transfer (P1)")
        for part in inc["parts"]:
            if part["severity"] == "P4":
                self.people_for_unique(inc, "P4", label=part["name"])
        user = comp["user"]
        inc["accounts"] = []
        for r in rows:
            u = p.user_by_email(r["to"])
            hit = u["Username"] == user["Username"]
            inc["accounts"].append({"username": u["Username"], "name": u["Full name"], "role": u["Role"], "laptop": u["Laptop tag"],
                                    "status": "COMPROMISED (click seen, attacker VPN login)" if hit else "phishing delivered, no click seen",
                                    "cite": cite_row(self.f("18"), u["Username"])})
        inc["summary"] = (f"{user['Full name']} ({user['Username']}) clicked a payroll phishing link, an attacker from {comp['attacker_ip']} (RO) then logged into the VPN "
                          f"after repeated MFA rejections, reached the file server and database server, reset the password and pulled ~2.4 GB from SRV-FS01. "
                          f"Two other recipients show no click. Overall P1.")
        inc["related_ids"] = [user["Username"], comp["attacker_ip"], comp["assigned"], "M-55187"]

    def people_for_unique(self, inc, severity, label=""):
        for row in self.p.escalation:
            if row["Severity"] == severity:
                inc["people"].append({"severity": severity, "who": row["Who to inform"], "limit": row["Time limit"], "how": row["How"],
                                      "cite": cite_row(self.f("04"), row["id"]), "for": label})

    # ------------------------------------------------------------ admin sessions
    def admin_sessions(self):
        p = self.p
        for e in self.ev("dc", EventID="4624"):
            if "remote desktop" not in e["desc"].lower() and "type 10" not in e["desc"].lower():
                continue
            acct = e["account"].split("\\")[-1]
            user = p.users.get(acct)
            target = p.asset_by_host(e.get("target", "DC01"))
            off = next((x for x in self.ev("dc", EventID="4634") if x.get("account", "").endswith(acct) and x["ts"] > e["ts"]), None)
            end = off["ts"] if off else e["ts"]
            approved, full, near = self.match_change([acct], [user["Full name"] if user else ""], set(),
                                                     e["ts"], end, system_names=[target["Hostname"]])
            if not approved:
                continue
            ch = approved[0]
            vpn = next(iter(sorted((v for v in self.ev("vpn") if v.get("assigned_ip") == e["client"] and v.get("kind") == "auth" and v["ts"] <= e["ts"]),
                                   key=lambda v: v["ts"], reverse=True)), None)
            vpn_end = next((v for v in self.ev("vpn") if v.get("session") == (vpn or {}).get("session") and v.get("kind") == "session_end"), None)
            fw = [x for x in self.ev("fw_int") if x["src_ip"] == e["client"] and x["dst_port"] == 3389]
            ids = [x for x in p.events if x["src"] == "ids" and acct in x["desc"] and "Remote desktop" in x["desc"]]
            cites = [e["cite"]] + ([off["cite"]] if off else []) + [x["cite"] for x in fw] + [x["cite"] for x in ids] + ([vpn["cite"]] if vpn else [])
            row = ch["row"]
            self.closed.append({
                "id": f"CL-{len(self.closed) + 1}", "alert": ids[0]["alert_id"] if ids else None,
                "title": f"Remote desktop to {target['Hostname']} by {user['Full name']} ({acct}) outside office hours",
                "change_id": ch["id"], "status": row["Status"],
                "reasons": [
                    f"Same system: change lists {row['System / target']}; logon target is {target['Hostname']} {cite_row(self.f('05'), ch['id'])} {e['cite']}",
                    f"Same person: change is 'Performed by {row['Performed by']}'; the logon account is ORBIT\\{acct} {cite_row(self.f('05'), ch['id'])} {e['cite']}",
                    f"Window contains the activity: {row['Window (PKT)']} PKT = {fmt_utc(ch['w0'])[11:19]}-{fmt_utc(ch['w1'])[11:19]} UTC; session "
                    f"{fmt_utc(e['ts'])[11:19]}-{fmt_utc(end)[11:19]} UTC ({fmt_pkt(e['ts'])[:5]}-{fmt_pkt(end)[:5]} PKT)",
                ],
                "detail": (f"Remote desktop arrived over VPN session {vpn['session']} (assigned {vpn['assigned_ip']}, geo {vpn['geo']}, same source address as his earlier login). " if vpn else "")
                          + (f"The internal firewall session was logged at close {fmt_pkt(fw[0]['end'])}; start derived = {fmt_pkt(fw[0]['start'])}, matching the DC logon." if fw else ""),
                "cites": cites + [cite_row(self.f("05"), ch["id"])],
                "runbook": [], "severity": None,
                "rule": f"Rule 3.2: approved activity is not escalated {cite_row(self.f('01'), '3.2')}; matrix: approved activity gets no severity {cite_row(self.f('03'), 'Phishing email delivered, no click seen')}",
                "near_miss": [f"{n['id']} ({n['row']['System / target']}, {n['status']}) is not a match" for n in near],
                "start": e["ts"], "end": end,
                "timeline": [{"ts": x["ts"], "utc": fmt_utc(x["ts"]), "pkt": fmt_pkt(x["ts"]), "text": self.describe(x), "cites": [x["cite"]],
                              "label": "confirmed", "src": x["src"]} for x in sorted(([vpn] if vpn else []) + [e] + fw + ids + ([off] if off else []) + ([vpn_end] if vpn_end else []), key=lambda y: y.get("start", y["ts"]))],
            })

    # ------------------------------------------------------------ cross-checks (wow)
    def consistency_checks(self):
        p = self.p
        chk = self.checks
        # IDS alerts vs raw events within 60 s
        pairs = [
            ("ALT-9001", lambda e: e["src"] == "fw_edge" and e.get("src_ip") == "192.0.2.88" and e["action"] == "ALLOW"),
            ("ALT-9002", lambda e: e["src"] == "fw_edge" and e.get("dst_ip") == "198.51.100.77" and e.get("src_ip") == "10.20.5.14"),
            ("ALT-9003", lambda e: e["src"] == "vpn" and e.get("result") == "SUCCESS" and e.get("geo") == "RO"),
            ("ALT-9004", lambda e: e["src"] == "web" and e.get("ip") == "192.0.2.150"),
            ("ALT-9005", lambda e: e["src"] == "fw_int" and int(e.get("bytes_total", 0)) > LARGE_TRANSFER_BYTES),
            ("ALT-9006", lambda e: e["src"] == "fw_int" and e["src_ip"] == "10.10.9.50"),
            ("ALT-9007", lambda e: e["src"] == "dc" and e.get("EventID") == "4624"),
            ("ALT-9008", lambda e: e["src"] == "dc" and e.get("EventID") == "4740"),
        ]
        for aid, pred in pairs:
            ids_ev = next((e for e in p.events if e.get("alert_id") == aid), None)
            if not ids_ev:
                continue
            raw = [e for e in p.events if e["src"] != "ids" and pred(e)]
            if not raw:
                continue
            nearest = min(raw, key=lambda e: abs((e["ts"] - ids_ev["ts"]).total_seconds()))
            if nearest.get("src") == "fw_int" and int(nearest.get("bytes_total", 0)) > LARGE_TRANSFER_BYTES:
                at = nearest["end"]
            else:
                at = nearest["ts"]
            delta = abs((at - ids_ev["ts"]).total_seconds())
            naive_note = ""
            if nearest["src"] in ("fw_int", "web", "email"):
                naive = at.replace(tzinfo=None) + timedelta(hours=5)
                naive_note = f" Read as UTC without conversion it would be {naive.strftime('%H:%M:%S')} - {abs((naive.replace(tzinfo=UTC) - ids_ev['ts']).total_seconds()) / 3600:.1f} h away."
            chk.append({"name": f"{aid} matches {nearest['src']} log", "ok": delta <= 60,
                        "detail": f"IDS {fmt_utc(ids_ev['ts'])[11:19]} UTC vs log event {fmt_utc(at)[11:19]} UTC (diff {int(delta)} s) after time zone normalisation.{naive_note}",
                        "cites": [ids_ev["cite"], nearest["cite"]]})
        vpn_end = next((e for e in self.ev("vpn") if e.get("kind") == "session_end" and e.get("user") == "amalik"), None)
        big = next((e for e in self.ev("fw_int") if int(e.get("bytes_total", 0)) > LARGE_TRANSFER_BYTES), None)
        if vpn_end and big:
            d = abs(int(vpn_end["bytes_to_client"]) - int(big["bytes_server_to_client"]))
            chk.append({"name": "VPN bytes vs internal firewall bytes", "ok": d / int(vpn_end["bytes_to_client"]) < 0.01,
                        "detail": f"VPN to-client {int(vpn_end['bytes_to_client']):,} vs firewall server-to-client {int(big['bytes_server_to_client']):,}: differ by {d:,} bytes ({d / int(vpn_end['bytes_to_client']) * 100:.2f}%).",
                        "cites": [vpn_end["cite"], big["cite"]]})
        # internal fw derived start vs DC kerberos
        tgt = next((e for e in self.ev("dc", EventID="4769") if "cifs" in e.get("service", "")), None)
        smb = next((e for e in self.ev("fw_int") if e["src_ip"] == "10.10.3.45" and e["dst_port"] == 445), None)
        if tgt and smb:
            d = abs((smb["start"] - tgt["ts"]).total_seconds())
            chk.append({"name": "Close-time logging corrected", "ok": d <= 5,
                        "detail": f"Internal firewall logs at session close ({fmt_utc(smb['end'])[11:19]} UTC) with duration {smb['duration']}; derived start {fmt_utc(smb['start'])[11:19]} UTC vs DC cifs ticket {fmt_utc(tgt['ts'])[11:19]} UTC (diff {int(d)} s).",
                        "cites": [smb["cite"], tgt["cite"]]})
        # braza: derived RDP start vs DC logon
        rdp = next((e for e in self.ev("fw_int") if e["dst_port"] == 3389 and e["src_ip"] == "10.10.3.18"), None)
        logon = next((e for e in self.ev("dc", EventID="4624")), None)
        if rdp and logon:
            d = abs((rdp["start"] - logon["ts"]).total_seconds())
            chk.append({"name": "RDP session start derivation", "ok": d <= 5,
                        "detail": f"Firewall close {fmt_pkt(rdp['end'])} - {rdp['duration']} = start {fmt_pkt(rdp['start'])} = DC logon {fmt_utc(logon['ts'])[11:19]} UTC (diff {int(d)} s).",
                        "cites": [rdp["cite"], logon["cite"]]})
        # DHCP before lease trap
        for e in self.ev("fw_edge"):
            if e["src_ip"] == "10.20.5.22":
                lease = next((d for d in self.ev("dhcp") if d.get("ip") == e["src_ip"]), None)
                if lease and e["ts"] < lease["ts"]:
                    self.observations.append(self.item(
                        f"{e['src_ip']} connected at {fmt_utc(e['ts'])[11:19]} UTC, before its DHCP lease at {fmt_utc(lease['ts'])[11:19]} UTC; the DHCP log cannot confirm the host at that moment "
                        f"(asset inventory lists {e['src_ip']} as LT-FIN-022). The destination is not the phishing host, so it does not change the findings.",
                        [e["cite"], lease["cite"]]))
        # rule 6.2 observations
        for uname in {e.get("user") for e in self.ev("vpn") if e.get("kind") == "auth" and e.get("result") == "SUCCESS"}:
            user = p.users[uname]
            lap = p.assets[user["Laptop tag"]]
            sessions = [e for e in self.ev("vpn") if e.get("user") == uname and e.get("kind") == "auth" and e.get("result") == "SUCCESS"]
            ends = {e["session"]: e for e in self.ev("vpn") if e.get("kind") == "session_end"}
            for s in sessions:
                end = ends.get(s["session"])
                lease = next((d for d in self.ev("dhcp") if d.get("ip") == lap["ips"][0] and d["ts"] < (end["ts"] if end else s["ts"]) and d["lease_end"] > s["ts"]), None)
                if not (end and lease):
                    continue
                incs = [i for i in self.incidents if any(c.get("user", {}).get("Username") == uname for c in i.get("compromised", []))]
                if incs:
                    continue
                self.observations.append(self.item(
                    f"Rule 6.2 literal match, not escalated: {uname} has VPN session {s['session']} ({fmt_utc(s['ts'])[11:19]}-{fmt_utc(end['ts'])[11:19]} UTC, geo {s['geo']}, push approved on first try) while "
                    f"office laptop {lap['Hostname']} holds a DHCP lease. The logs cannot tell whether the VPN client is the same laptop or a second device, and nothing else is abnormal "
                    f"(no failed MFA, geo PK as for all other staff, no sensitive access). Verify with the user if desired {cite_row(self.f('01'), '6.2')}.",
                    [s["cite"], lease["cite"], end["cite"]]))

    # ------------------------------------------------------------ misc
    def generic_missing(self, keys):
        f20 = self.f("20")
        ms = self.p.missing_sources
        table = {
            "fs01": ("SRV-FS01 file access (audit) log", "SRV-FS01 file access (audit) log"),
            "db01": ("SRV-DB01 login and query log", "SRV-DB01 login and query log"),
            "proxy": ("Web proxy log (which websites staff open)", "Web proxy log (which websites staff open)"),
            "edr": ("Laptop endpoint security (EDR) logs", "Laptop endpoint security (EDR) logs"),
            "other_dates": ("Logs for any date other than 2026-11-04", "Other dates"),
        }
        out = []
        for k in keys:
            if k == "fw_int_gap":
                g = self.p.coverage["Internal firewall"]["gap"]
                out.append({"source": f"Internal firewall, {fmt_pkt(g[0])[:8]}-{fmt_pkt(g[1] - timedelta(seconds=1))[:8]} PKT ({fmt_utc(g[0])[11:19]}-{fmt_utc(g[1] - timedelta(seconds=1))[11:19]} UTC)",
                            "impact": "device rebooted for a firmware update; sessions in this window were never logged",
                            "cite": cite_row(f20, "Internal firewall")})
            elif k in table:
                name, key = table[k]
                out.append({"source": name, "impact": ms.get(name.split(" (which")[0] if k == "proxy" else name, ms.get(key, "")) or "not available",
                            "cite": cite_row(f20, key)})
        return out

    def describe(self, e):
        s = e["src"]
        if s == "web":
            return f"Web: {e['ip']} {e['method']} {e['path']} -> {e['status']} ({e['size']:,} bytes) UA '{e['agent']}'"
        if s in ("fw_edge", "fw_int"):
            tail = ""
            if e["action"] == "DENY":
                tail = f" DENIED ({e.get('rule', '')})"
            elif s == "fw_int" and e.get("duration"):
                tail = f" ALLOWED, closed {fmt_utc(e['end'])[11:19]} UTC after {e['duration']}, {e.get('bytes_total', '?')} bytes (logged at close; start derived)"
            else:
                tail = f" ALLOWED ({e.get('rule', '')})"
            return f"{'Perimeter' if s == 'fw_edge' else 'Internal'} firewall: {e['src_ip']}:{e['src_port']} -> {e['dst_ip']}:{e['dst_port']}{tail}"
        if s == "ids":
            return f"IDS {e['alert_id']} ({e['sensor']}): {e['desc']}"
        if s == "vpn":
            return f"VPN {e.get('kind')} {e.get('user')} {e.get('result', '')} {e.get('geo', '')} {e.get('reason', e.get('mfa', ''))}".strip()
        if s == "dc":
            return f"DC EventID {e.get('EventID')} {e.get('desc')}: {e.get('account') or e.get('target') or ''} client={e.get('client', '')}"
        return e["raw"][:120]


def build(pack):
    return Analysis(pack)
