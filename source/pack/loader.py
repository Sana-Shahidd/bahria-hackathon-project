"""
Loader for the Problem C data pack (Orbit Logistics, 20 files).

Everything the assistant knows comes from these files. Each fact keeps the
citation it came from:
  * log files   -> file name + line number (line 1 = first line inside the code block)
  * table files -> file name + row ID (alert ID, asset tag, change ID, username ...)
  * runbooks    -> file name + step number
Times are normalised to UTC using the rules in file 20 (log source coverage sheet).
"""
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

UTC = timezone.utc
PKT = timezone(timedelta(hours=5))
KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse_kv(text):
    out = {}
    for key, value in KV_RE.findall(text):
        out[key] = value.strip('"')
    return out


def fmt_utc(dt):
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_pkt(dt):
    return dt.astimezone(PKT).strftime("%H:%M:%S PKT")


def fmt_both(dt):
    return f"{fmt_utc(dt)} ({fmt_pkt(dt)})"


# ---------------------------------------------------------------- citations

def cite_line(file, n):
    return f"[{file}:{n}]"


def cite_row(file, row_id):
    return f"[{file}#{row_id}]"


CITE_RE = re.compile(r"\[(\d\d_[A-Za-z0-9_]+\.md)(?::(\d+)|#([^\]]+))\]")


class Pack:
    def __init__(self, directory):
        self.dir = directory
        self.files = {}          # name -> full text
        self.code_lines = {}     # name -> [lines inside code block]
        self.tables = {}         # name -> {"header": [...], "rows": [dict]}
        self.events = []         # every parsed log event, time-sorted later
        self.by_file = {}        # name -> [event]
        self._load()

    # ------------------------------------------------------------- basics
    def _load(self):
        names = sorted(n for n in os.listdir(self.dir) if re.match(r"\d\d_.*\.md$", n))
        for name in names:
            with open(os.path.join(self.dir, name), "r", encoding="utf-8") as fh:
                text = fh.read()
            self.files[name] = text
            self.code_lines[name] = self._code_block(text)
            self.tables[name] = self._table(text)
        self._parse_reference()
        self._parse_logs()

    def file(self, prefix):
        for name in self.files:
            if name.startswith(prefix):
                return name
        raise KeyError(prefix)

    @staticmethod
    def _code_block(text):
        lines, inside = [], False
        for line in text.splitlines():
            if line.strip().startswith("```"):
                if inside:
                    break
                inside = True
                continue
            if inside:
                lines.append(line)
        return lines

    @staticmethod
    def _table(text):
        rows = [l.strip() for l in text.splitlines() if l.strip().startswith("|")]
        if len(rows) < 2:
            return {"header": [], "rows": []}
        split = lambda l: [c.strip() for c in l.strip().strip("|").split("|")]
        header = split(rows[0])
        out = []
        for line in rows[2:]:
            cells = split(line)
            cells += [""] * (len(header) - len(cells))
            out.append(dict(zip(header, cells)))
        return {"header": header, "rows": out}

    # ------------------------------------------------------------- reference tables
    def _parse_reference(self):
        f = self.file
        self.assets = {r["Asset tag"]: r for r in self.tables[f("02")]["rows"]}
        for tag, a in self.assets.items():
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", a["IP address"])
            a["ips"] = ips
            a["_file"] = f("02")
        self.users = {r["Username"]: r for r in self.tables[f("18")]["rows"]}
        self.changes = {r["Change ID"]: r for r in self.tables[f("05")]["rows"]}
        self.ids_alerts = {r["Alert ID"]: r for r in self.tables[f("17")]["rows"]}
        self.coverage_rows = {r["Source"]: r for r in self.tables[f("20")]["rows"]}

        # severity matrix: id = incident type without the bracketed hint
        self.matrix = {}
        for r in self.tables[f("03")]["rows"]:
            key = re.sub(r"\s*\(.*\)", "", r["Incident type"]).strip()
            self.matrix[key] = {"label": r["Incident type"], "Low": r["Low"], "Medium": r["Medium"],
                                "High": r["High"], "Critical": r["Critical"]}

        # escalation rows: id = severity + "-" + who (before " - ")
        self.escalation = []
        for r in self.tables[f("04")]["rows"]:
            who = r["Who to inform"]
            role = who.split(" - ")[0].strip()
            r = dict(r)
            r["id"] = f"{r['Severity']}-{role}"
            r["role"] = role
            self.escalation.append(r)

        # security rules: "2.1 text"
        self.rules = {}
        for line in self.files[f("01")].splitlines():
            m = re.match(r"^(\d+\.\d+)\s+(.*)$", line)
            if m:
                self.rules[m.group(1)] = m.group(2).replace("**", "")

        # runbooks
        self.runbooks = {}
        for name in self.files:
            if "_runbook_" in name:
                text = self.files[name]
                m = re.search(r"Runbook (RB-[A-Z]+-\d+) - (.*)", text)
                steps = {int(n): s for n, s in re.findall(r"(?m)^(\d+)\. (.*)$", text)}
                self.runbooks[m.group(1)] = {"id": m.group(1), "title": m.group(2).strip(),
                                             "file": name, "steps": steps}

        self._parse_coverage()
        self.missing_sources = {}
        for line in self.files[f("20")].splitlines():
            m = re.match(r"^- (.*?):\s*(.*)$", line)
            if m:
                self.missing_sources[m.group(1).strip()] = m.group(2).strip()
            elif line.startswith("- No logs of any kind"):
                self.missing_sources["Other dates"] = line[2:].strip()

    def _parse_coverage(self):
        """Covered intervals (UTC) for 2026-11-04 per source, read from file 20."""
        day = datetime(2026, 11, 4, tzinfo=UTC)
        self.coverage = {}
        for source, row in self.coverage_rows.items():
            cov = row["Coverage on 2026-11-04"]
            intervals = [(day, day + timedelta(days=1))]
            m = re.search(r"(\d\d:\d\d)\s+to\s+(\d\d:\d\d)\s+UTC only", cov)
            if m:
                intervals = [(self._at(day, m.group(1)), self._at(day, m.group(2)))]
            m = re.search(r"except\s+(\d\d:\d\d:\d\d)\s+to\s+(\d\d:\d\d:\d\d)\s+PKT", cov)
            gap = None
            if m:
                g0 = self._at(day, m.group(1)) - timedelta(hours=5)
                g1 = self._at(day, m.group(2)) - timedelta(hours=5)
                gap = (g0, g1 + timedelta(seconds=1))
                intervals = [(day, g0), (g1 + timedelta(seconds=1), day + timedelta(days=1))]
            self.coverage[source] = {"intervals": intervals, "gap": gap, "text": cov,
                                     "file": row["File"], "tz": row["Time zone / format"],
                                     "notes": row["Notes"]}

    @staticmethod
    def _at(day, hhmm):
        parts = [int(p) for p in hhmm.split(":")]
        while len(parts) < 3:
            parts.append(0)
        return day.replace(hour=parts[0], minute=parts[1], second=parts[2])

    # ------------------------------------------------------------- logs
    def _add(self, file, line, src, ts, raw, **fields):
        ev = {"file": file, "line": line, "src": src, "ts": ts, "raw": raw, "start": ts, "end": ts,
              "cite": cite_line(file, line), **fields}
        self.events.append(ev)
        self.by_file.setdefault(file, []).append(ev)
        return ev

    def _parse_logs(self):
        f = self.file
        for n, raw in enumerate(self.code_lines[f("11")], 1):
            m = re.match(r"^(\S+Z)\s+(\S+)\s+(auth|session_end)\s+(.*)$", raw)
            if not m:
                continue
            ts = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            self._add(f("11"), n, "vpn", ts, raw, kind=m.group(3), **parse_kv(m.group(4)))

        for n, raw in enumerate(self.code_lines[f("12")], 1):
            parts = [p.strip() for p in raw.split(" | ")]
            ts = datetime.strptime(parts[0].replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            kv = {}
            for p in parts[2:]:
                kv.update(parse_kv(p))
            self._add(f("12"), n, "dc", ts, raw, desc=parts[3] if len(parts) > 3 else "", **kv)

        web_re = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d+) (\d+) "[^"]*" "([^"]*)"')
        for n, raw in enumerate(self.code_lines[f("13")], 1):
            m = web_re.match(raw)
            if not m:
                continue
            ts = datetime.strptime(m.group(2), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
            self._add(f("13"), n, "web", ts, raw, ip=m.group(1), method=m.group(3), url=m.group(4),
                      path=unquote(m.group(4)), status=int(m.group(5)), size=int(m.group(6)), agent=m.group(7))

        fw_re = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\S+) (ALLOW|DENY) (\w+) ([\d.]+):(\d+) -> ([\d.]+):(\d+)\s*(.*)$")
        for key, tz, src in (("14", UTC, "fw_edge"), ("15", PKT, "fw_int")):
            for n, raw in enumerate(self.code_lines[f(key)], 1):
                m = fw_re.match(raw)
                if not m:
                    continue
                logged = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz).astimezone(UTC)
                kv = parse_kv(m.group(9))
                ev = self._add(f(key), n, src, logged, raw, action=m.group(3), proto=m.group(4),
                               src_ip=m.group(5), src_port=int(m.group(6)), dst_ip=m.group(7),
                               dst_port=int(m.group(8)), **kv)
                ev["logged"] = logged
                if src == "fw_int" and "duration" in kv:
                    # internal firewall logs when the session CLOSES; start = close - duration
                    ev["start"] = logged - timedelta(seconds=int(kv["duration"].rstrip("s")))
                    ev["end"] = logged
                else:
                    ev["start"] = logged
                    ev["end"] = logged

        mail_re = re.compile(r"^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) PKT\]\s+(.*)$")
        for n, raw in enumerate(self.code_lines[f("16")], 1):
            m = mail_re.match(raw)
            if not m:
                continue
            ts = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=PKT).astimezone(UTC)
            kv = parse_kv(m.group(2))
            self._add(f("16"), n, "email", ts, raw, **kv)

        dh_re = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) ([+-]\d\d:\d\d) (\w+) (.*)$")
        for n, raw in enumerate(self.code_lines[f("19")], 1):
            m = dh_re.match(raw)
            if not m:
                continue
            ts = datetime.strptime(m.group(1) + m.group(2).replace(":", ""), "%Y-%m-%d %H:%M:%S%z").astimezone(UTC)
            kv = parse_kv(m.group(4))
            lease_h = int(re.sub(r"\D", "", kv.get("lease", "0")) or 0)
            self._add(f("19"), n, "dhcp", ts, raw, kind=m.group(3), lease_end=ts + timedelta(hours=lease_h), **kv)

        for alert_id, row in self.ids_alerts.items():
            ts = datetime.strptime(row["Time raised"].replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            ev = {"file": f("17"), "line": None, "src": "ids", "ts": ts, "raw": row["Description"],
                  "start": ts, "end": ts, "cite": cite_row(f("17"), alert_id), "alert_id": alert_id, "sensor": row["Sensor"],
                  "desc": row["Description"]}
            self.events.append(ev)
            self.by_file.setdefault(f("17"), []).append(ev)

        self.events.sort(key=lambda e: e["ts"])

    # ------------------------------------------------------------- lookups
    def asset_by_ip(self, ip):
        for tag, a in self.assets.items():
            if ip in a["ips"]:
                return a
        return None

    def asset_by_host(self, host):
        host = host.split(".")[0].upper()
        for a in self.assets.values():
            if a["Hostname"].upper() == host or a["Hostname"].upper().replace("SRV-", "") == host:
                return a
        return None

    def user_by_email(self, email):
        for u in self.users.values():
            if u["Email"].lower() == email.lower():
                return u
        return None

    def row_cite(self, file_prefix, row_id):
        return cite_row(self.file(file_prefix), row_id)

    def runbook_cite(self, rb_id, step):
        rb = self.runbooks[rb_id]
        return f"{rb_id} step {step} [{rb['file']}#step{step}]"

    def dhcp_host(self, ip, at):
        """Host holding `ip` at time `at` according to the DHCP log (None if not covered)."""
        best = None
        for e in self.by_file.get(self.file("19"), []):
            if e.get("ip") == ip and e["ts"] <= at <= e["lease_end"]:
                best = e
        return best

    # ------------------------------------------------------------- citation checking
    def verify_cite(self, file, line=None, row=None):
        if file not in self.files:
            return False
        if line is not None:
            lines = self.code_lines.get(file) or []
            return 1 <= int(line) <= len(lines)
        row = row.strip()
        t = self.tables.get(file, {}).get("rows", [])
        ids = set()
        for r in t:
            for k in ("Alert ID", "Asset tag", "Change ID", "Username"):
                if k in r:
                    ids.add(r[k])
            if "Incident type" in r:
                ids.add(re.sub(r"\s*\(.*\)", "", r["Incident type"]).strip())
            if "Source" in r and "File" in r:
                ids.add(r["Source"])
        if file == self.file("20"):
            ids |= set(self.missing_sources)
        if file == self.file("04"):
            ids |= {e["id"] for e in self.escalation}
        if file == self.file("01"):
            ids |= set(self.rules)
        m = re.match(r"step(\d+)$", row)
        if m:
            for rb in self.runbooks.values():
                if rb["file"] == file:
                    return int(m.group(1)) in rb["steps"]
        return row in ids

    def check_text(self, text):
        """Return (total, valid, invalid_list) for every [file:line] / [file#id] citation in text."""
        total, valid, bad = 0, 0, []
        for file, line, row in CITE_RE.findall(text or ""):
            total += 1
            if self.verify_cite(file, line or None, row or None):
                valid += 1
            else:
                bad.append(f"{file}:{line}" if line else f"{file}#{row}")
        return total, valid, bad

    def resolve_cite(self, file, line=None, row=None):
        """Return the source text behind a citation (for click-to-view)."""
        if file not in self.files:
            return None
        if line is not None:
            lines = self.code_lines.get(file) or []
            n = int(line)
            return lines[n - 1] if 1 <= n <= len(lines) else None
        row = row.strip()
        m = re.match(r"step(\d+)$", row)
        if m:
            for rb in self.runbooks.values():
                if rb["file"] == file:
                    return f"{rb['id']} step {m.group(1)}: {rb['steps'].get(int(m.group(1)))}"
        if file == self.file("20") and row in self.missing_sources:
            return f"Not collected: {row} - {self.missing_sources[row]}"
        if file == self.file("01") and row in self.rules:
            return f"{row} {self.rules[row]}"
        if file == self.file("04"):
            for e in self.escalation:
                if e["id"] == row:
                    return " | ".join(f"{k}: {v}" for k, v in e.items() if k in ("Severity", "Who to inform", "Time limit", "How"))
        if file == self.file("03") and row in self.matrix:
            r = self.matrix[row]
            return " | ".join(f"{k}: {r[k]}" for k in ("label", "Low", "Medium", "High", "Critical"))
        for r in self.tables.get(file, {}).get("rows", []):
            for k in ("Alert ID", "Asset tag", "Change ID", "Username", "Source"):
                if r.get(k) == row:
                    return " | ".join(f"{h}: {v}" for h, v in r.items())
        return None


_cache = {}


def get_pack(directory):
    key = os.path.abspath(directory)
    if key not in _cache:
        _cache[key] = Pack(key)
    return _cache[key]
