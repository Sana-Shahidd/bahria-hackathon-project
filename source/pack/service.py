"""Cached access to the pack + JSON serialisation for the UI."""
import os
import threading

from config import PACK_DIR
from pack.loader import get_pack, fmt_utc, fmt_pkt, UTC
from pack.analysis import build
from pack import qa
from pack.report import build_markdown

_lock = threading.Lock()
_state = {}


def available():
    return os.path.isdir(PACK_DIR) and any(n.startswith("01_") for n in os.listdir(PACK_DIR))


def get():
    with _lock:
        if "analysis" not in _state:
            pack = get_pack(PACK_DIR)
            _state["pack"], _state["analysis"] = pack, build(pack)
        return _state["pack"], _state["analysis"]


def ask(question):
    pack, analysis = get()
    return qa.answer(pack, analysis, question)


def looks_like_pack_question(question):
    if not available():
        return False
    pack, _ = get()
    return qa.matches(pack, question)


def report_markdown(incident_id=None):
    pack, analysis = get()
    return build_markdown(analysis, incident_id)


def _minute(dt):
    return dt.hour * 60 + dt.minute + dt.second / 60


def _graph(analysis):
    """Attack-path graph for the account-takeover incident (nodes + edges with citations)."""
    inc = next((i for i in analysis.incidents if i.get("compromised")), None)
    if not inc:
        return None
    c = inc["compromised"][0]
    tl = {t["text"][:30]: t for t in inc["timeline"]}
    def first(sub):
        return next((t for t in sorted(inc["timeline"], key=lambda x: x["ts"]) if sub in t["text"]), None)
    mail, click, fail, login = first("Phishing mail"), first("connected to 198"), first("VPN login FAIL"), first("VPN login SUCCESS")
    pw, big, db = first("password was changed") or first("EventID 4724"), first("LARGE TRANSFER"), first("SRV-DB01")
    lock = first("Account locked out")
    nodes = [
        {"id": "mail", "label": "Phishing mail M-55187", "sub": "04:12:07 UTC", "kind": "attacker", "cites": mail["cites"][:1] if mail else []},
        {"id": "click", "label": f"{c['user']['Username']} clicks link", "sub": f"{click['utc'][11:19]} UTC" if click else "", "kind": "victim", "cites": click["cites"][:1] if click else []},
        {"id": "ip", "label": c["attacker_ip"], "sub": "RO - fake page host + VPN source", "kind": "attacker", "cites": login["cites"][:1] if login else []},
        {"id": "vpn", "label": "VPN login (after 4 MFA failures)", "sub": f"{login['utc'][11:19]} UTC -> {c['assigned']}" if login else "", "kind": "attacker", "cites": login["cites"][:1] if login else []},
        {"id": "dc", "label": "SRV-DC01 Kerberos", "sub": "tickets only (Critical)", "kind": "asset", "cites": []},
        {"id": "fs", "label": "SRV-FS01", "sub": "2.4 GB transferred (High)", "kind": "loss", "cites": big["cites"][:1] if big else []},
        {"id": "db", "label": "SRV-DB01", "sub": "1,240-byte session (High)", "kind": "asset", "cites": db["cites"][:1] if db else []},
        {"id": "pw", "label": "Password reset", "sub": "06:42:17 UTC", "kind": "attacker", "cites": pw["cites"][:1] if pw else []},
        {"id": "lock", "label": "Real user locked out", "sub": "07:32:50 UTC", "kind": "victim", "cites": lock["cites"][:1] if lock else []},
    ]
    edges = [["mail", "click"], ["click", "ip"], ["ip", "vpn"], ["vpn", "dc"], ["vpn", "fs"], ["vpn", "db"], ["vpn", "pw"], ["pw", "lock"]]
    return {"nodes": nodes, "edges": edges, "incident": inc["id"]}


def _clean_incident(i):
    def tl(t):
        return {"utc": t["utc"], "pkt": t["pkt"], "min": _minute(t["ts"]), "text": t["text"], "cites": t["cites"], "label": t["label"], "src": t["src"]}
    return {
        "id": i["id"], "title": i["title"], "kind": i["kind"], "severity": i["severity"], "summary": i["summary"],
        "parts": i["parts"], "timeline": [tl(t) for t in sorted(i["timeline"], key=lambda x: x["ts"])],
        "assets": [{"hostname": a["asset"]["Hostname"], "tag": a["asset"]["Asset tag"], "criticality": a["asset"]["Criticality"],
                    "reached": a["reached"], "why": a["why"]} for a in i["assets"]],
        "accounts": i.get("accounts", []),
        "confirmed": i["confirmed"], "suspected": i["suspected"], "not_enough": i["not_enough"], "missing": i["missing"],
        "actions": i["actions"], "people": i["people"],
    }


def analysis_json():
    pack, a = get()
    cov = []
    for name, c in pack.coverage.items():
        cov.append({"source": name, "tz": c["tz"], "text": c["text"], "notes": c["notes"],
                    "intervals": [[_minute(x), 1440 if y.day != x.day else _minute(y)] for x, y in c["intervals"]],
                    "gap": [_minute(c["gap"][0]), _minute(c["gap"][1])] if c["gap"] else None})
    closed = []
    for c in a.closed:
        closed.append({k: c[k] for k in ("id", "alert", "title", "change_id", "status", "reasons", "detail", "rule", "near_miss", "cites")}
                      | {"timeline": [{"utc": t["utc"], "pkt": t["pkt"], "min": _minute(t["ts"]), "text": t["text"], "cites": t["cites"]} for t in c["timeline"]],
                         "start_min": _minute(c["start"]), "end_min": _minute(c["end"])})
    total, valid, bad = pack.check_text(build_markdown(a))
    return {
        "incidents": [_clean_incident(i) for i in a.incidents], "closed": closed,
        "checks": a.checks, "observations": a.observations, "coverage": cov, "graph": _graph(a),
        "citations": {"total": total, "valid": valid, "invalid": bad},
        "files": sorted(pack.files), "events": len(pack.events),
    }


def cite_text(ref):
    pack, _ = get()
    import re
    m = re.match(r"^(\d\d_[A-Za-z0-9_]+\.md)(?::(\d+)|#(.+))$", ref.strip())
    if not m:
        return None
    return pack.resolve_cite(m.group(1), m.group(2), m.group(3))
