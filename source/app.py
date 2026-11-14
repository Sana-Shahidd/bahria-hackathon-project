"""
IncidentPilot web app.

All CyberPulse pages are kept (dashboard, IP lists, blocked IPs, logs, settings).
New: incident queue + detail with AI triage, approve/dismiss, reports,
daily AI briefing and the "Ask Pilot" floating assistant.
"""
import html as html_lib
import secrets
import re
import threading

import markdown as md
from flask import Flask, render_template, request, redirect, session, flash, jsonify, Response, abort, url_for
from werkzeug.security import check_password_hash

import incidents as incident_ops
from ai import llm
from ai.briefing import get_briefing
from ai.chat import answer as pilot_answer
from ai.report import build_report_markdown
from ai.triage import triage_incident, run_pending_triage
from config import (SECRET_KEY, RULES_FILE, DEMO_MODE, AUTO_TRIAGE, AUTO_TRIAGE_INTERVAL_SECONDS,
                    DASHBOARD_HOST_IP)
from firewall import (block_ip_iptables, unblock_ip_iptables, save_blocked_ip_to_file,
                      remove_ip_from_blocked_file, clear_blocked_ip_file, read_blocked_file)
from sniffer import record_brute_force
from ai.tuning import get_threshold_suggestions, apply_suggestion
import log_ingest
from pack import service as pack_service
from pack import seed as pack_seed
from init_db import ensure_schema
import db
from db import (
    get_recent_attacks,
    get_blocked_ips,
    get_ip_list,
    add_ip_to_list,
    delete_ip_from_list,
    delete_blocked_ip,
    save_blocked_ip_to_db,
    save_to_db,
    get_attack_stats,
    get_filtered_attack_logs
)
import os
import ipaddress
import json
import csv
import io
from datetime import datetime


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024   # log uploads up to 20 MB

try:
    ensure_schema()   # upgrade databases created by older versions
    try:
        if os.environ.get("ORBIT_SEED", "true").lower() != "false" and pack_service.available():
            print(f"[ORBIT] loaded {pack_seed.seed()} Orbit incident(s) into the dashboard")
    except Exception as error:   # never block start-up
        print("[ORBIT] seed skipped:", error)
except Exception as _error:
    print("[SCHEMA] check skipped:", _error)


login_attempts = {}


# ---------------------------------------------------------------- CSRF protection
# (new in IncidentPilot; CyberPulse had none). Every POST must carry the session
# token as a form field `csrf_token` or an `X-CSRF-Token` header (added to all
# fetch() calls by _pilot_widget.html).

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def csrf_protect():
    if request.method != "POST" or app.config.get("TESTING_NO_CSRF"):
        return None
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token")
    if not expected or not sent or not secrets.compare_digest(sent, expected):
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"error": "Invalid or missing CSRF token. Reload the page."}), 400
        flash("Your session expired. Please try again.", "error")
        return redirect(request.referrer or "/login")
    return None


app.jinja_env.globals["csrf_token"] = get_csrf_token

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_TIME_WINDOW = 60


def login_required():
    return "user" in session


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_all_blocked_ips_for_reset():
    ip_set = set()

    try:
        db_ips = get_blocked_ips(1000)

        for item in db_ips:
            if len(item) > 1:
                ip_set.add(item[1])
    except Exception as error:
        print("DB blocked IP read error:", error)

    ip_set.update(read_blocked_file())

    return list(ip_set)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user_ip = request.remote_addr
        current_time = datetime.now().timestamp()

        login_attempts[user_ip] = [
            t for t in login_attempts.get(user_ip, [])
            if current_time - t <= BRUTE_FORCE_TIME_WINDOW
        ]

        if len(login_attempts[user_ip]) >= BRUTE_FORCE_THRESHOLD:
            return render_template("login.html", error="Too many attempts. Try again in a minute.")

        user = db.get_user(username)

        if user and check_password_hash(user["password_hash"], password):
            login_attempts[user_ip] = []
            session["user"] = username
            return redirect("/")

        login_attempts[user_ip].append(current_time)

        if len(login_attempts[user_ip]) >= BRUTE_FORCE_THRESHOLD:
            print(f"[BRUTE FORCE] Detected from {user_ip}")
            record_brute_force(user_ip, DASHBOARD_HOST_IP, 5000, len(login_attempts[user_ip]))
            return render_template(
                "login.html",
                error="Too many attempts. This IP has been flagged for review."
            )

        return render_template(
            "login.html",
            error="Access denied. Invalid credentials."
        )

    return render_template("login.html")


@app.route("/")
def dashboard():
    if not login_required():
        return redirect("/login")

    attacks = get_recent_attacks(10)
    blocked_ips = get_blocked_ips(10)
    stats = get_attack_stats()

    return render_template(
        "dashboard.html",
        attacks=attacks,
        blocked_ips=blocked_ips,
        stats=stats,
        pilot_page="dashboard"
    )


@app.route("/api/dashboard-data")
def dashboard_data():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401

    attacks = get_recent_attacks(10)
    blocked_ips = get_blocked_ips(10)
    stats = get_attack_stats()

    attack_list = []

    for attack in attacks:
        attack_list.append({
            "id": attack[0],
            "attack_type": attack[1],
            "source_ip": attack[2],
            "target_ip": attack[3],
            "protocol": attack[4],
            "severity": attack[5],
            "status": attack[6],
            "action": attack[7],
            "detected_at": attack[8].strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({
        "stats": stats,
        "blocked_count": len(blocked_ips),
        "attacks": attack_list
    })


@app.route("/reset-blocks", methods=["POST"])
def reset_blocks():
    if not login_required():
        return redirect("/login")

    blocked_ip_list = get_all_blocked_ips_for_reset()

    for ip in blocked_ip_list:
        if is_valid_ip(ip):
            unblock_ip_iptables(ip)
            delete_blocked_ip(ip)

    clear_blocked_ip_file()

    flash("All blocked IP rules have been reset successfully.", "success")

    if request.method == "POST":
        return jsonify({
            "message": "All blocked IP rules have been reset successfully.",
            "reset_count": len(blocked_ip_list)
        })

    return redirect("/blocked-ips")


@app.route("/ip-lists", methods=["GET", "POST"])
def ip_lists():
    if not login_required():
        return redirect("/login")

    if request.method == "POST":
        ip_address = request.form["ip_address"]
        list_type = request.form["list_type"]
        reason = request.form["reason"]

        if not is_valid_ip(ip_address):
            flash("Invalid IP address.", "error")
            return redirect("/ip-lists")

        if list_type not in ["whitelist", "blacklist"]:
            flash("Invalid list type.", "error")
            return redirect("/ip-lists")

        added = add_ip_to_list(ip_address, list_type, reason)

        if added:
            flash("IP address added successfully.", "success")
        else:
            flash("IP already exists.", "error")

        return redirect("/ip-lists")

    whitelist = get_ip_list("whitelist")
    blacklist = get_ip_list("blacklist")

    return render_template(
        "ip_lists.html",
        whitelist=whitelist,
        blacklist=blacklist,
        pilot_page="ip_lists"
    )


@app.route("/ip-lists/delete/<int:ip_id>", methods=["POST"])
def delete_ip(ip_id):
    if not login_required():
        return redirect("/login")

    delete_ip_from_list(ip_id)
    flash("IP address removed from list.", "success")

    return redirect("/ip-lists")


@app.route("/blocked-ips")
def blocked_ips_page():
    if not login_required():
        return redirect("/login")

    ips = get_blocked_ips(50)

    return render_template("blocked_ips.html", ips=ips, pilot_page="blocked")


@app.route("/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    if not login_required():
        return redirect("/login")

    if not is_valid_ip(ip):
        flash("Invalid IP address.", "error")
        return redirect("/blocked-ips")

    unblock_ip_iptables(ip)

    delete_blocked_ip(ip)
    remove_ip_from_blocked_file(ip)

    flash("IP unblocked successfully.", "success")

    return redirect("/blocked-ips")


@app.route("/logs")
def logs_page():
    if not login_required():
        return redirect("/login")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    source_ip = request.args.get("source_ip")
    attack_type = request.args.get("attack_type")
    severity = request.args.get("severity")

    logs = get_filtered_attack_logs(
        start_date=start_date,
        end_date=end_date,
        source_ip=source_ip,
        attack_type=attack_type,
        severity=severity
    )

    return render_template(
        "logs.html",
        logs=logs,
        start_date=start_date or "",
        end_date=end_date or "",
        source_ip=source_ip or "",
        attack_type=attack_type or "",
        severity=severity or "",
        pilot_page="logs"
    )


@app.route("/logs/download")
def download_logs():
    if not login_required():
        return redirect("/login")

    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    source_ip = request.args.get("source_ip")
    attack_type = request.args.get("attack_type")
    severity = request.args.get("severity")

    logs = get_filtered_attack_logs(
        start_date=start_date,
        end_date=end_date,
        source_ip=source_ip,
        attack_type=attack_type,
        severity=severity
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Attack Type",
        "Source IP",
        "Target IP",
        "Source Port",
        "Target Port",
        "Protocol",
        "Severity",
        "Description",
        "Status",
        "Action",
        "Detected At"
    ])

    for log in logs:
        writer.writerow([
            log[0],
            log[1],
            log[2],
            log[3],
            log[4],
            log[5],
            log[6],
            log[7],
            log[8],
            log[9],
            log[10],
            log[11]
        ])

    output.seek(0)

    return Response(
        output,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=attack_logs.csv"
        }
    )


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if not login_required():
        return redirect("/login")

    if request.method == "POST":
        rules = {
            "sql_block_threshold": max(1, int(request.form.get("sql_threshold"))),
            "xss_block_threshold": max(1, int(request.form.get("xss_threshold"))),
            "high_traffic_threshold": max(1, int(request.form.get("traffic_threshold"))),
            "port_scan_threshold": max(1, int(request.form.get("port_threshold"))),
            "sql_block_enabled": "sql_enabled" in request.form,
            "xss_block_enabled": "xss_enabled" in request.form,
            "high_traffic_block_enabled": "traffic_enabled" in request.form,
            "port_scan_block_enabled": "port_enabled" in request.form,
            "require_analyst_approval": "approval_enabled" in request.form
        }

        with open(RULES_FILE, "w") as file:
            json.dump(rules, file, indent=4)

        flash("Settings updated successfully.", "success")
        return redirect("/settings")

    with open(RULES_FILE, "r") as file:
        rules = json.load(file)

    rules.setdefault("require_analyst_approval", True)
    return render_template("settings.html", rules=rules, pilot_page="settings",
                           suggestions=get_threshold_suggestions())


@app.route("/settings/apply-suggestion", methods=["POST"])
def settings_apply_suggestion():
    if not login_required():
        return redirect("/login")
    rule, value = request.form.get("rule", ""), request.form.get("value", "0")
    if apply_suggestion(rule, value):
        flash(f"Applied Pilot's suggestion: {rule} = {value}.", "success")
    else:
        flash("Could not apply that suggestion.", "error")
    return redirect("/settings")


@app.route("/reset-rules", methods=["POST"])
def reset_rules():
    if not login_required():
        return redirect("/login")

    default_rules = {
        "sql_block_threshold": 3,
        "xss_block_threshold": 3,
        "high_traffic_threshold": 40,
        "port_scan_threshold": 5,
        "sql_block_enabled": True,
        "xss_block_enabled": True,
        "high_traffic_block_enabled": True,
        "port_scan_block_enabled": True,
        "require_analyst_approval": True
    }

    with open(RULES_FILE, "w") as file:
        json.dump(default_rules, file, indent=4)

    flash("Rule settings reset to default values.", "success")
    return redirect("/settings")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


# ======================================================================
# IncidentPilot: shared template context
# ======================================================================

PRIORITY_CLASS = {"P1": "p1", "P2": "p2", "P3": "p3", "P4": "p4"}
VERDICT_LABEL = {
    "true_positive": "True positive",
    "likely_false_positive": "Likely false positive",
    "needs_review": "Needs review",
}


@app.context_processor
def inject_pilot_context():
    open_count = 0
    if "user" in session:
        try:
            open_count = db._run("SELECT COUNT(*) FROM incidents WHERE analyst_status='new'", fetch="one")[0]
        except Exception:
            open_count = 0
    return {
        "pilot_engine": llm.engine_name(),
        "pilot_ai_online": llm.is_enabled(),
        "demo_mode": DEMO_MODE,
        "open_incident_count": open_count,
        "priority_class": PRIORITY_CLASS,
        "verdict_label": VERDICT_LABEL,
    }


@app.template_filter("ts")
def format_ts(value):
    return value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value, "strftime") else (value or "-")


def safe_markdown(text):
    """Render markdown but never raw HTML (alert payloads can contain <script>)."""
    text = html_lib.escape(text or "", quote=False)
    # Python-Markdown needs a blank line before a list; LLM / offline answers often skip it.
    text = re.sub(r"(?m)^(?!\s*(?:[-*]|\d+\.)\s)(\S.*)\n(?=\s*(?:[-*]|\d+\.)\s)", r"\1\n\n", text)
    return md.markdown(text, extensions=["tables"])


def wants_json():
    return request.is_json or request.headers.get("X-Requested-With") == "fetch"


# ======================================================================
# Incidents
# ======================================================================

@app.route("/incidents")
def incidents_page():
    if not login_required():
        return redirect("/login")

    status = request.args.get("status", "new")
    priority = request.args.get("priority", "")
    rows = db.list_incidents(status=None if status == "all" else status, limit=300)
    if priority:
        rows = [r for r in rows if r.get("ai_priority") == priority]

    counts = {"new": 0, "approved": 0, "dismissed": 0}
    for r in db.list_incidents(limit=1000):
        counts[r["analyst_status"]] = counts.get(r["analyst_status"], 0) + 1

    return render_template("incidents.html", incidents=rows, status=status, priority=priority,
                           counts=counts, pilot_page="incidents")


@app.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):
    if not login_required():
        return redirect("/login")

    incident = db.get_incident(incident_id)
    if not incident:
        abort(404)
    if incident["triage_status"] == "pending":
        triage_incident(incident_id)
        incident = db.get_incident(incident_id)

    alerts = db.get_incident_alerts(incident_id)
    feedback = [db.get_incident(i) for i in incident.get("ai_feedback_used") or []]
    similar = db.get_similar_incidents(incident)
    return render_template(
        "incident_detail.html", incident=incident, alerts=alerts,
        feedback=[f for f in feedback if f],
        similar=similar,
        ip_blocked=db.is_ip_blocked(incident["source_ip"]),
        ip_whitelisted=db.is_ip_in_list(incident["source_ip"], "whitelist"),
        pilot_page="incident", pilot_incident_id=incident_id,
    )


def _decision_response(ok, message, incident_id):
    if wants_json():
        return jsonify({"ok": ok, "message": message, "incident_id": incident_id})
    flash(message, "success" if ok else "error")
    return redirect(url_for("incident_detail", incident_id=incident_id))


@app.route("/incidents/<int:incident_id>/approve", methods=["POST"])
def approve_incident(incident_id):
    if not login_required():
        return redirect("/login")
    data = request.get_json(silent=True) or request.form
    block = str(data.get("block", "true")).lower() in ("true", "on", "1", "yes")
    ok, message = incident_ops.approve_incident(incident_id, session["user"], data.get("notes", ""), block=block)
    return _decision_response(ok, message, incident_id)


@app.route("/incidents/<int:incident_id>/dismiss", methods=["POST"])
def dismiss_incident(incident_id):
    if not login_required():
        return redirect("/login")
    data = request.get_json(silent=True) or request.form
    whitelist = str(data.get("whitelist", "false")).lower() in ("true", "on", "1", "yes")
    ok, message = incident_ops.dismiss_incident(incident_id, session["user"], data.get("notes", ""), whitelist)
    return _decision_response(ok, message, incident_id)


@app.route("/incidents/<int:incident_id>/reopen", methods=["POST"])
def reopen_incident(incident_id):
    if not login_required():
        return redirect("/login")
    incident_ops.reopen_incident(incident_id)
    triage_incident(incident_id)
    return _decision_response(True, "Incident reopened and re-triaged.", incident_id)


@app.route("/incidents/<int:incident_id>/retriage", methods=["POST"])
def retriage_incident(incident_id):
    if not login_required():
        return redirect("/login")
    if pack_seed.orbit_ref(db.get_incident(incident_id)):
        return _decision_response(False, "This incident comes from the Orbit data pack and is analysed by the data-pack engine; there is nothing to re-run.", incident_id)
    triage_incident(incident_id)
    return _decision_response(True, "Pilot re-triaged this incident.", incident_id)


@app.route("/incidents/triage-pending", methods=["POST"])
def triage_pending():
    if not login_required():
        return redirect("/login")
    done = run_pending_triage(limit=50)
    flash(f"Pilot triaged {done} incident(s).", "success")
    return redirect("/incidents")


@app.route("/incidents/<int:incident_id>/report")
def incident_report(incident_id):
    if not login_required():
        return redirect("/login")
    ref = pack_seed.orbit_ref(db.get_incident(incident_id))
    text = pack_service.report_markdown(ref) if ref else build_report_markdown(incident_id)
    if text is None:
        abort(404)
    return render_template("report.html", report_html=safe_markdown(text), incident_id=incident_id)


@app.route("/incidents/<int:incident_id>/report.md")
def incident_report_md(incident_id):
    if not login_required():
        return redirect("/login")
    ref = pack_seed.orbit_ref(db.get_incident(incident_id))
    text = pack_service.report_markdown(ref) if ref else build_report_markdown(incident_id)
    if text is None:
        abort(404)
    return Response(text, mimetype="text/markdown", headers={
        "Content-Disposition": f"attachment; filename=INC-{incident_id}-report.md"
    })


# ======================================================================
# Ask Pilot API
# ======================================================================

@app.route("/api/pilot/briefing")
def api_briefing():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_briefing(force=request.args.get("refresh") == "1"))


@app.route("/api/pilot/chat", methods=["POST"])
def api_chat():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    if pack_service.available() and pack_service.looks_like_pack_question(data.get("message", "")):
        result = pack_service.ask(data.get("message", ""))
        result["actions"] = [{"type": "link", "label": "Open Orbit incident board", "url": "/pack"}]
        result["answer"] += f"\n\n*Evidence check: {result['citations']['valid']}/{result['citations']['total']} citations verified. Engine: {result['engine']}.*"
        result["answer_html"] = safe_markdown(result["answer"])
        return jsonify(result)
    result = pilot_answer(
        data.get("message", ""),
        page=data.get("page"),
        incident_id=data.get("incident_id"),
        agent=data.get("agent", "triage"),
    )
    result["answer_html"] = safe_markdown(result["answer"])
    return jsonify(result)


# ======================================================================
# Problem C data pack: Orbit Logistics triage board
# ======================================================================

@app.route("/pack")
def pack_page():
    if not login_required():
        return redirect("/login")
    return render_template("pack.html", pack_ready=pack_service.available())


@app.route("/api/pack/analysis")
def api_pack_analysis():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    if not pack_service.available():
        return jsonify({"error": "Data pack folder not found (set PACK_DIR)"}), 404
    return jsonify(pack_service.analysis_json())


@app.route("/api/pack/ask", methods=["POST"])
def api_pack_ask():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    result = pack_service.ask(data.get("question", ""))
    result["answer_html"] = safe_markdown(result["answer"])
    return jsonify(result)


@app.route("/api/pack/cite")
def api_pack_cite():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    text = pack_service.cite_text(request.args.get("ref", ""))
    return jsonify({"ref": request.args.get("ref", ""), "text": text, "found": text is not None})


@app.route("/pack/report")
def pack_report():
    if not login_required():
        return redirect("/login")
    inc = request.args.get("incident") or None
    return render_template("pack_report.html", report_html=safe_markdown(pack_service.report_markdown(inc)), incident=inc)


@app.route("/pack/report.html")
def pack_report_html():
    """Self-contained HTML file (open in any browser, print or save as PDF)."""
    if not login_required():
        return redirect("/login")
    inc = request.args.get("incident") or None
    page = render_template("pack_report_file.html", report_html=safe_markdown(pack_service.report_markdown(inc)), incident=inc)
    return Response(page, mimetype="text/html", headers={
        "Content-Disposition": f"attachment; filename=orbit-incident-report{'-' + inc if inc else ''}.html"})


@app.route("/pack/seed", methods=["POST"])
def pack_seed_route():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    created = pack_seed.seed()
    return jsonify({"created": created, "message": f"Loaded {created} Orbit incident(s) into the dashboard." if created else "Orbit incidents are already in the dashboard."})


@app.route("/pack/report.md")
def pack_report_md():
    if not login_required():
        return redirect("/login")
    inc = request.args.get("incident") or None
    return Response(pack_service.report_markdown(inc), mimetype="text/markdown", headers={
        "Content-Disposition": f"attachment; filename=orbit-incident-report{'-' + inc if inc else ''}.md"})


@app.route("/api/incidents/summary")
def api_incident_summary():
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    row = db._run("SELECT COUNT(*), COALESCE(MAX(id), 0), COALESCE(SUM(alert_count), 0) FROM incidents", fetch="one")
    pending = db._run("SELECT COUNT(*) FROM incidents WHERE needs_triage=1", fetch="one")[0]
    return jsonify({"count": row[0], "max_id": row[1], "alerts": row[2], "pending_triage": pending})


@app.route("/api/alerts/critical")
def api_critical_alerts():
    """Open P1 incidents; the widget shows a toast for ones the user hasn't seen."""
    if not login_required():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify([{
        "id": i["id"], "source_ip": i["source_ip"], "summary": (i.get("ai_summary") or "")[:200],
        "types": i["attack_type_list"],
    } for i in db.get_critical_since(0, limit=10)])


# ======================================================================
# Bring your own logs
# ======================================================================

@app.route("/ingest-log", methods=["POST"])
def ingest_log():
    if not login_required():
        return redirect("/login")
    upload = request.files.get("logfile")
    if not upload or not upload.filename:
        flash("Choose an access log file first.", "error")
        return redirect("/logs")
    text = upload.read().decode("utf-8", errors="ignore").splitlines()
    result = log_ingest.ingest_lines(text, source_name=upload.filename)
    triaged = run_pending_triage(limit=50)
    message = (f"Analysed {result['parsed']}/{result['lines']} lines from {upload.filename}: "
               f"{result['alerts']} alert(s), Pilot triaged {triaged} incident(s).")
    if result["tools_seen"]:
        message += " Attack tools seen: " + ", ".join(sorted(set(result["tools_seen"]))) + "."
    flash(message, "success" if result["parsed"] else "error")
    return redirect("/incidents?status=new")


# ======================================================================
# Background auto-triage worker
# ======================================================================

def _triage_worker():
    import time
    while True:
        try:
            run_pending_triage(limit=10)
        except Exception as error:
            print("[TRIAGE WORKER] error:", error)
        time.sleep(AUTO_TRIAGE_INTERVAL_SECONDS)


def start_triage_worker():
    thread = threading.Thread(target=_triage_worker, daemon=True, name="pilot-triage")
    thread.start()


if __name__ == "__main__":
    import os
    # Flask's debug reloader runs this file twice; start the worker only in the real process.
    if AUTO_TRIAGE and os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_triage_worker()
    print(f"IncidentPilot running on http://127.0.0.1:5000  (AI: {llm.engine_name()}, demo mode: {DEMO_MODE})")
    app.run(host="0.0.0.0", port=5000, debug=True)
