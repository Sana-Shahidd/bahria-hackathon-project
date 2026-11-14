"""
Database layer.

Supports SQLite (default, zero setup) and PostgreSQL (original CyberPulse setup).
All original CyberPulse functions are kept with the same names and return shapes
(tuples), so the existing dashboard templates keep working. New IncidentPilot
functions (users, incidents, triage, feedback) return dicts.
"""
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta

from config import (
    DB_ENGINE, SQLITE_PATH,
    DB_HOST, DB_NAME, DB_USER, DB_PASSWORD,
)

IS_SQLITE = DB_ENGINE != "postgres"
_TS_FORMAT = "%Y-%m-%d %H:%M:%S"


# ======================================================================
# Connection handling (SQLite adapter makes the original psycopg2-style
# SQL work unchanged: %s placeholders and ::date casts are translated)
# ======================================================================

def _parse_ts(raw):
    text = raw.decode() if isinstance(raw, bytes) else str(raw)
    for fmt in (_TS_FORMAT, "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return text


sqlite3.register_adapter(datetime, lambda value: value.strftime(_TS_FORMAT))
sqlite3.register_converter("TIMESTAMP", _parse_ts)

_PLACEHOLDER = re.compile(r"%s(?!\w)")


class _SqliteCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=()):
        sql = _PLACEHOLDER.sub("?", sql)
        sql = re.sub(r"(\w+)::date", r"date(\1)", sql)
        return self._cursor.execute(sql, tuple(params))

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def description(self):
        return self._cursor.description

    def close(self):
        self._cursor.close()


class _SqliteConnection:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(
            path, detect_types=sqlite3.PARSE_DECLTYPES, timeout=15, check_same_thread=False
        )
        self._conn.execute("PRAGMA foreign_keys = ON")

    def cursor(self):
        return _SqliteCursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def executescript(self, script):
        self._conn.executescript(script)


def get_db_connection():
    if IS_SQLITE:
        return _SqliteConnection(SQLITE_PATH)

    import psycopg2  # only needed for PostgreSQL
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )


def _run(sql, params=(), fetch=None, as_dict=False, insert_id=False):
    """Small helper used by the new IncidentPilot functions."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if insert_id and not IS_SQLITE:
            sql = sql.rstrip().rstrip(";") + " RETURNING id"
        if params:
            cur.execute(sql, params)
        else:
            cur.execute(sql)  # psycopg2 would treat literal '%' as placeholders otherwise

        result = None
        if insert_id:
            result = cur.lastrowid if IS_SQLITE else cur.fetchone()[0]
        elif fetch == "one":
            row = cur.fetchone()
            if row is not None and as_dict:
                cols = [c[0] for c in cur.description]
                row = dict(zip(cols, row))
            result = row
        elif fetch == "all":
            rows = cur.fetchall()
            if as_dict:
                cols = [c[0] for c in cur.description]
                rows = [dict(zip(cols, r)) for r in rows]
            result = rows
        else:
            result = cur.rowcount

        conn.commit()
        return result
    finally:
        cur.close()
        conn.close()


def now():
    return datetime.now().replace(microsecond=0)


# ======================================================================
# Original CyberPulse functions (same names / same tuple shapes)
# ======================================================================

def save_to_db(attack_type, source_ip, target_ip, source_port, target_port, protocol, severity, description, status, action,
               detected_at=None):
    """Insert an alert and attach it to an incident. Returns the alert id."""
    try:
        alert_id = _run("""
            INSERT INTO attacks
            (attack_type, source_ip, target_ip, source_port, target_port, protocol,
             severity, description, status, action_taken, detected_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (attack_type, source_ip, target_ip, source_port, target_port, protocol,
              severity, description, status, action, detected_at or now()), insert_id=True)

    except Exception as e:
        print("DB ERROR:", e)
        return None

    try:
        from incidents import attach_alert
        attach_alert(alert_id)
    except Exception as e:
        print("INCIDENT GROUPING ERROR:", e)

    return alert_id


def save_blocked_ip_to_db(ip, reason):
    try:
        _run("""
            INSERT INTO blocked_ips (ip_address, block_reason, blocked_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (ip_address) DO NOTHING
        """, (ip, reason, now()))

    except Exception as e:
        print("DB BLOCK ERROR:", e)


def get_recent_attacks(limit=10):
    try:
        return _run("""
            SELECT id, attack_type, source_ip, target_ip, protocol, severity, status, action_taken, detected_at
            FROM attacks
            ORDER BY detected_at DESC, id DESC
            LIMIT %s
        """, (limit,), fetch="all")

    except Exception as e:
        print("DB READ ERROR:", e)
        return []


def get_filtered_attack_logs(start_date=None, end_date=None, source_ip=None, attack_type=None, severity=None):
    try:
        query = """
            SELECT id, attack_type, source_ip, target_ip, source_port, target_port,
                   protocol, severity, description, status, action_taken, detected_at
            FROM attacks
            WHERE 1=1
        """

        params = []

        if start_date:
            query += " AND detected_at::date >= %s"
            params.append(start_date)

        if end_date:
            query += " AND detected_at::date <= %s"
            params.append(end_date)

        if source_ip:
            query += " AND source_ip = %s"
            params.append(source_ip)

        if attack_type:
            query += " AND LOWER(attack_type) LIKE LOWER(%s)"
            params.append(f"%{attack_type}%")

        if severity:
            query += " AND LOWER(severity) = LOWER(%s)"
            params.append(severity)

        query += " ORDER BY detected_at DESC, id DESC"

        return _run(query, tuple(params), fetch="all")

    except Exception as e:
        print("DB FILTERED LOG ERROR:", e)
        return []


def get_attack_stats():
    stats = {
        "total_attacks": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "port_scan_count": 0,
        "high_traffic_count": 0,
        "sql_count": 0,
        "xss_count": 0,
        "brute_count": 0
    }

    queries = {
        "total_attacks": "SELECT COUNT(*) FROM attacks",
        "high_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(severity)='high'",
        "medium_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(severity)='medium'",
        "low_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(severity)='low'",
        "port_scan_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(REPLACE(attack_type, '_', ' ')) = 'port scan'",
        "high_traffic_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(REPLACE(attack_type, '_', ' ')) = 'high traffic'",
        "sql_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(attack_type) LIKE '%sql%'",
        "xss_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(attack_type) LIKE '%xss%'",
        "brute_count": "SELECT COUNT(*) FROM attacks WHERE LOWER(attack_type) = 'brute force'",
    }

    try:
        for key, sql in queries.items():
            stats[key] = _run(sql, fetch="one")[0]
    except Exception as e:
        print("DB STATS ERROR:", e)

    return stats


def get_blocked_ips(limit=10):
    try:
        return _run("""
            SELECT id, ip_address, block_reason, blocked_at
            FROM blocked_ips
            ORDER BY blocked_at DESC
            LIMIT %s
        """, (limit,), fetch="all")

    except Exception as e:
        print("DB READ ERROR:", e)
        return []


def get_ip_list(list_type):
    try:
        return _run("""
            SELECT id, ip_address, list_type, reason, created_at
            FROM ip_lists
            WHERE list_type=%s
            ORDER BY created_at DESC
        """, (list_type,), fetch="all")

    except Exception as e:
        print("DB IP LIST READ ERROR:", e)
        return []


def add_ip_to_list(ip_address, list_type, reason):
    try:
        added = _run("""
            INSERT INTO ip_lists (ip_address, list_type, reason, created_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (ip_address, list_type) DO NOTHING
        """, (ip_address, list_type, reason, now()))
        return added > 0

    except Exception as e:
        print("DB IP LIST ADD ERROR:", e)
        return False


def delete_ip_from_list(ip_id):
    try:
        _run("DELETE FROM ip_lists WHERE id=%s", (ip_id,))
    except Exception as e:
        print("DB IP LIST DELETE ERROR:", e)


def delete_blocked_ip(ip_address):
    try:
        _run("DELETE FROM blocked_ips WHERE ip_address=%s", (ip_address,))
    except Exception as e:
        print("DB BLOCK DELETE ERROR:", e)


# ======================================================================
# New: users
# ======================================================================

def get_user(username):
    return _run("SELECT id, username, password_hash FROM users WHERE username=%s",
                (username,), fetch="one", as_dict=True)


def upsert_user(username, password_hash):
    existing = get_user(username)
    if existing:
        _run("UPDATE users SET password_hash=%s WHERE username=%s", (password_hash, username))
    else:
        _run("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))


# ======================================================================
# New: incidents
# ======================================================================

JSON_FIELDS = ("ai_mitre", "ai_evidence", "ai_next_steps", "ai_feedback_used")
PRIORITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _decode_incident(row):
    if not row:
        return row
    for field in JSON_FIELDS:
        value = row.get(field)
        try:
            row[field] = json.loads(value) if value else []
        except (TypeError, ValueError):
            row[field] = []
    row["attack_type_list"] = [t for t in (row.get("attack_types") or "").split(",") if t]
    return row


def get_alert(alert_id):
    return _run("SELECT * FROM attacks WHERE id=%s", (alert_id,), fetch="one", as_dict=True)


def find_open_incident(source_ip, since):
    return _run("""
        SELECT * FROM incidents
        WHERE source_ip=%s AND last_seen >= %s AND analyst_status = 'new'
        ORDER BY last_seen DESC LIMIT 1
    """, (source_ip, since), fetch="one", as_dict=True)


def create_incident(source_ip, first_seen, attack_type, severity):
    return _run("""
        INSERT INTO incidents (source_ip, first_seen, last_seen, alert_count, attack_types,
                               max_severity, needs_triage, triage_status, analyst_status, created_at)
        VALUES (%s, %s, %s, 1, %s, %s, 1, 'pending', 'new', %s)
    """, (source_ip, first_seen, first_seen, attack_type, severity, now()), insert_id=True)


def update_incident_counters(incident_id, last_seen, attack_types, max_severity):
    _run("""
        UPDATE incidents
        SET last_seen=%s, alert_count=alert_count+1, attack_types=%s, max_severity=%s,
            needs_triage=1
        WHERE id=%s
    """, (last_seen, attack_types, max_severity, incident_id))


def set_alert_incident(alert_id, incident_id):
    _run("UPDATE attacks SET incident_id=%s WHERE id=%s", (incident_id, alert_id))


def get_incident(incident_id):
    return _decode_incident(_run("SELECT * FROM incidents WHERE id=%s",
                                 (incident_id,), fetch="one", as_dict=True))


def list_incidents(since=None, status=None, limit=200):
    sql = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if since:
        sql += " AND last_seen >= %s"
        params.append(since)
    if status:
        sql += " AND analyst_status = %s"
        params.append(status)
    sql += " ORDER BY last_seen DESC LIMIT %s"
    params.append(limit)
    rows = [_decode_incident(r) for r in _run(sql, tuple(params), fetch="all", as_dict=True)]
    rows.sort(key=lambda r: (
        0 if r["analyst_status"] == "new" else 1,
        PRIORITY_ORDER.get(r.get("ai_priority") or "", 5),
        -(r["last_seen"].timestamp() if isinstance(r["last_seen"], datetime) else 0),
    ))
    return rows


def get_incident_alerts(incident_id):
    return _run("""
        SELECT id, attack_type, source_ip, target_ip, source_port, target_port, protocol,
               severity, description, status, action_taken, detected_at
        FROM attacks WHERE incident_id=%s ORDER BY detected_at ASC, id ASC
    """, (incident_id,), fetch="all", as_dict=True)


def incidents_needing_triage(limit=10):
    return [_decode_incident(r) for r in _run("""
        SELECT * FROM incidents WHERE needs_triage=1 ORDER BY last_seen ASC LIMIT %s
    """, (limit,), fetch="all", as_dict=True)]


def save_triage(incident_id, result, engine):
    _run("""
        UPDATE incidents SET
            ai_summary=%s, ai_verdict=%s, ai_priority=%s, ai_confidence=%s,
            ai_mitre=%s, ai_evidence=%s, ai_next_steps=%s, ai_recommended_action=%s,
            ai_feedback_used=%s, ai_engine=%s, triaged_at=%s,
            triage_status='triaged', needs_triage=0
        WHERE id=%s
    """, (
        result.get("summary"), result.get("verdict"), result.get("priority"),
        float(result.get("confidence") or 0),
        json.dumps(result.get("mitre") or []), json.dumps(result.get("evidence") or []),
        json.dumps(result.get("next_steps") or []), result.get("recommended_action"),
        json.dumps(result.get("feedback_used") or []), engine, now(), incident_id,
    ))


def mark_triage_error(incident_id, message):
    _run("UPDATE incidents SET triage_status='error', needs_triage=0, ai_summary=%s WHERE id=%s",
         (f"Triage failed: {message}", incident_id))


def request_retriage(incident_id):
    _run("UPDATE incidents SET needs_triage=1, triage_status='pending' WHERE id=%s", (incident_id,))


def set_analyst_decision(incident_id, status, verdict, notes, user):
    _run("""
        UPDATE incidents SET analyst_status=%s, analyst_verdict=%s, analyst_notes=%s,
                             decided_by=%s, decided_at=%s
        WHERE id=%s
    """, (status, verdict, notes, user, now(), incident_id))


def get_feedback_examples(attack_types, source_ip=None, exclude_id=None, limit=5):
    """Past analyst decisions on similar incidents (same IP or overlapping attack types)."""
    rows = _run("""
        SELECT * FROM incidents
        WHERE analyst_status IN ('approved', 'dismissed') AND id <> %s
        ORDER BY decided_at DESC LIMIT 100
    """, (exclude_id or -1,), fetch="all", as_dict=True)

    wanted = set(attack_types or [])
    scored = []
    for row in rows:
        row = _decode_incident(row)
        overlap = len(wanted & set(row["attack_type_list"]))
        same_ip = 1 if source_ip and row["source_ip"] == source_ip else 0
        if overlap or same_ip:
            scored.append((same_ip * 10 + overlap, row))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in scored[:limit]]


def get_alerts_since(since, limit=200):
    return _run("""
        SELECT id, attack_type, source_ip, target_ip, target_port, severity, description,
               status, action_taken, detected_at, incident_id
        FROM attacks WHERE detected_at >= %s ORDER BY detected_at DESC, id DESC LIMIT %s
    """, (since, limit), fetch="all", as_dict=True)


def is_ip_in_list(ip, list_type):
    return bool(_run("SELECT 1 FROM ip_lists WHERE ip_address=%s AND list_type=%s",
                     (ip, list_type), fetch="one"))


def is_ip_blocked(ip):
    return bool(_run("SELECT 1 FROM blocked_ips WHERE ip_address=%s", (ip,), fetch="one"))


# ======================================================================
# New: similar incidents, P1 notifications
# ======================================================================

def get_similar_incidents(incident, days=30, limit=5):
    """Same source IP, or the same set of attack types, in the last `days` days."""
    since = incident["first_seen"] - timedelta(days=days)
    rows = [_decode_incident(r) for r in _run("""
        SELECT * FROM incidents WHERE id <> %s AND last_seen >= %s ORDER BY last_seen DESC LIMIT 300
    """, (incident["id"], since), fetch="all", as_dict=True)]
    wanted = set(incident["attack_type_list"])
    scored = []
    for row in rows:
        same_ip = row["source_ip"] == incident["source_ip"]
        overlap = len(wanted & set(row["attack_type_list"]))
        if same_ip or overlap:
            reason = "Same source IP" if same_ip else "Same attack pattern" if set(row["attack_type_list"]) == wanted else "Overlapping attack types"
            row["similar_reason"] = reason
            scored.append(((10 if same_ip else 0) + overlap + (3 if set(row["attack_type_list"]) == wanted else 0), row))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [row for _, row in scored[:limit]]


def mark_notified(incident_id):
    _run("UPDATE incidents SET notified_at=%s WHERE id=%s", (now(), incident_id))


def get_critical_since(after_id=0, limit=5):
    return [_decode_incident(r) for r in _run("""
        SELECT * FROM incidents
        WHERE id > %s AND ai_priority = 'P1' AND analyst_status = 'new'
        ORDER BY id ASC LIMIT %s
    """, (after_id, limit), fetch="all", as_dict=True)]
