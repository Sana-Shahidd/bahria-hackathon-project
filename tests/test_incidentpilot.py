"""
IncidentPilot test suite (standard library only).

    python -m unittest discover -s tests -v
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="incidentpilot-test-")
os.environ.update({
    "DB_ENGINE": "sqlite",
    "SQLITE_PATH": os.path.join(TMP, "test.db"),
    "DEMO_MODE": "true",
    "LLM_PROVIDER": "offline",
    "AUTO_TRIAGE": "false",
    "NOTIFY_WEBHOOK_URL": "",
    "ORBIT_SEED": "false",
})
sys.path.insert(0, os.path.join(ROOT, "source"))

import config  # noqa: E402

# keep the real logs/ and rules file untouched
config.LOGS_DIR = os.path.join(TMP, "logs")
shutil.copy(config.RULES_FILE, os.path.join(TMP, "rules.json"))
config.RULES_FILE = os.path.join(TMP, "rules.json")

import firewall  # noqa: E402
firewall.LOGS_DIR = config.LOGS_DIR
firewall.BLOCKED_FILE = os.path.join(config.LOGS_DIR, "blocked_ips.txt")

import sniffer  # noqa: E402
sniffer.RULES_FILE = config.RULES_FILE
sniffer.LOGS_DIR = config.LOGS_DIR

import db  # noqa: E402
import incidents  # noqa: E402
import init_db  # noqa: E402
import log_ingest  # noqa: E402
from ai import triage, tuning, chat  # noqa: E402
tuning.RULES_FILE = config.RULES_FILE


def fresh_db():
    init_db.init(reset=True)
    firewall.clear_blocked_ip_file()
    sniffer.blocked_ips.clear()
    sniffer.attack_counter.clear()
    sniffer.last_logged_attacks.clear()
    sniffer.port_tracker.clear()
    sniffer.packet_times.clear()
    sniffer.prepare_engine()


def alert(attack_type, ip, severity="Medium", desc="test", status="detected", detected_at=None):
    return db.save_to_db(attack_type, ip, "10.0.0.1", None, 80, "TCP", severity, desc, status, "monitored",
                         detected_at=detected_at)


class DetectionTests(unittest.TestCase):
    def test_signatures(self):
        self.assertEqual(sniffer.detect_web_attack("GET /?id=1 UNION SELECT a FROM b"), "SQL Injection")
        self.assertEqual(sniffer.detect_web_attack("GET /?q=%3Cscript%3Ealert(1)%3C/script%3E"), "XSS Attack")
        self.assertIsNone(sniffer.detect_web_attack("GET /products?id=3 HTTP/1.1"))


class IncidentTests(unittest.TestCase):
    def setUp(self):
        fresh_db()

    def test_alerts_from_same_ip_are_grouped(self):
        a = alert("Port Scan", "192.168.56.10")
        b = alert("SQL Injection", "192.168.56.10", "High")
        c = alert("XSS Attack", "192.168.56.11")
        inc_a, inc_b, inc_c = (db.get_alert(x)["incident_id"] for x in (a, b, c))
        self.assertEqual(inc_a, inc_b)
        self.assertNotEqual(inc_a, inc_c)
        inc = db.get_incident(inc_a)
        self.assertEqual(inc["alert_count"], 2)
        self.assertEqual(inc["attack_type_list"], ["Port Scan", "SQL Injection"])
        self.assertEqual(inc["max_severity"], "High")

    def test_old_alert_starts_new_incident(self):
        old = alert("Port Scan", "192.168.56.10", detected_at=db.now().replace(year=2020))
        new = alert("Port Scan", "192.168.56.10")
        self.assertNotEqual(db.get_alert(old)["incident_id"], db.get_alert(new)["incident_id"])

    def test_recon_then_exploit_is_p1(self):
        inc_id = db.get_alert(alert("Port Scan", "192.168.56.10", status="pending_approval"))["incident_id"]
        alert("SQL Injection", "192.168.56.10", "High", status="pending_approval")
        result = triage.triage_incident(inc_id)
        self.assertEqual(result["priority"], "P1")
        self.assertEqual(result["verdict"], "true_positive")
        self.assertEqual(result["recommended_action"], "block_ip")
        self.assertTrue(all(e.startswith("alert #") for e in result["evidence"]))

    def test_feedback_learning_marks_repeat_false_positive(self):
        first = db.get_alert(alert("Port Scan", "192.168.56.5"))["incident_id"]
        triage.triage_incident(first)
        incidents.dismiss_incident(first, "tester", "authorized IT scanner")
        second = db.get_alert(alert("Port Scan", "192.168.56.5"))["incident_id"]
        self.assertNotEqual(first, second)
        result = triage.triage_incident(second)
        self.assertEqual(result["verdict"], "likely_false_positive")
        self.assertEqual(result["priority"], "P4")
        self.assertIn(first, result["feedback_used"])

    def test_approve_blocks_and_updates_alerts(self):
        inc_id = db.get_alert(alert("SQL Injection", "192.168.56.20", "High", status="pending_approval"))["incident_id"]
        ok, _ = incidents.approve_incident(inc_id, "tester", "real")
        self.assertTrue(ok)
        self.assertTrue(db.is_ip_blocked("192.168.56.20"))
        self.assertEqual(db.get_incident_alerts(inc_id)[0]["status"], "blocked")
        self.assertEqual(db.get_incident(inc_id)["analyst_status"], "approved")

    def test_similar_incidents(self):
        a = db.get_alert(alert("Port Scan", "192.168.56.30"))["incident_id"]
        incidents.dismiss_incident(a, "t")
        b = db.get_alert(alert("Port Scan", "192.168.56.31"))["incident_id"]
        similar = db.get_similar_incidents(db.get_incident(b))
        self.assertIn(a, [s["id"] for s in similar])


class LLMNormalizeTests(unittest.TestCase):
    def setUp(self):
        fresh_db()

    def test_bad_llm_output_is_repaired(self):
        inc_id = db.get_alert(alert("XSS Attack", "192.168.56.23"))["incident_id"]
        ctx = triage.build_context(db.get_incident(inc_id))
        out = triage.normalize({"priority": "urgent!!", "verdict": "maybe", "confidence": "9",
                                "mitre": ["T1059"], "feedback_used": ["INC-3", "x"]}, ctx)
        self.assertIn(out["priority"], ("P1", "P2", "P3", "P4"))
        self.assertIn(out["verdict"], triage.VALID_VERDICTS)
        self.assertEqual(out["confidence"], 1.0)
        self.assertEqual(out["mitre"], [{"id": "T1059", "name": ""}])
        self.assertEqual(out["feedback_used"], [3])


class LogIngestTests(unittest.TestCase):
    def setUp(self):
        fresh_db()

    def test_sample_log(self):
        result = log_ingest.ingest_file(os.path.join(ROOT, "data", "sample_access.log"))
        self.assertEqual(result["parsed"], result["lines"])
        types = {r[1] for r in db.get_recent_attacks(50)}
        self.assertTrue({"Web Scan", "SQL Injection", "Brute Force", "High Traffic", "XSS Attack"} <= types)
        triage.run_pending_triage(50)
        compromised = [i for i in db.list_incidents() if i["source_ip"] == "192.168.56.88"][0]
        self.assertEqual(compromised["ai_priority"], "P1")
        self.assertIn("compromised", compromised["ai_summary"])
        normal_user = [i for i in db.list_incidents() if i["source_ip"] == "192.168.56.30"]
        self.assertEqual(normal_user, [], "one failed login must not raise an alert")


class TuningAndChatTests(unittest.TestCase):
    def setUp(self):
        fresh_db()

    def test_noisy_rule_suggestion_and_apply(self):
        for ip in ("192.168.56.5", "192.168.56.6"):
            inc = db.get_alert(alert("Port Scan", ip))["incident_id"]
            incidents.dismiss_incident(inc, "t", "scanner")
        port = [s for s in tuning.get_threshold_suggestions() if s["attack_type"] == "Port Scan"][0]
        self.assertTrue(port["noisy"])
        self.assertEqual(port["suggested"], port["current"] + 3)
        self.assertTrue(tuning.apply_suggestion(port["rule"], port["suggested"]))
        with open(config.RULES_FILE) as f:
            self.assertEqual(json.load(f)["port_scan_threshold"], port["suggested"])

    def test_offline_chat_answers(self):
        inc = db.get_alert(alert("SQL Injection", "192.168.56.10", "High"))["incident_id"]
        triage.triage_incident(inc)
        top = chat.answer("Which IP is most dangerous?")
        self.assertIn("192.168.56.10", top["answer"])
        self.assertTrue(any(a["type"] == "approve" for a in top["actions"]))
        why = chat.answer("Why is 192.168.56.10 urgent?")
        self.assertIn(f"INC-{inc}", why["answer"])


class WebAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fresh_db()
        import app as webapp
        cls.webapp = webapp
        cls.client = webapp.app.test_client()

    def login(self):
        self.client.get("/login")
        with self.client.session_transaction() as s:
            token = s["csrf_token"]
        self.client.post("/login", data={"username": "admin", "password": "admin123", "csrf_token": token})
        return token

    def test_csrf_blocks_post_without_token(self):
        token = self.login()
        r = self.client.post("/api/pilot/chat", json={"message": "hi"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post("/api/pilot/chat", json={"message": "hi"}, headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 200)

    def test_payloads_are_escaped(self):
        token = self.login()
        inc = db.get_alert(alert("XSS Attack", "192.168.56.23", desc="Payload <script>alert(1)</script>"))["incident_id"]
        triage.triage_incident(inc)
        page = self.client.get(f"/incidents/{inc}/report").data.decode()
        self.assertNotIn("<script>alert(1)", page)
        r = self.client.post("/api/pilot/chat", json={"message": f"explain INC-{inc}"}, headers={"X-CSRF-Token": token})
        self.assertNotIn("<script>alert(1)", r.json["answer_html"])

    def test_pages_render(self):
        self.login()
        for url in ["/", "/incidents", "/logs", "/settings", "/blocked-ips", "/ip-lists",
                    "/api/pilot/briefing", "/api/alerts/critical"]:
            self.assertEqual(self.client.get(url).status_code, 200, url)


if __name__ == "__main__":
    unittest.main()
