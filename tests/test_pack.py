"""
Problem C data-pack tests (standard library only).

    python -m unittest tests.test_pack -v        (from the project root)
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["LLM_PROVIDER"] = "offline"
sys.path.insert(0, os.path.join(ROOT, "source"))

from pack.loader import get_pack  # noqa: E402
from pack.analysis import build  # noqa: E402
from pack import qa  # noqa: E402
from pack.report import build_markdown  # noqa: E402

PACK = get_pack(os.path.join(ROOT, "problem_c_data"))
A = build(PACK)


def inc(kind):
    return next(i for i in A.incidents if i["kind"] == kind)


class PackTests(unittest.TestCase):
    def test_time_zones_normalised_to_utc(self):
        big = next(e for e in PACK.events if e["src"] == "fw_int" and int(e.get("bytes_total", 0)) > 1e9)
        self.assertEqual(big["end"].strftime("%H:%M:%S"), "06:21:19")      # 11:21:19 PKT
        self.assertEqual(big["start"].strftime("%H:%M:%S"), "06:03:12")    # logged at close - 1087 s
        web = next(e for e in PACK.events if e["src"] == "web" and e["status"] == 200 and e["size"] == 48213)
        self.assertEqual(web["ts"].strftime("%H:%M:%S"), "06:06:02")       # +0500 in the line

    def test_incidents_and_severity(self):
        self.assertEqual([i["severity"] for i in A.incidents], ["P1", "P2", "P4"])
        phish = inc("phish")
        sev = {p["type"]: p["severity"] for p in phish["parts"]}
        self.assertEqual(sev["Data exfiltration"], "P1")
        self.assertEqual(sev["Credential compromise"], "P2")
        self.assertEqual(inc("web")["severity"], "P2")      # Medium asset, success suspected
        self.assertEqual(inc("scan")["severity"], "P4")     # Medium asset, unapproved scan

    def test_phishing_click_only_for_amalik(self):
        text = " ".join(x["text"] for x in inc("phish")["confirmed"])
        self.assertIn("amalik): click seen", text)
        self.assertIn("sraheel): no click seen", text)
        self.assertIn("utariq): no click seen", text)

    def test_approved_activity_closed_with_change_id(self):
        ids = {c["change_id"] for c in A.closed}
        self.assertEqual(ids, {"CHG-2026-1104-02", "CHG-2026-1104-03"})
        self.assertNotIn("CHG-2026-1104-05", ids)           # postponed, not performed

    def test_never_claims_data_was_stolen(self):
        md = build_markdown(A).lower()
        self.assertNotIn("data was stolen", md)
        self.assertIn("which files on srv-fs01 were read", md)

    def test_every_citation_in_report_is_valid(self):
        total, valid, bad = PACK.check_text(build_markdown(A))
        self.assertGreater(total, 100)
        self.assertEqual(bad, [])
        self.assertEqual(total, valid)

    def test_report_has_all_mandatory_sections(self):
        md = build_markdown(A)
        for h in ["Summary", "Timeline (UTC, with file and line)", "Affected assets and accounts", "Severity (with steps)", "Confirmed",
                  "Suspected", "Not enough evidence in the logs", "Missing log sources", "Closed as harmless (with change ID)",
                  "Recommended actions (runbook ID and step)", "People to inform (name and time limit)"]:
            self.assertIn(f"## {h}", md)

    def test_escalation_for_p1(self):
        who = [p["who"] for p in inc("phish")["people"] if p["severity"] == "P1"]
        self.assertTrue(any("CISO" in w for w in who))
        self.assertTrue(any("Saima Noor" in w for w in who))
        self.assertTrue(any(w.startswith("Legal") for w in who))   # FS01 holds finance and HR shares

    def test_citation_validator_catches_fake_citations(self):
        total, valid, bad = PACK.check_text("[11_vpn_auth_log.md:7] [11_vpn_auth_log.md:99] [17_ids_alert_summary.md#ALT-1234]")
        self.assertEqual((total, valid, len(bad)), (3, 1, 2))

    def test_qa_offline(self):
        r = qa.answer(PACK, A, "Which files were stolen from FS01?", use_llm=False)
        self.assertIn("Not enough evidence in the logs", r["answer"])
        self.assertEqual(r["citations"]["invalid"], [])
        r = qa.answer(PACK, A, "Was the scan from SCAN01 approved?", use_llm=False)
        self.assertIn("CHG-2026-1104-02", r["answer"])
        r = qa.answer(PACK, A, "What is the capital of France?", use_llm=False)
        self.assertIn("Not enough evidence", r["answer"])


if __name__ == "__main__":
    unittest.main()
