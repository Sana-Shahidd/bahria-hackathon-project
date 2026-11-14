# IncidentPilot - AI Security Incident Triage Assistant (Problem C)

Reads the 20 Orbit Logistics data-pack files (`problem_c_data/`), normalises all times to UTC, correlates VPN, domain controller,
web, firewall, email, IDS and DHCP evidence into incidents, scores severity with the matrix, and writes a cited report
(Confirmed / Suspected / Not enough evidence). Every claim carries a `file:line` or `file#row` citation that is verified against the files.

```bash
python -m venv venv && venv\Scriptsctivate     # Windows (use source venv/bin/activate on Linux/macOS)
pip install -r requirements.txt
python source/init_db.py --reset
python source/app.py                              # open http://127.0.0.1:5000/pack  (login admin / admin123)
python -m unittest discover -s tests
```
Optional: copy `.env.example` to `.env` and set `LLM_PROVIDER=gemini` + `GEMINI_API_KEY` for AI answers; without it the offline engine is used.
Live packet sensor extras: `pip install -r requirements-live.txt`. Deploy: `vercel --prod` (see `vercel.json`, `api/index.py`).

---

# Problem C - Security Incident Triage Assistant - Data Pack

Company: Orbit Logistics (made-up). This folder has 20 files (01 to 20). Your assistant must use only these files.

## Files
- 01 Security rules, 02 Asset inventory, 03 Severity matrix, 04 Escalation and contacts, 05 Change calendar
- 06 to 10 Runbooks (phishing, credential compromise, web attack, data exfiltration, scanning)
- 11 VPN log, 12 Domain controller log, 13 Web server log, 14 Perimeter firewall log, 15 Internal firewall log, 16 Email gateway log
- 17 IDS alert summary, 18 User directory, 19 DHCP lease log, 20 Log source coverage sheet

## How to cite
- Log files: file name plus line number. Line 1 is the first log line inside the code block.
- Tables: file name plus the row ID (alert ID, asset tag, change ID, username) and for runbooks the step number.

## Notes
- Read file 20 before comparing times. Logs do not all use the same time zone.
- Test questions are given separately by the organizers.
