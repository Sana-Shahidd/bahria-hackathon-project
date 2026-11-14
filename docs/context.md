# IncidentPilot — Context (read this first)

This file is the quick-start brief for any teammate **or AI coding assistant** (Claude, Cursor,
Copilot, Gemini) working on this repo. Paste it into the chat before asking for changes.

## What this project is
An **AI Security Incident Triage Assistant** (hackathon Challenge C). It is built on CyberPulse, a
Flask + Scapy IDS/IPS. The IDS detects attacks. IncidentPilot groups them into incidents and has an
AI analyst ("Pilot") explain, prioritise and recommend actions. A human approves or dismisses, and
those decisions feed back into future triage.

## How to run (zero setup)
```bash
pip install -r requirements.txt          # scapy / psycopg2 only needed for live sensor / Postgres
python source/replay.py --reset          # create DB + replay demo attacks + triage
python source/app.py                     # http://127.0.0.1:5000  (admin / admin123)
```
Optional AI: copy `.env.example` to `.env`, then set `LLM_PROVIDER=gemini` and `GEMINI_API_KEY=...`.

## Golden rules for changes
1. **Don't break the offline path.** Every AI feature must work with `LLM_PROVIDER=offline`.
   LLM calls are wrapped in try/except and fall back to the rule-based engine.
2. **Facts come from the DB, not the model.** Evidence must cite `alert #<id>`; reports build
   tables from DB rows; the LLM only writes narrative.
3. **Escape before rendering.** Alert descriptions contain attack payloads (`<script>`). Use
   `safe_markdown()` in `app.py` and keep Jinja autoescape on. Never use `|safe` on model output.
4. **Humans decide blocks.** With `require_analyst_approval` on, detection only *recommends*.
   Only `incidents.approve_incident()` blocks.
5. **Same detection code for live and demo.** Add new rules in `sniffer.analyze_traffic()`, not in replay.
6. **SQL style:** write psycopg2-style `%s` placeholders; `db.py` translates for SQLite. Use `db._run()`.
7. **CSRF:** every POST form needs `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`;
   fetch() calls get the header automatically from `_pilot_widget.html`.
8. New pages: include `_pilot_styles.html`, `_sidebar.html` (set `active`) and
   `_pilot_widget.html`; pass `pilot_page` (and `pilot_incident_id` on incident pages).

## File map
```text
source/
  app.py            Flask routes (original + incidents/API) and auto-triage worker
  config.py         settings from env/.env
  db.py             SQLite/Postgres layer, all queries
  sniffer.py        detection engine (analyze_traffic, record_brute_force)
  firewall.py       iptables + blocked_ips.txt (DEMO_MODE simulates)
  incidents.py      grouping + approve/dismiss/reopen
  replay.py         demo scenario runner
  log_ingest.py     Nginx/Apache access-log analysis (upload or CLI)
  notifications.py  P1 webhook (Slack/Discord)
  init_db.py        schema + admin user
  main.py           live sensor entry (sudo)
  ai/llm.py         Gemini / OpenAI-compatible client
  ai/triage.py      prompt, context, offline engine, normalize
  ai/chat.py        Ask Pilot answers + action buttons
  ai/briefing.py    daily briefing
  ai/report.py      incident report markdown
  ai/tuning.py      noisy-rule detection + threshold suggestions
  templates/        original pages + incidents.html, incident_detail.html, report.html,
                    _pilot_widget.html, _pilot_styles.html, _sidebar.html
  static/vendor/    bootstrap.min.css, chart.umd.min.js
data/demo_scenario.json   demo attacks + yesterday's dismissed IT scan (feedback demo)
data/sample_access.log    access log: gobuster+sqlmap (.66), brute force then SUCCESS (.88), flood (.99), XSS (.23)
tests/                    python -m unittest discover -s tests -v
database/                 schema.sql (Postgres), schema_sqlite.sql, migrate_from_cyberpulse.sql
docs/                     idea, PRD, TRD, progress, context, DEMO_SCRIPT
```

## Key vocabulary
- **Alert** = one row in `attacks` (one detection).
- **Incident** = alerts from one source IP within 10 min (`incidents` table).
- **Triage** = AI result on an incident: summary, verdict, priority, confidence, MITRE, evidence, next steps, recommended action.
- **Feedback** = analyst approve/dismiss and notes, injected into later triage of similar incidents.
- **Engine** = which brain produced a result (`Gemini (...)`, a model name, or `Pilot offline engine`).

## Demo IPs (data/demo_scenario.json + data/sample_access.log)
| IP | Story | Expected triage |
|---|---|---|
| 192.168.56.10 | port scan → SQL injection | **P1** true positive, block |
| 192.168.56.77 | brute force on login | P2 true positive, block |
| 192.168.56.23 | XSS on /search | P2 true positive, block |
| 192.168.56.40 | traffic spike | P3 needs review, monitor |
| 192.168.56.5 | IT scanner; dismissed yesterday | **P4** likely false positive (learned) |
| 192.168.56.66 | (log) gobuster dir scan → sqlmap SQLi | **P1** recon → exploit |
| 192.168.56.88 | (log) 9 failed logins → **successful login** → data export | **P1** account compromise |
| 192.168.56.99 | (log) HTTP flood | P3 needs review |
