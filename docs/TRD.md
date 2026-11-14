# IncidentPilot — Technical Requirements Document (TRD)

## 1. Architecture

```text
  Live traffic (Scapy, root)         Demo replay (data/demo_scenario.json)
            │                                   │
            ▼                                   ▼
  sniffer.packet_info()  ──────►  sniffer.analyze_traffic()   ◄── same detection rules
                                     │ SQLi / XSS / port scan / flood / brute force
                                     ▼
                              db.save_to_db()  ──► attacks table
                                     │
                                     ▼
                         incidents.attach_alert()  ──► incidents table (group by IP + 10 min)
                                     │ needs_triage = 1
                                     ▼
            app.py background worker / replay / page open
                                     │
                                     ▼
                         ai/triage.triage_incident()
                 context: alerts + IP history + analyst feedback + lists
                    ├── LLM (Gemini or OpenAI-compatible) → JSON → normalize()
                    └── offline engine (rule-based scoring) ← fallback / default
                                     │
                                     ▼
          Flask UI: queue · incident detail · approve/dismiss · report · briefing · Ask Pilot
                                     │
                     approve → firewall.block_ip_iptables (simulated in DEMO_MODE)
                     dismiss → false positive → feeds future triage (feedback loop)
```

## 2. Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.10+ | Same as CyberPulse |
| Web | Flask 3 + Jinja templates | Reuse existing dashboard |
| DB | **SQLite** (default) or PostgreSQL | Zero-setup demo; Postgres for the original lab |
| Sensor | Scapy (optional) | Live mode only |
| AI | Gemini REST or any OpenAI-compatible API via `urllib` | No SDK dependency; swap providers via `.env` |
| UI libs | Bootstrap 5.3 and Chart.js 4, **vendored** in `source/static/vendor` | Works without internet |
| Markdown | `Markdown` package | Reports and chat rendering |

## 3. Modules

| File | Responsibility | Origin |
|---|---|---|
| `source/config.py` | All settings from env / `.env` | Rewritten |
| `source/db.py` | SQLite/Postgres layer (translates `%s` and `::date`), original queries, plus users, incidents, feedback | Extended |
| `source/sniffer.py` | Detection rules; `analyze_traffic()` split from packet parsing; approval mode; `record_brute_force()` | Extended |
| `source/firewall.py` | iptables via `subprocess` (no shell), blocked-IP file, DEMO_MODE | New (merged two copies) |
| `source/incidents.py` | Grouping, approve, dismiss, reopen | New |
| `source/ai/llm.py` | Provider client, JSON mode, error → `LLMError` | New |
| `source/ai/triage.py` | Context builder, system prompt, offline engine, normaliser, worker entry | New |
| `source/ai/chat.py` | Ask Pilot: context, LLM answer, offline intents, action buttons | New |
| `source/ai/briefing.py` | Daily briefing (60 s cache) | New |
| `source/ai/report.py` | Report = DB facts + AI narrative | New |
| `source/app.py` | Original routes, plus incidents, API and background worker | Extended |
| `source/replay.py` | Demo scenario runner (history seeding plus traffic steps) | New |
| `source/init_db.py` | Create schema and admin user (hashed password); `ensure_schema()` upgrades old DBs | New |
| `source/log_ingest.py` | Parse Nginx/Apache logs: SQLi/XSS, brute force + success-after-failures, web scan, flood, tool UAs | New |
| `source/notifications.py` | P1 notification (once per incident) to Slack/Discord webhook | New |
| `source/ai/tuning.py` | Noisy-rule detection from analyst decisions and threshold suggestions | New |
| `tests/test_incidentpilot.py` | 14 unit/integration tests (stdlib `unittest`) | New |

## 4. Data model

Original tables `attacks`, `blocked_ips` and `ip_lists` are unchanged except for **`attacks.incident_id`**.

**users**: `id, username UNIQUE, password_hash, created_at` (missing in the original repo; passwords are now hashed).

**incidents**

| Column | Notes |
|---|---|
| `source_ip, first_seen, last_seen, alert_count, attack_types (csv), max_severity` | Grouping |
| `needs_triage (0/1), triage_status (pending/triaged/error)` | Worker queue |
| `ai_summary, ai_verdict, ai_priority, ai_confidence` | Triage result |
| `ai_mitre, ai_evidence, ai_next_steps, ai_feedback_used` | JSON text |
| `ai_recommended_action (block_ip/monitor/no_action), ai_engine, triaged_at` | |
| `notified_at` | When the P1 alert was sent (prevents repeats) |
| `analyst_status (new/approved/dismissed), analyst_verdict, analyst_notes, decided_by, decided_at` | Human decision = feedback |

New alert statuses: `pending_approval` (action `block_recommended`) and `dismissed`.

## 5. Triage contract

Input context: incident header, all alerts (id, time, type, severity, target, status, description
with a payload excerpt), other incidents from the same IP (7 days), whitelist/blacklist/blocked
flags, and up to 5 similar past analyst decisions (same IP scores highest, then overlapping attack types).

Output JSON (validated by `normalize()`; invalid fields fall back to offline values):

```json
{"summary": "...", "verdict": "true_positive|likely_false_positive|needs_review",
 "priority": "P1|P2|P3|P4", "confidence": 0.0,
 "mitre": [{"id": "T1190", "name": "..."}], "evidence": ["alert #12: ..."],
 "next_steps": ["..."], "recommended_action": "block_ip|monitor|no_action",
 "feedback_used": [1], "reasoning": "..."}
```

Offline scoring: base by type (SQLi 40, Brute 35, XSS 30, Flood 25, Scan 15); +20 for a recon→exploit
chain; +5 for multiple types; +3 per alert (max 15); +10 if a threshold was hit. Feedback: same-IP
false positive caps the score at P4; same-IP confirmed adds +15; same-pattern false positive subtracts 15.
Score ≥ 70 → P1, ≥ 45 → P2, ≥ 25 → P3, otherwise P4.

## 6. HTTP API

| Method | Route | Purpose |
|---|---|---|
| GET | `/incidents?status=new\|approved\|dismissed\|all&priority=P1` | Queue |
| GET | `/incidents/<id>` | Detail (auto-triages if pending) |
| POST | `/incidents/<id>/approve` | form or JSON `{notes, block}` |
| POST | `/incidents/<id>/dismiss` | form or JSON `{notes, whitelist}` |
| POST | `/incidents/<id>/reopen`, `/incidents/<id>/retriage`, `/incidents/triage-pending` | |
| GET | `/incidents/<id>/report`, `/incidents/<id>/report.md` | Report |
| GET | `/api/pilot/briefing[?refresh=1]` | Briefing JSON |
| POST | `/api/pilot/chat` | `{message, page, incident_id, agent}` → `{answer, answer_html, actions, engine}` |
| GET | `/api/incidents/summary` | Live refresh key |
| GET | `/api/alerts/critical` | Open P1 incidents (toasts) |
| POST | `/ingest-log` | Multipart upload `logfile` → alerts, incidents, triage |
| POST | `/settings/apply-suggestion` | `rule`, `value` from the tuning card |

Send the header `X-Requested-With: fetch` (or a JSON body) to get JSON back from approve/dismiss.
Every POST needs the CSRF token: the form field `csrf_token` or the header `X-CSRF-Token` (added automatically to `fetch()` by the widget).

## 7. Security notes

- Passwords hashed (Werkzeug); `SECRET_KEY` from env; login rate-limited after 5 failures.
- iptables called with argument lists (no shell) and IP validation.
- All markdown is rendered with HTML escaped first, because attack payloads contain `<script>`.
- LLM output never triggers actions by itself; actions require an analyst click.
- CSRF token on every POST (session-bound, constant-time compare); all state-changing routes are POST-only.
- Uploads are capped at 20 MB and parsed as text only (never executed).
- Remaining gap: single admin role (no RBAC). Add it before multi-user deployment.

## 8. Configuration (`.env`)

`DB_ENGINE`, `DEMO_MODE`, `LLM_PROVIDER` (offline/gemini/openai), `GEMINI_API_KEY`, `GEMINI_MODEL`,
`OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`, `INCIDENT_WINDOW_MINUTES`, `AUTO_TRIAGE`,
`IDS_INTERFACE`, `MONITORED_NETWORK`, `IDS_HOST_IP`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`. See `.env.example`.

## 9. Testing done

- `python -m unittest discover -s tests -v`: 14 tests (grouping, time window, P1 chain, feedback learning,
  approve/block, similar incidents, LLM output repair, log ingestion incl. compromise, tuning, chat, CSRF,
  XSS escaping, page rendering).

- Full replay, then every page returns HTTP 200 (Flask test client).
- Approve, dismiss, reopen, retriage, settings save, brute-force via login.
- XSS payloads render escaped in the report and the chat.
- LLM path tested against a mock OpenAI-compatible server (valid JSON, fenced JSON, server down → offline fallback); Gemini request shape verified with a stub.
- Not tested here: a real Gemini/OpenAI key, live Scapy sniffing, PostgreSQL mode.
