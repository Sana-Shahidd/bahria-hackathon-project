# IncidentPilot — Progress

Last updated: 2026-11-13

## Status: MVP feature-complete ✅ (runs end-to-end in demo mode)

### Foundation
- [x] Forked CyberPulse into IncidentPilot (rebranded UI, credits kept)
- [x] Config via `.env` (`source/config.py`, `.env.example`)
- [x] SQLite by default, PostgreSQL still supported (`db.py` adapter)
- [x] `users` table added (it was missing in the original) with hashed passwords, plus `init_db.py`
- [x] Shared `firewall.py` (subprocess, no shell) and `DEMO_MODE`
- [x] Detection split into `analyze_traffic()` so live packets and replay use the same rules
- [x] Demo replay (`replay.py` + `data/demo_scenario.json`) including past analyst feedback
- [x] Bootstrap and Chart.js vendored, so the UI works offline

### Must-have (Challenge C core)
- [x] F1 AI incident summary
- [x] F2 Group alerts into incidents (+ timeline)
- [x] F3 AI priority P1–P4 with reasons
- [x] F4 True/false positive verdict and confidence
- [x] F5 Recommended actions, human approval (Approve / Dismiss / Reopen)

### Extras
- [x] F6 Ask Pilot floating assistant (page-aware quick actions, 3 agent tabs, action buttons)
- [x] F10 One-click incident report (print/PDF and .md)
- [x] F11 Learning from analyst feedback (shown in the UI)
- [x] F12 Daily AI briefing card on the dashboard
- [x] Bonus: threshold-noise check in chat; MITRE links; clickable evidence
- [x] Background auto-triage worker

### Added in v0.2
- [x] **Bring your own logs**: upload an Nginx/Apache access log (Logs page) or run `python source/log_ingest.py file.log`
  - SQLi/XSS, brute force **and a successful login right after it (compromise → P1)**, directory scans (new "Web Scan" type, MITRE T1595.003), HTTP floods, attack-tool user agents
  - Sample log: `data/sample_access.log`
- [x] **P1 alerts**: red toast on every page, plus optional Slack/Discord webhook (`NOTIFY_WEBHOOK_URL`)
- [x] **Similar incidents** panel on the incident page (same IP / same pattern, 30 days)
- [x] **Smart threshold tuning**: Settings shows noisy rules learned from analyst decisions, with one-click **Apply**
- [x] **Security hardening**: CSRF tokens on every POST; unblock / delete / reset routes are now POST-only
- [x] **Automatic DB upgrade**: old databases get new columns on start (`ensure_schema`)
- [x] **14 unit tests**: `python -m unittest discover -s tests -v`

### Verified
- [x] All pages return 200 after replay; approve/dismiss/reopen/retriage work
- [x] Browser test: upload log, approve, dismiss, apply tuning, unblock, list delete, reset blocks (all with CSRF)
- [x] XSS payloads escaped in report and chat
- [x] LLM path tested with a mock OpenAI-compatible server and fallback when down

## Next (if time allows), in priority order
- [ ] Test with a real Gemini key (`LLM_PROVIDER=gemini`); tune the prompt on the demo data
- [ ] Rehearse the demo (`DEMO_SCRIPT.md`) 3× and time it under 5 minutes
- [ ] Multi-user roles (analyst vs admin) and an audit log page
- [ ] Email notifications (webhook already done)
- [ ] Windows Event Log / SSH auth.log ingestion

## Suggested team split
| Person | Owns |
|---|---|
| A — Detection & data | `sniffer.py`, `replay.py`, scenario JSON, DB |
| B — AI | `ai/` prompts, Gemini testing, offline engine tuning |
| C — UI & demo | templates, Ask Pilot widget, slides, demo script |

## Changelog
- **2026-11-13**: v0.2. Log upload, P1 alerts + webhook, similar incidents, tuning suggestions, CSRF, unit tests.
- **2026-11-13**: v0.1. CyberPulse → IncidentPilot: incidents, AI triage, approval workflow, Ask Pilot, briefing, reports, feedback learning, replay, docs.

## v0.3 - Problem C data pack (2026-11-14)
- [x] `source/pack/`: loader (20 files, file:line + row-ID citations), time zone normalisation from file 20, deterministic correlation engine, report in file-01 format, cited Q&A (LLM + offline), citation verifier
- [x] `/pack` Orbit Triage board: overview, timeline (UTC + PKT), attack-path graph, evidence (Confirmed / Suspected / Not enough evidence), actions + escalation clock, log coverage strip, cross-checks, Ask the data
- [x] Ask Pilot widget routes Orbit questions to the pack engine; `PACK_DIR` env var; 10 new tests (`python -m unittest tests.test_pack`)
