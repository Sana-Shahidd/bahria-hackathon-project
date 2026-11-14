# IncidentPilot — Guide for Judges

**Challenge C: Security Incident Triage Assistant**
*Detects attacks. Explains them. Tells you what to do next.*

---

## 1. The 30-second pitch

Small teams can install an intrusion detection system (IDS), but nobody has time to read its
alerts. An IDS says "SQL Injection from 192.168.56.10" a hundred times a day. It does not say
whether that matters, whether it is real, or what to do about it.

**IncidentPilot** adds an AI security analyst, **Pilot**, on top of a working IDS. Pilot:

- groups scattered alerts into **incidents**
- ranks them **P1–P4**
- says whether each is a **real attack or a false positive**
- shows the **evidence** behind every conclusion
- recommends **what to do next**

A human approves or dismisses each recommendation, and Pilot **learns from that decision**.

---

## 2. The problem we are solving

| Pain point | What happens today | What IncidentPilot does |
|---|---|---|
| **Alert overload** | Hundreds of separate rows; important ones get buried | Alerts are grouped into incidents and sorted by urgency |
| **No context** | "Port scan" and "SQL injection" look like two unrelated events | Pilot recognises *reconnaissance followed by exploitation* as one attack chain → P1 |
| **False positives** | The IT team's own scanner triggers the same alarms every week | Analysts dismiss it once; Pilot remembers and marks it "likely false positive" next time |
| **"What do I do now?"** | Junior analysts don't know the next step | Concrete next steps for every incident, mapped to MITRE ATT&CK |
| **Blind automation** | The original IDS auto-blocked IPs, which risks blocking real users | AI *recommends*, a human *approves*: safe automation |
| **Reporting** | Writing an incident report takes an hour | One click: a report with timeline, evidence, impact and actions |
| **"Did they get in?"** | Failed-login alerts hide the one login that worked | Pilot flags a **successful login right after a brute force** as a likely account compromise (P1) |

**Who it's for:** university labs, small offices, startups and student SOC teams. These are places with an IDS but no full-time security analyst.

---

## 3. How it works (end to end)

```text
 1. DETECT      Live network traffic, a replayed demo, or an uploaded web-server log
                → detection rules (SQLi, XSS, port scan, flood, brute force, web scan)
 2. GROUP       Alerts from the same IP within 10 minutes become ONE incident with a timeline
 3. TRIAGE      Pilot (AI) → summary, priority P1–P4, verdict, confidence, MITRE ATT&CK,
                evidence (alert IDs), next steps, recommended action
 4. ALERT       New P1 → red pop-up in the dashboard (+ optional Slack/Discord message)
 5. DECIDE      Analyst clicks Approve (block the IP) or Dismiss (false positive)
 6. LEARN       That decision is fed into future triage of similar incidents
                and into threshold-tuning suggestions
 7. COMMUNICATE Ask Pilot chat, daily briefing, one-click incident report
```

---

## 4. What we reused vs what we built

We started from **CyberPulse**, an open-source IDS/IPS graduation project by Sude Güngör, and we
credit it in the README. Being clear about this is important.

| Reused from CyberPulse | Built by our team |
|---|---|
| Packet sniffer and detection signatures (SQLi, XSS, port scan, traffic flood, brute force) | Incident grouping (alerts → incidents) |
| Flask dashboard pages: stats, IP lists, blocked IPs, logs, settings | AI triage engine (LLM + offline engine), prompts, output validation |
| PostgreSQL schema for attacks / blocked IPs / IP lists | Human approval workflow (Approve / Dismiss / Reopen) |
| Visual style | Feedback learning loop |
| | Ask Pilot assistant (floating widget, 3 agents, action buttons) |
| | Daily AI briefing, incident reports (PDF/Markdown) |
| | Access-log upload with compromise detection, new "Web Scan" detection |
| | P1 pop-ups and webhook, similar incidents, smart threshold tuning |
| | SQLite support, demo replay, hashed logins, CSRF protection, safe firewall module, 14 tests |

**In short:** CyberPulse is the *eyes*. Everything that *thinks* is ours.

---

## 5. Features in detail

Each feature below lists **what it does**, **how it works**, **where it lives in the code**, and **what to show the judges**.

### 5.1 Detection engine (kept and improved)
- **What:** catches SQL injection, XSS, port scans, traffic floods and brute-force logins.
- **How:** regex signatures and time-window counters (e.g. more than 5 different ports in 5 seconds = port scan).
- **What we changed:** packet parsing is separated from analysis (`analyze_traffic()`), so the **same rules** run on live packets, demo replay and uploaded logs. Thresholds hot-reload from Settings.
- **Code:** `source/sniffer.py`

### 5.2 Demo replay (runs anywhere)
- **What:** replays a realistic attack scenario on any laptop, with no VM lab, root access or firewall needed.
- **How:** `data/demo_scenario.json` describes the steps: port scan → SQL injection, XSS attempts, a brute force, a traffic spike, and the IT team's weekly scanner. It also seeds "yesterday", when an analyst dismissed that scanner. Each step goes through the real detection code.
- **Code:** `source/replay.py` · **Run:** `python source/replay.py --reset`

### 5.3 Bring your own logs ⭐
- **What:** upload an **Nginx/Apache access log** (Logs page). Pilot finds attacks in it and triages them.
- **Detects:** SQLi/XSS in URLs; **brute force**; **a successful login right after failed attempts** (likely compromise); **directory scans** (many different 404s, e.g. gobuster); HTTP floods; attack-tool user agents (sqlmap, nikto, hydra…) noted as evidence.
- **Why it matters:** anyone can try it with their own server logs, not just our demo.
- **Code:** `source/log_ingest.py` · **Sample:** `data/sample_access.log`
- **Show:** upload the sample → 192.168.56.88 becomes **P1 "treat the account as compromised"**.

### 5.4 Alerts → incidents
- **What:** alerts from the same source IP within 10 minutes are grouped into one incident with a timeline, attack types, first and last seen, and the highest severity.
- **How:** every saved alert calls `attach_alert()`, which finds an open incident for that IP inside the time window or creates a new one.
- **Code:** `source/incidents.py`, `incidents` table

### 5.5 AI triage, the core
For every incident Pilot produces:

| Output | Example |
|---|---|
| **Summary** | "192.168.56.10 triggered 3 alerts: Port Scan then SQL Injection. This looks like reconnaissance followed by an exploitation attempt." |
| **Priority** | P1 (act now) · P2 (act today) · P3 (monitor) · P4 (noise) |
| **Verdict + confidence** | True positive · Likely false positive · Needs review, e.g. 88% |
| **MITRE ATT&CK** | T1046 Network Service Discovery, T1190 Exploit Public-Facing Application (clickable) |
| **Evidence** | "alert #4: SQL Injection … DROP TABLE users" (click → highlights that row) |
| **Next steps** | "Review database logs for the targeted endpoint; confirm no data was returned" |
| **Recommended action** | Block IP · Monitor · No action |

- **How:** Pilot receives only facts from the database: the alerts, this IP's history, whitelist/blacklist status, and past analyst decisions on similar incidents. It must answer in a strict JSON format. `normalize()` checks every field and repairs anything invalid.
- **Code:** `source/ai/triage.py` (prompt, context, offline engine, validation)

### 5.6 Works with or without an AI provider
- **Offline engine (default):** a rule-based scorer that produces the **same output format**. It weights attack type, recon→exploit chains, repeat attempts, thresholds reached, compromise signals and analyst feedback. It needs no internet and no API key, so the demo cannot fail on venue Wi-Fi.
- **LLM mode:** Google **Gemini** or any **OpenAI-compatible** API (OpenAI, Groq, OpenRouter, local Ollama), switched in `.env`. If the LLM fails, it automatically falls back to the offline engine.
- **Transparency:** every result shows which engine produced it.
- **Code:** `source/ai/llm.py`

### 5.7 Human in the loop: Approve / Dismiss
- **What:** when a threshold is reached, the system creates a **block recommendation**, not a block. The analyst clicks:
  - **Approve:** blocks the IP on the firewall and marks the alerts "blocked"
  - **Dismiss:** marks the incident as a false positive (optionally whitelists the IP)
  - **Reopen:** undoes the decision and re-triages
- A Settings switch restores the original instant auto-block if wanted.
- **Safety:** demo mode only *simulates* firewall changes.
- **Code:** `source/incidents.py`, `source/firewall.py`

### 5.8 Learning from analyst feedback ⭐
- **What:** Pilot uses past human decisions as ground truth.
- **How:** when triaging, the 5 most similar past decisions (same IP first, then the same attack pattern) are added to Pilot's context:
  - same IP dismissed before → **P4 likely false positive**
  - same IP confirmed before → **"repeat offender"**, priority goes up
  - same pattern dismissed elsewhere → priority goes down a level
- The incident page shows a green **"Learned from analyst feedback"** box linking to the past incident and the analyst's note.
- **No model training is needed**, so it works instantly from the first decision.
- **Show:** the IT scanner (192.168.56.5) is P4 because it was dismissed "yesterday".

### 5.9 Similar incidents
- **What:** a panel on every incident page that lists related incidents from the last 30 days: same IP, same attack pattern, or overlapping types, with their status.
- **Why:** gives the analyst context ("we've seen this before; it was dismissed / confirmed").
- **Code:** `db.get_similar_incidents()`

### 5.10 Ask Pilot, the floating assistant ⭐
- **What:** a floating button on every page (like the helper widgets in modern SaaS tools) that opens a chat panel.
- **Three agents:** 🛡 **Triage** (explain and prioritise), 📄 **Report** (write reports), ☀ **Briefing** (summarise the day).
- **Page-aware quick questions**, for example:
  - Dashboard: "What's most urgent?"
  - Incident page: "Is this a false positive?"
  - Settings: "Are my thresholds too noisy?"
- **Answers from live data only**, citing `[INC-2]` and `[alert #4]`, which become clickable links.
- **Action buttons inside answers:** Open · **Approve & block** · Dismiss · Report. You can act straight from the chat.
- **Example questions:** "What happened in the last hour?" · "Which IP is most dangerous?" · "Why is 192.168.56.10 P1?" · "Is it safe to unblock 192.168.56.10?"
- **Code:** `source/ai/chat.py`, `source/templates/_pilot_widget.html`

### 5.11 Daily AI briefing
- **What:** a card at the top of the dashboard, for example: "5 incidents today, 3 need attention… Start with INC-2 (P1)… 3 block recommendations waiting for approval." It includes P1–P4 counts, the top source and a "Start with top incident" button.
- **Code:** `source/ai/briefing.py`

### 5.12 One-click incident report
- **What:** a printable report (browser → Save as PDF) or a `.md` download.
- **Contents:** summary table, executive summary, timeline, impact, MITRE, evidence, actions taken (who decided and when), recommendations.
- **Accuracy:** facts (timeline, IPs, decisions) come **directly from the database**. The AI writes only the narrative, so numbers can't be hallucinated.
- **Code:** `source/ai/report.py`, `templates/report.html`

### 5.13 P1 alerts
- **What:** when an incident is triaged as P1, a **red pop-up** appears on whatever page the analyst is on (Open / Dismiss). It can also post to **Slack or Discord** via a webhook (`NOTIFY_WEBHOOK_URL`). Each incident notifies only once.
- **Code:** `source/notifications.py`, `/api/alerts/critical`

### 5.14 Smart threshold tuning
- **What:** the Settings page shows Pilot's suggestions based on the last 7 days of decisions. For example: "Port Scan: 2 dismissed / 0 confirmed (100% false positives) → raise the threshold from 5 to 8 or whitelist 192.168.56.5", with an **Apply** button.
- **Why:** this closes the loop. Analyst feedback improves not just the AI but the detection rules themselves.
- **Code:** `source/ai/tuning.py`

### 5.15 Security hardening (things we fixed)
- Passwords are **hashed**. The original project compared plain-text passwords and its `users` table was missing from the schema.
- **CSRF protection** on every form and API call; delete / unblock / reset now require POST.
- Firewall commands use argument lists (no shell), with IP validation.
- **Attack payloads are escaped** everywhere. Alerts contain `<script>` payloads, so we escape before rendering to stop the dashboard itself being attacked.
- Login rate limiting; upload size limit (20 MB).

### 5.16 Tests
- 14 automated tests cover grouping, the time window, P1 attack chains, feedback learning, approve/block, similar incidents, repair of bad AI output, log ingestion with compromise detection, tuning, chat, CSRF, XSS escaping and page rendering.
- **Run:** `python -m unittest discover -s tests -v`

---

## 6. Folder-by-folder tour

```text
IncidentPilot/
├── README.md                 Overview, quick start, screenshots, credits
├── requirements.txt          Python packages (Flask, Markdown; scapy/psycopg2 optional)
├── rules_config.json         Detection thresholds + "require analyst approval" switch
├── .env.example              All settings: AI provider/keys, demo mode, webhook, DB
│
├── source/                   ── the application ──
│   ├── app.py                Web server: all pages, APIs, CSRF, background auto-triage worker
│   ├── config.py             Reads settings from .env (safe defaults: SQLite, demo mode, offline AI)
│   ├── db.py                 Database layer (SQLite or PostgreSQL) + all queries
│   ├── sniffer.py            Detection engine (signatures, time windows, approval mode)
│   ├── firewall.py           Block/unblock IPs (simulated in demo mode)
│   ├── incidents.py          Group alerts into incidents; approve / dismiss / reopen
│   ├── log_ingest.py         Analyse uploaded Nginx/Apache logs
│   ├── notifications.py      P1 alerts to Slack/Discord
│   ├── replay.py             Demo attack scenario player
│   ├── init_db.py            Creates tables + admin user; upgrades old databases
│   ├── main.py               Starts the live packet sensor (needs root, real network)
│   │
│   ├── ai/                   ── Pilot's brain ──
│   │   ├── llm.py            Talks to Gemini / OpenAI-compatible APIs (no SDK needed)
│   │   ├── triage.py         Triage prompt, context builder, offline engine, output validation
│   │   ├── chat.py           Ask Pilot: answers questions, adds action buttons
│   │   ├── briefing.py       Daily briefing
│   │   ├── report.py         Incident reports
│   │   └── tuning.py         Noisy-rule detection and threshold suggestions
│   │
│   ├── templates/            ── web pages ──
│   │   ├── dashboard.html    Stats, charts, AI briefing card
│   │   ├── incidents.html    Incident queue (sorted by priority, live refresh)
│   │   ├── incident_detail.html  Triage, evidence, timeline, decision, similar incidents
│   │   ├── report.html       Printable report
│   │   ├── _pilot_widget.html    Ask Pilot assistant + P1 pop-ups (on every page)
│   │   ├── logs.html         Attack logs + "Upload access log"
│   │   ├── settings.html     Thresholds, approval mode, tuning suggestions
│   │   └── login / ip_lists / blocked_ips / _sidebar / _pilot_styles
│   └── static/vendor/        Bootstrap + Chart.js stored locally (works without internet)
│
├── data/
│   ├── demo_scenario.json    Demo attacks + "yesterday's" dismissed scanner
│   └── sample_access.log     Web log with scan + sqlmap, brute force → successful login, flood, XSS
│
├── database/
│   ├── schema_sqlite.sql     Default database (zero setup)
│   ├── schema.sql            PostgreSQL version
│   └── migrate_from_cyberpulse.sql  Upgrade an existing CyberPulse database
│
├── tests/test_incidentpilot.py   14 automated tests
│
├── docs/
│   ├── JUDGES_GUIDE.md       This document
│   ├── idea.md               Problem and pitch
│   ├── PRD.md                Product requirements and acceptance criteria
│   ├── TRD.md                Technical design: architecture, data model, API, security
│   ├── context.md            Brief for teammates / AI coding tools
│   ├── progress.md           What's done, what's next
│   ├── DEMO_SCRIPT.md        5-minute demo
│   └── images/               Screenshots
│
└── logs/                     Runtime alert and blocked-IP logs
```

---

## 7. Technology

| Area | Choice |
|---|---|
| Backend | Python 3, Flask |
| Database | SQLite (default) or PostgreSQL |
| Detection | Regex signatures + time-window counters; Scapy for live packets |
| AI | Google Gemini or any OpenAI-compatible model; built-in offline engine |
| Frontend | Jinja templates, Bootstrap 5, Chart.js, vanilla JavaScript |
| Security frameworks | MITRE ATT&CK mapping |

---

## 8. Responsible AI: how we keep Pilot trustworthy

1. **Grounded:** Pilot only sees data from our database and is told never to invent alerts or IPs.
2. **Verifiable:** every claim cites an alert ID you can click and check.
3. **Validated:** AI output must match a strict format; invalid fields are replaced by safe values.
4. **Human decides:** AI never blocks anyone by itself.
5. **Facts vs narrative:** reports take numbers and timelines from the database, not from the AI.
6. **Transparent:** every result shows which engine produced it.
7. **Safe rendering:** attack payloads (and AI text) are escaped before display, which protects against prompt-injected HTML.
8. **Fails safely:** if the AI is unavailable, the offline engine takes over automatically.

---

## 9. Five-minute demo path

1. **Dashboard**: the AI briefing and a red P1 pop-up.
2. **Incident queue**: 8 alerts became 5 incidents, sorted P1 → P4.
3. **P1 incident**: recon → SQL injection chain, clickable evidence, MITRE, next steps → **Approve**.
4. **P4 incident**: the IT scanner, with the "Learned from analyst feedback" box.
5. **Ask Pilot**: "Which IP is most dangerous?" → approve from the chat.
6. **Upload `sample_access.log`** → P1 **account compromise** detected.
7. **Report** → Save as PDF. **Settings** → tuning suggestion → Apply.

(Full script: `docs/DEMO_SCRIPT.md`)

---

## 10. Questions judges may ask

**Q: Isn't this just a chatbot on top of a database?**
A: No. The chat is one of seven outputs. The core is the pipeline: detect → group → triage → human decision → learn → tune rules. The triage runs automatically in the background with no chat needed.

**Q: How do you stop the AI hallucinating?**
A: Grounded context, required alert-ID citations, strict output validation, and facts in reports taken from the database. The offline engine is fully deterministic.

**Q: What if the AI is wrong and blocks a real user?**
A: It can't. Pilot only recommends; blocking needs a human click. Whitelisted IPs can never be blocked from the approval flow.

**Q: How does it "learn" without training a model?**
A: Analyst decisions are stored and injected as examples into every future triage of a similar incident (in-context learning). It works from the very first decision and also feeds the threshold-tuning suggestions.

**Q: Did you build the IDS yourselves?**
A: The detection layer comes from the open-source CyberPulse project, credited in our README. We restructured it so it runs on live traffic, replays and uploaded logs, and we added web-scan and compromise detection. Everything AI, the incident model, the workflow, the assistant, the reports, the alerts, tuning, security fixes and tests are our work.

**Q: Does it need internet or a paid API?**
A: No. The offline engine runs everything. Plugging in Gemini (free tier) or Groq gives richer explanations.

**Q: Can it work on real data?**
A: Yes: the live sensor (`sudo python source/main.py`) or uploading any Nginx/Apache access log.

**Q: Why P1–P4 and not just High/Medium/Low?**
A: The old severity only counted attempts. Our priority considers the attack chain, repeats, compromise signals, history and analyst feedback, and it maps to *when* to act.

---

## 11. Limitations and future work

- Single admin role; add analyst/admin roles and an audit-log page.
- More log sources: SSH `auth.log`, Windows Event Logs, firewall logs.
- Email notifications (webhook already works).
- Tested with a mock AI server and the offline engine. Test with a real Gemini key before the final demo.
