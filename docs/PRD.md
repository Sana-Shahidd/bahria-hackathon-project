# IncidentPilot — Product Requirements Document (PRD)

| | |
|---|---|
| Product | IncidentPilot — AI Security Incident Triage Assistant |
| Challenge | C: Security Incident Triage Assistant |
| Base | CyberPulse IDS/IPS (detection engine and dashboard reused) |
| Status | MVP complete (see `progress.md`) |

## 1. Problem statement

Small organisations can deploy an IDS but cannot staff a SOC. Raw alerts are noisy, disconnected
and unexplained. Analysts waste time deciding *what matters*, *whether it is real* and *what to do*.
Blind auto-blocking (as in the original CyberPulse) risks blocking legitimate users and tools.

## 2. Goals

1. Cut the time from "alert fired" to "analyst knows what to do" to **under 1 minute**.
2. Turn alerts into **incidents** with a clear story.
3. Make every AI conclusion **verifiable** by citing the alerts behind it.
4. Keep a **human in the loop** for every blocking decision.
5. **Learn** from analyst decisions to reduce repeat false positives.
6. **Run anywhere**: offline demo mode with no root access, no VM lab and no API key.

### Non-goals (MVP)

- Replacing a full SIEM, or multi-tenant / multi-sensor deployment
- Training a custom ML model (feedback is applied at prompt/rule level)
- Automatic remediation beyond IP blocking

## 3. Users

| Persona | Need |
|---|---|
| **Junior SOC analyst / IT admin** (primary) | "Tell me what's urgent, why, and what to click." |
| **Team lead / manager** | Daily picture and a shareable report per incident. |
| **Student / hackathon judge** | See the whole loop working in 5 minutes on a laptop. |

## 4. User stories and acceptance criteria

### Must-have

**F1 — AI incident summary**
*As an analyst I want a plain-English summary of each incident.*
- [x] Every triaged incident has a 1–2 sentence summary a non-expert understands.
- [x] It mentions multi-stage behaviour (e.g. "reconnaissance followed by exploitation").

**F2 — Group alerts into incidents**
- [x] Alerts from the same source IP within `INCIDENT_WINDOW_MINUTES` (default 10) join one incident.
- [x] The incident shows a timeline of its alerts, its attack types, first and last seen, and an alert count.
- [x] Decided incidents are closed; new activity opens a new incident.

**F3 — AI priority P1–P4 with reasons**
- [x] P1 = active exploitation, P2 = clear attempt, P3 = suspicious, P4 = noise.
- [x] The queue is sorted open-first, then by priority.

**F4 — True / false positive verdict**
- [x] Verdict is one of `true_positive`, `likely_false_positive` or `needs_review`, with a 0–100% confidence.

**F5 — Recommended actions, human-approved**
- [x] Recommendation is one of: block IP, monitor, no action. Plus 2–5 concrete next steps.
- [x] With "analyst approval" mode on (default), a threshold hit creates a *block recommendation*, not a block.
- [x] **Approve** blocks the IP (firewall + DB) and marks alerts blocked. **Dismiss** marks them as false positive (optional whitelist).
- [x] Approval mode can be turned off in Settings to restore the original auto-block behaviour.

**Evidence and MITRE**
- [x] Each evidence line starts with `alert #id`; clicking it highlights the timeline row.
- [x] MITRE ATT&CK technique tags link to attack.mitre.org.

### Strong extras

**F6 — Ask Pilot (chat with your incidents)**
- [x] A floating assistant appears on every page, with quick actions that depend on the page.
- [x] It answers questions such as "What happened in the last hour?", "Which IP is most dangerous?" and "Why is X P1?" from live DB data, citing `[INC-n]` and `[alert #n]`.
- [x] Answers include buttons: Open, Approve & block, Dismiss, Report.
- [x] It has three agent tabs (Triage, Report, Briefing), each the same brain with a different focus.

**F10 — One-click incident report**
- [x] A printable HTML report (browser → Save as PDF) and a `.md` download.
- [x] Facts (timeline, IPs, MITRE, decision) come from the DB; only the narrative is AI-written.

### Wow factor

**F11 — Learning from analyst feedback**
- [x] Past decisions on the same IP or the same attack pattern are injected into triage.
- [x] The UI shows a "Learned from analyst feedback" box linking to the past incident and its notes.
- [x] Demo: yesterday's dismissed IT scan means today's scan from the same host is triaged P4 "likely false positive".

**F12 — Daily AI briefing**
- [x] A dashboard card shows today's incident count, P1–P4 breakdown, items awaiting approval, top source and where to start.

**Bonus:** "Are my thresholds too noisy?" uses dismissal rates by attack type to suggest tuning.

## 5. Kept from CyberPulse (unchanged features)

Live packet sniffing (Scapy); SQLi/XSS signatures; port-scan, traffic-flood and brute-force
detection; whitelist/blacklist; blocked-IP management; log filtering and CSV export; rule settings;
dashboard charts.

## 6. Success metrics (for the demo)

- Replay → triaged queue in **< 15 s**.
- 5/5 demo incidents receive a correct priority ordering (P1 recon+SQLi at the top, IT scanner at the bottom).
- 0 hallucinated alert IDs (evidence is validated against the DB in offline mode; the LLM is instructed to cite only given IDs).

## 7. Risks and mitigations

| Risk | Mitigation |
|---|---|
| LLM down, no key or no internet at the venue | Offline engine gives the same output shape; the UI shows which engine was used |
| LLM hallucination | Strict prompt, facts-only context, alert-ID citations, deterministic report facts |
| Prompt injection via attacker payloads | Payloads are treated as data inside the context; all model output is HTML-escaped before rendering |
| Wrong block | Human approval by default; whitelist always wins; demo mode never touches iptables |
| Running the sensor needs root and a lab | `replay.py` drives the same detection code with recorded attacks |
