# IncidentPilot — Idea

**Challenge:** C — Security Incident Triage Assistant

**One-liner:** *Detects attacks. Explains them. Tells you what to do next.*

## The problem

Small teams (university labs, small offices, startups) can run an intrusion detection system, but
nobody has time to read its alerts. An IDS produces a flood of rows like
`SQL Injection | 192.168.56.10 | High`. Someone still has to answer:

- Is this real, or noise?
- Which of these 40 alerts matters **first**?
- Are these 5 alerts actually **one** attack?
- What exactly should I do now?
- How do I explain this to my manager tomorrow?

That is **triage**, and it is where junior analysts lose the most time.

## The solution

IncidentPilot keeps a working IDS (the "eyes") and adds an AI analyst, **Pilot** (the "brain"):

1. **Detect:** the existing engine catches SQL injection, XSS, port scans, traffic floods and brute force.
2. **Group:** alerts from the same source within 10 minutes become one **incident** with a timeline.
3. **Triage:** Pilot gives every incident a plain-English summary, a priority (P1–P4), a
   true/false-positive verdict with confidence, MITRE ATT&CK techniques, evidence that cites real
   alert IDs, and recommended next steps.
4. **Decide:** a human approves or dismisses. Blocking happens **after** approval, not blindly.
5. **Learn:** dismissed false positives and confirmed attacks are fed back into the next triage.
   For example, an authorised IT scanner is recognised the next week.
6. **Communicate:** a daily AI briefing on the dashboard, one-click incident reports (PDF or
   Markdown), and **Ask Pilot**, a floating assistant that answers questions from the live database.

## Why it stands out

| Most hackathon triage bots | IncidentPilot |
|---|---|
| Chatbot over a static CSV | Real detection engine feeding live data |
| "Summarise this alert" | Groups alerts into incidents (recon → exploit chains) |
| AI output you have to trust | Every claim cites alert IDs you can click |
| One-way | Learns from analyst decisions (feedback loop) |
| Auto-blocks or does nothing | AI recommends, the human approves (safe automation) |
| Needs internet + API key | Works offline (built-in engine), better with Gemini/OpenAI/Groq |

## Built on

IncidentPilot extends **CyberPulse**, an open-source IDS/IPS graduation project by Sude Güngör
(https://gh.ali360.cloudns.ch/sudenurgungor/CyberPulse). We kept its detection engine and dashboard and
built the AI triage layer, incident model, analyst workflow, assistant and demo tooling on top.
See README → Credits for exactly what is reused and what is new.
