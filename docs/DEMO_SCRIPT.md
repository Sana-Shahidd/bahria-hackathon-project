# IncidentPilot — 5-minute demo script

**Before judges arrive**
```bash
python source/init_db.py --reset
python source/app.py              # leave running, log in as admin / admin123
```
Open the Dashboard in one tab and keep a terminal ready.

---

**0:00 — The problem (30 s)**
> "Small teams run an IDS, but nobody has time to read 500 alerts a day. The hard part isn't
> detection, it's *triage*: what's real, what's urgent, what do I do?"

**0:30 — Live attack (45 s)**
Run in the terminal: `python source/replay.py --slow`
> "This replays real attack traffic through our detection engine: a port scan, SQL injection,
> XSS, password guessing, a traffic spike, and our own IT team's weekly scanner."

Switch to **Incidents**. The queue fills and re-sorts live.

**1:15 — Incidents, not alerts (45 s)**
> "Eight alerts became five incidents. Pilot ranked them. The top one is P1."

Open the **P1 (192.168.56.10)**.
> "Pilot noticed a port scan followed by SQL injection, which is reconnaissance and then
> exploitation. Every claim cites an alert ID." Click `alert #…` to highlight the timeline row.
> "Mapped to MITRE ATT&CK, with concrete next steps."

**2:00 — Human in the loop (30 s)**
> "Pilot recommends a block, but it doesn't block blindly like the original IDS did. I approve."
Click **Approve — real attack**.

**2:30 — It learns (45 s)**
Open the **P4 (192.168.56.5)**.
> "This is also a port scan, but it's P4 'likely false positive'. Why? Yesterday an analyst
> dismissed the same host as our authorised weekly scanner. Pilot learned from that." Point at the green feedback box.

**3:15 — Ask Pilot (45 s)**
Click the floating ✈ button. Tap **"Which IP is most dangerous?"**, then type
*"Is it safe to unblock 192.168.56.10?"*. Point out the inline **Approve / Report** buttons.

**3:45 — Bring your own logs (30 s, optional wow)**
Logs → **Upload access log** → `data/sample_access.log` → Analyse.
> "No sensor? Upload your web server log. Pilot found a directory scan followed by sqlmap, and
> someone who guessed a password 9 times and then **got in**. That's flagged P1 'account compromised'."
A red P1 toast appears; open it.

**4:00 — Report and briefing (30 s)**
Click **Report** → **Save as PDF**.
> "One click, and the manager gets a report. Facts come from the database; the AI only writes the narrative."
Go back to the **Dashboard** and show the briefing card.

**4:30 — Close (30 s)**
> "IncidentPilot: it detects attacks, explains them, and tells you what to do next. It works fully
> offline and gets smarter with Gemini or any LLM and with every decision you make."

---

**If something breaks:** `python source/replay.py --reset` rebuilds everything in about 10 seconds.
**If Wi-Fi dies:** set `LLM_PROVIDER=offline`. Every feature still works.
