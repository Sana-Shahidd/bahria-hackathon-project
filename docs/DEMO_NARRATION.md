# IncidentPilot demo — narration script

Video length: **2:19**. Read each line while its scene is on screen (about 2.5 words per second, calm pace).
Change "Hi, I'm Sana" to your team intro if you present together.

| Time | Scene | Say this |
|---|---|---|
| 0:00–0:05 | Title | Hi, I'm Sana. This is IncidentPilot, an AI security incident triage assistant. |
| 0:05–0:14 | News: Microsoft | In October, Microsoft reported hackers using AI agents against more than 2,250 Microsoft 365 tenants, sometimes getting in within three hours. |
| 0:14–0:24 | News: NCERT warns banks | And on November 5th, Pakistan's National CERT warned banks to watch for automated logins, failed authentications and unusual API requests. |
| 0:24–0:30 | The problem | Attacks move at machine speed. Teams can't read every alert. So we built an AI analyst. |
| 0:30–0:37 | Dashboard | The dashboard opens with Pilot's daily briefing, and a P1 alert appears the moment it's found. |
| 0:37–0:44 | Incident queue | Raw alerts are grouped into incidents, and Pilot ranks them from P1 to P4. |
| 0:44–0:52 | AI triage | Here, a port scan followed by SQL injection. Pilot recognises the attack chain and maps it to MITRE ATT&CK. |
| 0:52–0:58 | Evidence | Every claim links to a real alert, so nothing is made up. |
| 0:58–1:04 | Human in the loop | Pilot recommends a block, but I decide. One click, and the attacker is blocked. |
| 1:04–1:12 | Learns from feedback | This port scan is our own IT scanner. It was dismissed yesterday, so Pilot now marks it as a likely false positive. |
| 1:12–1:19 | Ask Pilot | I can simply ask: which IP is most dangerous? And approve right from the chat. |
| 1:19–1:24 | Banking demo | Now, the attack NCERT warned banks about. |
| 1:24–1:29 | Bring your own logs | I upload the access log from a banking API. |
| 1:29–1:35 | Seconds later | Within seconds: two P1 incidents and live alerts. |
| 1:35–1:43 | Account compromise | A bot failed twelve logins, then got in. Pilot flags the account as compromised. |
| 1:43–1:51 | API attack chain | Another IP probed hidden APIs, then ran sqlmap. Recon, then exploit: P1. |
| 1:51–1:57 | One-click report | One click gives a report for management, with facts straight from the database. |
| 1:57–2:03 | Smarter rules | Our decisions even tune the detection rules, cutting false alarms. |
| 2:03–2:13 | NCERT advice → IncidentPilot | Monitoring bot logins, watching API activity, keeping incident logs, faster response: IncidentPilot does what NCERT asks banks to do. |
| 2:13–2:19 | Closing | IncidentPilot. It detects attacks, explains them, and tells you what to do next. |

## How to add your voice
1. Open `IncidentPilot_demo.mp4` in CapCut, Clipchamp (Windows) or iMovie.
2. Record the voice-over track there while the video plays, or record it on your phone and drop the audio in.
3. Optional: import `IncidentPilot_narration.srt` as subtitles; it is already timed to the scenes.
4. Export as 1080p or 720p MP4.

## Sources used in the video
- Microsoft / Storm-0940: CSO Online, "China-linked hackers used agentic AI in attack on 2,250 Microsoft 365 tenants" (Microsoft blog post, 21 Oct 2026)
- Pakistan NCERT advisory (5 Nov 2026): The Express Tribune, "AI tools increase cyberattack risks", 7 Nov 2026
