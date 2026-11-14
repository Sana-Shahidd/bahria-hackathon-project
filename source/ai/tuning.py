"""
Smart threshold suggestions: learn from analyst decisions which detection rules
are noisy (mostly dismissed as false positives) and suggest new thresholds.
Shown on the Settings page (one-click Apply) and answered by Ask Pilot.
"""
import json
from datetime import datetime, timedelta

import db
from config import RULES_FILE

# attack type -> (rule key, step to raise the threshold by)
RULE_FOR_TYPE = {
    "Port Scan": ("port_scan_threshold", 3),
    "High Traffic": ("high_traffic_threshold", 20),
    "SQL Injection": ("sql_block_threshold", 1),
    "XSS Attack": ("xss_block_threshold", 1),
}
NOISY_FP_RATE = 0.5


def _rules():
    try:
        with open(RULES_FILE, "r") as file:
            return json.load(file)
    except Exception:
        return {}


def get_threshold_suggestions(days=7):
    incidents = db.list_incidents(since=datetime.now() - timedelta(days=days), limit=1000)
    rules = _rules()
    stats = {}
    for inc in incidents:
        if inc["analyst_status"] not in ("approved", "dismissed"):
            continue
        for attack_type in inc["attack_type_list"]:
            entry = stats.setdefault(attack_type, {"dismissed": 0, "approved": 0, "ips": set()})
            entry[inc["analyst_status"]] += 1
            if inc["analyst_status"] == "dismissed":
                entry["ips"].add(inc["source_ip"])

    suggestions = []
    for attack_type, entry in sorted(stats.items()):
        total = entry["dismissed"] + entry["approved"]
        fp_rate = entry["dismissed"] / total if total else 0
        item = {
            "attack_type": attack_type,
            "dismissed": entry["dismissed"],
            "approved": entry["approved"],
            "fp_rate": round(fp_rate * 100),
            "noisy": fp_rate >= NOISY_FP_RATE,
            "rule": None, "current": None, "suggested": None,
            "dismissed_ips": sorted(entry["ips"]),
        }
        if attack_type in RULE_FOR_TYPE:
            key, step = RULE_FOR_TYPE[attack_type]
            item["rule"] = key
            item["current"] = rules.get(key)
            if item["noisy"] and item["current"] is not None:
                item["suggested"] = int(item["current"]) + step

        if item["noisy"]:
            tips = []
            if item["suggested"]:
                tips.append(f"raise `{item['rule']}` from {item['current']} to {item['suggested']}")
            if item["dismissed_ips"]:
                tips.append("whitelist known-good sources (" + ", ".join(item["dismissed_ips"][:3]) + ")")
            item["advice"] = "Noisy: " + " or ".join(tips) if tips else "Noisy rule"
        else:
            item["advice"] = "Looks well tuned"
        suggestions.append(item)
    return suggestions


def apply_suggestion(rule_key, value):
    rules = _rules()
    if rule_key not in {k for k, _ in RULE_FOR_TYPE.values()}:
        return False
    rules[rule_key] = max(1, int(value))
    with open(RULES_FILE, "w") as file:
        json.dump(rules, file, indent=4)
    return True


def suggestions_markdown(days=7):
    items = get_threshold_suggestions(days)
    if not items:
        return ("No analyst decisions in the last 7 days yet, so I can't judge the thresholds. "
                "Approve or dismiss a few incidents first.")
    lines = [f"**Threshold check (last {days} days of analyst decisions):**"]
    for i in items:
        lines.append(f"- **{i['attack_type']}**: {i['dismissed']} dismissed / {i['approved']} confirmed "
                     f"({i['fp_rate']}% false positives) -> {i['advice']}")
    lines.append("\nYou can apply these with one click on the **Settings** page.")
    return "\n".join(lines)
