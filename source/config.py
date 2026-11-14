"""
IncidentPilot configuration.

All settings can be overridden with environment variables or a `.env` file
in the project root (see `.env.example`). Defaults are chosen so the project
runs on any laptop with zero setup: SQLite database, demo mode (no iptables),
and the offline AI engine.
"""
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv(path):
    """Tiny .env loader so we don't need an extra dependency."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)


_load_dotenv(os.path.join(PROJECT_ROOT, ".env"))


def _bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def path_in_project(*parts):
    return os.path.join(PROJECT_ROOT, *parts)


# ---------------------------------------------------------------- Database
DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite").lower()          # sqlite | postgres
SQLITE_PATH = os.environ.get("SQLITE_PATH", path_in_project("data", "incidentpilot.db"))

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "intrusiondb")
DB_USER = os.environ.get("DB_USER", "postgres")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "your_password")

# ---------------------------------------------------------------- Web app
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-incidentpilot")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
DASHBOARD_HOST_IP = os.environ.get("DASHBOARD_HOST_IP", "192.168.56.104")

# ---------------------------------------------------------------- Detection / sensor
# DEMO_MODE = True never touches iptables; blocks are simulated and logged.
DEMO_MODE = _bool("DEMO_MODE", True)
IDS_INTERFACE = os.environ.get("IDS_INTERFACE", "enp0s8")
MONITORED_NETWORK = os.environ.get("MONITORED_NETWORK", "192.168.56.0/24")
IDS_HOST_IP = os.environ.get("IDS_HOST_IP", "192.168.56.112")   # sensor's own IP, ignored

RULES_FILE = os.environ.get("RULES_FILE", path_in_project("rules_config.json"))
LOGS_DIR = os.environ.get("LOGS_DIR", path_in_project("logs"))

# ---------------------------------------------------------------- Incidents
# Alerts from the same source IP within this window are grouped into one incident.
INCIDENT_WINDOW_MINUTES = int(os.environ.get("INCIDENT_WINDOW_MINUTES", "10"))
# Background worker that triages new/updated incidents automatically.
AUTO_TRIAGE = _bool("AUTO_TRIAGE", True)
AUTO_TRIAGE_INTERVAL_SECONDS = int(os.environ.get("AUTO_TRIAGE_INTERVAL_SECONDS", "10"))

# ---------------------------------------------------------------- AI (the "Pilot")
# offline  -> built-in rule-based engine (works with no key / no internet)
# gemini   -> Google Gemini API
# openai   -> any OpenAI-compatible API (OpenAI, Groq, OpenRouter, Ollama, LM Studio...)
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "offline").lower()

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

LLM_TIMEOUT_SECONDS = int(os.environ.get("LLM_TIMEOUT_SECONDS", "30"))

# ---------------------------------------------------------------- Notifications
# Slack / Discord incoming webhook for new P1 incidents (optional).
NOTIFY_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "")
# Used to build links in notifications.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "http://127.0.0.1:5000")

# ---------------------------------------------------------------- Log ingestion
# The web server the uploaded access logs belong to (used as alert target).
WEB_SERVER_IP = os.environ.get("WEB_SERVER_IP", "192.168.56.104")

# ---------------------------------------------------------------- Problem C data pack
# Folder with the 20 Orbit Logistics files (01_company_security_rules.md ... 20_log_source_coverage.md).
PACK_DIR = os.environ.get("PACK_DIR", path_in_project("problem_c_data"))
