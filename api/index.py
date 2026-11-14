"""Vercel entry point: serves the IncidentPilot Flask app (demo mode, SQLite in /tmp)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "source"))
os.environ.setdefault("SQLITE_PATH", "/tmp/incidentpilot.db")   # the deployment file system is read-only except /tmp
os.environ.setdefault("DEMO_MODE", "true")
os.environ.setdefault("AUTO_TRIAGE", "false")
os.environ.setdefault("LLM_PROVIDER", "offline")
os.environ.setdefault("PACK_DIR", os.path.join(ROOT, "problem_c_data"))

import shutil  # noqa: E402

# Everything the app writes must live in /tmp on Vercel.
os.makedirs("/tmp/logs", exist_ok=True)
shutil.copy(os.path.join(ROOT, "rules_config.json"), "/tmp/rules_config.json")
os.environ.setdefault("LOGS_DIR", "/tmp/logs")
os.environ.setdefault("RULES_FILE", "/tmp/rules_config.json")

import init_db  # noqa: E402

try:
    init_db.init()
except OSError as error:   # e.g. cannot create logs/ on a read-only disk; the DB itself is already ready
    print("init warning:", error)

from app import app  # noqa: E402,F401
