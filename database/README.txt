Database files for IncidentPilot.

- schema_sqlite.sql           : default schema (SQLite, used automatically - zero setup)
- schema.sql                  : PostgreSQL schema (set DB_ENGINE=postgres)
- migrate_from_cyberpulse.sql : upgrade an existing CyberPulse PostgreSQL database

Create tables + admin user:   python source/init_db.py
Wipe and start fresh:         python source/init_db.py --reset
