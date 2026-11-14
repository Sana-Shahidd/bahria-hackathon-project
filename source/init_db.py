"""
Create the database tables and the admin user.

    python source/init_db.py           # create tables (safe to re-run)
    python source/init_db.py --reset   # delete everything and start fresh (SQLite only)
"""
import os
import sys

from werkzeug.security import generate_password_hash

import db
from config import ADMIN_USERNAME, ADMIN_PASSWORD, PROJECT_ROOT, SQLITE_PATH


NEW_COLUMNS = {"incidents": {"notified_at": "TIMESTAMP"}}


def ensure_schema():
    """Add columns introduced after a database was created (safe to call every start)."""
    for table, columns in NEW_COLUMNS.items():
        for column, col_type in columns.items():
            try:
                if db.IS_SQLITE:
                    existing = [row[1] for row in db._run(f"PRAGMA table_info({table})", fetch="all")]
                    if existing and column not in existing:
                        db._run(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
                else:
                    db._run(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {col_type}")
            except Exception as error:
                print(f"[SCHEMA] could not add {table}.{column}: {error}")


def init(reset=False):
    if db.IS_SQLITE:
        if reset and os.path.exists(SQLITE_PATH):
            os.remove(SQLITE_PATH)
            print(f"Deleted {SQLITE_PATH}")
        schema_file = os.path.join(PROJECT_ROOT, "database", "schema_sqlite.sql")
        conn = db.get_db_connection()
        with open(schema_file, "r") as file:
            conn.executescript(file.read())
        conn.commit()
        conn.close()
    else:
        if reset:
            print("--reset is only supported for SQLite. Drop the PostgreSQL tables manually.")
        schema_file = os.path.join(PROJECT_ROOT, "database", "schema.sql")
        conn = db.get_db_connection()
        cur = conn.cursor()
        with open(schema_file, "r") as file:
            cur.execute(file.read())
        conn.commit()
        cur.close()
        conn.close()

    ensure_schema()
    db.upsert_user(ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD))
    os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)
    print(f"Database ready ({'SQLite: ' + SQLITE_PATH if db.IS_SQLITE else 'PostgreSQL'}).")
    print(f"Login: {ADMIN_USERNAME} / {ADMIN_PASSWORD}")


if __name__ == "__main__":
    init(reset="--reset" in sys.argv)
