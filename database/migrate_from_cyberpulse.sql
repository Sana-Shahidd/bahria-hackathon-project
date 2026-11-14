-- Upgrade an existing CyberPulse PostgreSQL database to IncidentPilot.
-- Run once:  psql -d intrusiondb -f database/migrate_from_cyberpulse.sql
-- (then run `python source/init_db.py` to create the admin user)

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    source_ip VARCHAR(50) NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    alert_count INTEGER DEFAULT 0,
    attack_types TEXT DEFAULT '',
    max_severity VARCHAR(20) DEFAULT 'Low',
    needs_triage INTEGER DEFAULT 1,
    triage_status VARCHAR(20) DEFAULT 'pending',      -- pending | triaged | error
    ai_summary TEXT,
    ai_verdict VARCHAR(30),                            -- true_positive | likely_false_positive | needs_review
    ai_priority VARCHAR(5),                            -- P1..P4
    ai_confidence REAL,
    ai_mitre TEXT,                                     -- JSON list
    ai_evidence TEXT,                                  -- JSON list
    ai_next_steps TEXT,                                -- JSON list
    ai_recommended_action VARCHAR(30),                 -- block_ip | monitor | no_action
    ai_feedback_used TEXT,                             -- JSON list of past incident ids
    ai_engine VARCHAR(80),
    triaged_at TIMESTAMP,
    analyst_status VARCHAR(20) DEFAULT 'new',          -- new | approved | dismissed
    analyst_verdict VARCHAR(30),                       -- true_positive | false_positive
    analyst_notes TEXT,
    decided_by VARCHAR(100),
    decided_at TIMESTAMP,
    notified_at TIMESTAMP,                             -- P1 alert sent (toast / webhook)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE attacks ADD COLUMN IF NOT EXISTS incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_attacks_incident ON attacks(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip, last_seen);
