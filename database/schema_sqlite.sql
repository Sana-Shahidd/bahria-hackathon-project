-- IncidentPilot schema (SQLite — default, zero setup)
-- Original CyberPulse tables (attacks, blocked_ips, ip_lists) are kept as-is,
-- plus: users (was missing in the original), incidents (AI triage), incident_id on attacks.

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    created_at TIMESTAMP DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(50) NOT NULL,
    target_ip VARCHAR(50),
    source_port INTEGER,
    target_port INTEGER,
    protocol VARCHAR(20),
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    status VARCHAR(30) DEFAULT 'detected',
    action_taken VARCHAR(50) DEFAULT 'none',
    detected_at TIMESTAMP DEFAULT (datetime('now','localtime')),
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(50) NOT NULL UNIQUE,
    block_reason VARCHAR(100),
    blocked_at TIMESTAMP DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS ip_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(50) NOT NULL,
    list_type VARCHAR(20) NOT NULL,
    reason VARCHAR(100),
    created_at TIMESTAMP DEFAULT (datetime('now','localtime')),
    UNIQUE (ip_address, list_type)
);

CREATE INDEX IF NOT EXISTS idx_attacks_incident ON attacks(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(source_ip, last_seen);
