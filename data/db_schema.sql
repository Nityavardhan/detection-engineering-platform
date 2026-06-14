-- Techniques master table
CREATE TABLE IF NOT EXISTS techniques (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    tactic          TEXT NOT NULL,
    description     TEXT,
    threat_groups   TEXT,   -- JSON array as text
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Detection validation results
CREATE TABLE IF NOT EXISTS detections (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id        TEXT NOT NULL,
    test_timestamp      DATETIME NOT NULL,
    detection_result    TEXT NOT NULL,   -- 'DETECTED', 'MISSED', 'PARTIAL'
    severity            TEXT,
    triggered_rules     TEXT,            -- JSON array as text
    event_ids_observed  TEXT,            -- JSON array as text
    false_positive_risk TEXT,
    evidence_path       TEXT,
    playbook_path       TEXT,
    report_path         TEXT,
    notes               TEXT,
    FOREIGN KEY (technique_id) REFERENCES techniques(technique_id)
);

-- Compliance mappings
CREATE TABLE IF NOT EXISTS compliance_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    framework       TEXT NOT NULL,   -- 'NIST_CSF', 'CIS_v8', 'ISO_27001'
    control_id      TEXT NOT NULL,
    control_name    TEXT,
    mapping_note    TEXT,
    FOREIGN KEY (technique_id) REFERENCES techniques(technique_id)
);

-- Threat hunt log
CREATE TABLE IF NOT EXISTS hunts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hunt_id         TEXT NOT NULL,   -- e.g. 'HUNT-001'
    hypothesis      TEXT,
    technique_id    TEXT,
    status          TEXT,            -- 'OPEN', 'CONFIRMED', 'NOT_FOUND'
    findings        TEXT,
    hunt_date       DATETIME,
    analyst         TEXT
);