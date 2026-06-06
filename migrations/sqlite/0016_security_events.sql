CREATE TABLE IF NOT EXISTS security_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       BLOB NOT NULL UNIQUE,
    license_id     BLOB NOT NULL REFERENCES licenses(id),
    binding_id     BLOB NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id     BLOB REFERENCES active_sessions(id),
    occurred_at_ns INTEGER NOT NULL,
    received_at_ns INTEGER NOT NULL,
    event_type     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    payload        TEXT NOT NULL,
    response       TEXT NOT NULL,
    reviewed_by    TEXT,
    reviewed_at    INTEGER,
    case_id        BLOB REFERENCES quarantine_cases(case_id)
);
