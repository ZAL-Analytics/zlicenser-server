CREATE TABLE IF NOT EXISTS quarantine_cases (
    id           BLOB PRIMARY KEY,
    case_id      BLOB NOT NULL UNIQUE,
    binding_id   BLOB NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id   BLOB REFERENCES active_sessions(id),
    trigger      TEXT NOT NULL,
    triggered_at INTEGER NOT NULL,
    status       TEXT NOT NULL,
    resolution   TEXT,
    resolved_at  INTEGER,
    vendor_note  TEXT
);
