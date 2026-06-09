-- Drop in reverse-dependency order.
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS quarantine_cases;

CREATE TABLE quarantine_cases (
    id               BLOB    PRIMARY KEY,
    case_id          BLOB    NOT NULL UNIQUE,
    binding_id       BLOB    NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id       BLOB    REFERENCES active_sessions(id),
    trigger          TEXT    NOT NULL,
    -- event_id of the SecurityEventRecord that opened this case, if any.
    trigger_event_id BLOB,
    reason           TEXT    NOT NULL,
    created_at       INTEGER NOT NULL,
    resumed_at       INTEGER
);

CREATE TABLE security_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       BLOB    NOT NULL UNIQUE,
    license_id     BLOB    NOT NULL REFERENCES licenses(id),
    binding_id     BLOB    NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id     BLOB    REFERENCES active_sessions(id),
    occurred_at_ns INTEGER NOT NULL,
    received_at_ns INTEGER NOT NULL,
    -- Serialised SecurityEventType tag, e.g. 'DebuggerDetected'.
    event_type     TEXT    NOT NULL,
    -- Full JSON payload of the SecurityEventType variant.
    payload        TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    -- SecurityResponse variant returned: 'Log' | 'Warn' | 'Quarantine' | 'Terminate'.
    response_type  TEXT    NOT NULL,
    case_id        BLOB    REFERENCES quarantine_cases(case_id),
    reviewed_at    INTEGER
);

CREATE INDEX idx_security_events_license ON security_events (license_id);
