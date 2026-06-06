CREATE TABLE IF NOT EXISTS quarantine_cases (
    id           UUID PRIMARY KEY,
    case_id      UUID NOT NULL UNIQUE,
    binding_id   UUID NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id   UUID REFERENCES active_sessions(id),
    trigger      TEXT NOT NULL,
    triggered_at BIGINT NOT NULL,
    status       TEXT NOT NULL,
    resolution   TEXT,
    resolved_at  BIGINT,
    vendor_note  TEXT
);
