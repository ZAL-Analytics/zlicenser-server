CREATE TABLE IF NOT EXISTS security_events (
    id             BIGSERIAL PRIMARY KEY,
    event_id       UUID NOT NULL UNIQUE,
    license_id     UUID NOT NULL REFERENCES licenses(id),
    binding_id     UUID NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id     UUID REFERENCES active_sessions(id),
    occurred_at_ns BIGINT NOT NULL,
    received_at_ns BIGINT NOT NULL,
    event_type     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    payload        TEXT NOT NULL,
    response       TEXT NOT NULL,
    reviewed_by    TEXT,
    reviewed_at    BIGINT,
    case_id        UUID REFERENCES quarantine_cases(case_id)
);
