-- Drop in reverse-dependency order.
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS quarantine_cases;

CREATE TABLE quarantine_cases (
    id               UUID   PRIMARY KEY,
    case_id          UUID   NOT NULL UNIQUE,
    binding_id       UUID   NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id       UUID   REFERENCES active_sessions(id),
    trigger          TEXT   NOT NULL,
    -- event_id of the SecurityEventRecord that opened this case, if any.
    trigger_event_id UUID,
    reason           TEXT   NOT NULL,
    created_at       BIGINT NOT NULL,
    resumed_at       BIGINT
);

CREATE TABLE security_events (
    id             BIGSERIAL PRIMARY KEY,
    event_id       UUID   NOT NULL UNIQUE,
    license_id     UUID   NOT NULL REFERENCES licenses(id),
    binding_id     UUID   NOT NULL REFERENCES fingerprint_seat_bindings(id),
    session_id     UUID   REFERENCES active_sessions(id),
    occurred_at_ns BIGINT NOT NULL,
    received_at_ns BIGINT NOT NULL,
    -- Serialised SecurityEventType tag, e.g. 'DebuggerDetected'.
    event_type     TEXT   NOT NULL,
    -- Full JSON payload of the SecurityEventType variant.
    payload        TEXT   NOT NULL,
    severity       TEXT   NOT NULL,
    -- SecurityResponse variant returned: 'Log' | 'Warn' | 'Quarantine' | 'Terminate'.
    response_type  TEXT   NOT NULL,
    case_id        UUID   REFERENCES quarantine_cases(case_id),
    reviewed_at    BIGINT
);

CREATE INDEX idx_security_events_license ON security_events (license_id);
