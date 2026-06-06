CREATE TABLE IF NOT EXISTS active_sessions (
    id                UUID PRIMARY KEY,
    binding_id        UUID NOT NULL REFERENCES fingerprint_seat_bindings(id),
    ephemeral_pubkey  BYTEA NOT NULL,
    issued_at         BIGINT NOT NULL,
    expires_at        BIGINT NOT NULL,
    last_heartbeat_at BIGINT,
    seq_no            BIGINT NOT NULL DEFAULT 0,
    status            TEXT NOT NULL
);
