DROP TABLE IF EXISTS active_sessions CASCADE;

CREATE TABLE active_sessions (
    id                         UUID    PRIMARY KEY,
    binding_id                 UUID    NOT NULL REFERENCES fingerprint_seat_bindings(id),
    license_id                 UUID    NOT NULL REFERENCES licenses(id),
    product_id                 UUID    NOT NULL REFERENCES products(id),
    -- Rolling 32-byte auth token (plain; rotated each HeartbeatAck).
    session_token              BYTEA   NOT NULL,
    -- AES-256-GCM encrypted HMAC key: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
    session_hmac_key_encrypted BYTEA   NOT NULL,
    heartbeat_interval_secs    INTEGER NOT NULL,
    heartbeat_grace_secs       INTEGER NOT NULL,
    shutdown_countdown_secs    INTEGER NOT NULL,
    seq_no                     BIGINT  NOT NULL DEFAULT 0,
    last_heartbeat_at          BIGINT,
    expires_at                 BIGINT  NOT NULL,
    status                     TEXT    NOT NULL,
    -- Vendor dashboard action queued for next heartbeat: NULL | 'Resume' | 'Terminate'.
    command_pending            TEXT,
    created_at                 BIGINT  NOT NULL,
    updated_at                 BIGINT  NOT NULL
);

CREATE INDEX idx_active_sessions_binding_status
    ON active_sessions (binding_id, status);
