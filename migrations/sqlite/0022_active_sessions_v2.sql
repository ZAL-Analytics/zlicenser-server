DROP TABLE IF EXISTS active_sessions;

CREATE TABLE active_sessions (
    id                         BLOB    PRIMARY KEY,
    binding_id                 BLOB    NOT NULL REFERENCES fingerprint_seat_bindings(id),
    license_id                 BLOB    NOT NULL REFERENCES licenses(id),
    product_id                 BLOB    NOT NULL REFERENCES products(id),
    -- Rolling 32-byte auth token (plain; rotated each HeartbeatAck).
    session_token              BLOB    NOT NULL,
    -- AES-256-GCM encrypted HMAC key: nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
    session_hmac_key_encrypted BLOB    NOT NULL,
    heartbeat_interval_secs    INTEGER NOT NULL,
    heartbeat_grace_secs       INTEGER NOT NULL,
    shutdown_countdown_secs    INTEGER NOT NULL,
    seq_no                     INTEGER NOT NULL DEFAULT 0,
    last_heartbeat_at          INTEGER,
    expires_at                 INTEGER NOT NULL,
    status                     TEXT    NOT NULL,
    -- Vendor dashboard action queued for next heartbeat: NULL | 'Resume' | 'Terminate'.
    command_pending            TEXT,
    created_at                 INTEGER NOT NULL,
    updated_at                 INTEGER NOT NULL
);

CREATE INDEX idx_active_sessions_binding_status
    ON active_sessions (binding_id, status);
