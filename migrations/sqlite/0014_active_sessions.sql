CREATE TABLE IF NOT EXISTS active_sessions (
    id                BLOB PRIMARY KEY,
    binding_id        BLOB NOT NULL REFERENCES fingerprint_seat_bindings(id),
    ephemeral_pubkey  BLOB NOT NULL,
    issued_at         INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    last_heartbeat_at INTEGER,
    seq_no            INTEGER NOT NULL DEFAULT 0,
    status            TEXT NOT NULL
);
