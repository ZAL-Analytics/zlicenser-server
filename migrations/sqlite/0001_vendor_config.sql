CREATE TABLE IF NOT EXISTS vendor_config (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    public_key             BLOB NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    registered_at          INTEGER NOT NULL,
    rotated_from_key       BLOB,
    rotated_at             INTEGER
);
