CREATE TABLE IF NOT EXISTS vendor_config (
    id                     BIGINT PRIMARY KEY CHECK (id = 1),
    public_key             BYTEA NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    registered_at          BIGINT NOT NULL,
    rotated_from_key       BYTEA,
    rotated_at             BIGINT
);
