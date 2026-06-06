CREATE TABLE IF NOT EXISTS transfer_requests (
    id                         UUID PRIMARY KEY,
    license_id                 UUID NOT NULL REFERENCES licenses(id),
    old_fingerprint_commitment BYTEA NOT NULL,
    new_fingerprint_commitment BYTEA NOT NULL,
    requested_at               BIGINT NOT NULL,
    status                     TEXT NOT NULL,
    vendor_note                TEXT,
    resolved_at                BIGINT
);
