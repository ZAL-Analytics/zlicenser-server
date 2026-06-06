CREATE TABLE IF NOT EXISTS transfer_requests (
    id                         BLOB PRIMARY KEY,
    license_id                 BLOB NOT NULL REFERENCES licenses(id),
    old_fingerprint_commitment BLOB NOT NULL,
    new_fingerprint_commitment BLOB NOT NULL,
    requested_at               INTEGER NOT NULL,
    status                     TEXT NOT NULL,
    vendor_note                TEXT,
    resolved_at                INTEGER
);
