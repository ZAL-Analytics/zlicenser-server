CREATE TABLE IF NOT EXISTS fingerprint_seat_bindings (
    id                     BLOB PRIMARY KEY,
    license_id             BLOB NOT NULL REFERENCES licenses(id),
    fingerprint_commitment BLOB NOT NULL,
    seat_index             INTEGER NOT NULL,
    bound_at               INTEGER NOT NULL,
    last_verified_at       INTEGER,
    revoked_at             INTEGER
);
