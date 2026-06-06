CREATE TABLE IF NOT EXISTS fingerprint_seat_bindings (
    id                     UUID PRIMARY KEY,
    license_id             UUID NOT NULL REFERENCES licenses(id),
    fingerprint_commitment BYTEA NOT NULL,
    seat_index             BIGINT NOT NULL,
    bound_at               BIGINT NOT NULL,
    last_verified_at       BIGINT,
    revoked_at             BIGINT
);
