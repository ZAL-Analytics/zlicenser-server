CREATE TABLE IF NOT EXISTS revocation_records (
    license_id  UUID PRIMARY KEY REFERENCES licenses(id),
    revoked_at  BIGINT NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT
);
