CREATE TABLE IF NOT EXISTS revocation_records (
    license_id  BLOB PRIMARY KEY REFERENCES licenses(id),
    revoked_at  INTEGER NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT
);
