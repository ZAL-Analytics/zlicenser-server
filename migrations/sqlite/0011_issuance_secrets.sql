CREATE TABLE IF NOT EXISTS issuance_secrets (
    license_id  BLOB PRIMARY KEY REFERENCES licenses(id),
    secret      BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);
