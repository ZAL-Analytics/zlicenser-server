CREATE TABLE IF NOT EXISTS issuance_secrets (
    license_id  UUID PRIMARY KEY REFERENCES licenses(id),
    secret      BYTEA NOT NULL,
    created_at  BIGINT NOT NULL
);
