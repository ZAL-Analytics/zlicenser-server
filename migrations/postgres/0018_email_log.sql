CREATE TABLE IF NOT EXISTS email_log (
    id            UUID PRIMARY KEY,
    license_id    UUID NOT NULL REFERENCES licenses(id),
    email_type    TEXT NOT NULL,
    sent_to       TEXT NOT NULL,
    sent_at       BIGINT NOT NULL,
    success       BOOLEAN NOT NULL,
    error_message TEXT
);
