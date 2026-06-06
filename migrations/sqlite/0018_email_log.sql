CREATE TABLE IF NOT EXISTS email_log (
    id            BLOB PRIMARY KEY,
    license_id    BLOB NOT NULL REFERENCES licenses(id),
    email_type    TEXT NOT NULL,
    sent_to       TEXT NOT NULL,
    sent_at       INTEGER NOT NULL,
    success       INTEGER NOT NULL CHECK (success IN (0, 1)),
    error_message TEXT
);
