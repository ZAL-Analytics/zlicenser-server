CREATE TABLE IF NOT EXISTS payment_transactions (
    id                      BLOB PRIMARY KEY,
    license_id              BLOB NOT NULL REFERENCES licenses(id),
    provider                TEXT NOT NULL,
    provider_transaction_id TEXT NOT NULL,
    amount                  INTEGER NOT NULL,
    currency                TEXT NOT NULL,
    provider_tier           TEXT NOT NULL,
    test_mode               INTEGER NOT NULL CHECK (test_mode IN (0, 1)),
    status                  TEXT NOT NULL,
    created_at              INTEGER NOT NULL,
    confirmed_at            INTEGER
);
