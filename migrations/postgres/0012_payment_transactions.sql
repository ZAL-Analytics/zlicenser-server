CREATE TABLE IF NOT EXISTS payment_transactions (
    id                      UUID PRIMARY KEY,
    license_id              UUID NOT NULL REFERENCES licenses(id),
    provider                TEXT NOT NULL,
    provider_transaction_id TEXT NOT NULL,
    amount                  BIGINT NOT NULL,
    currency                TEXT NOT NULL,
    provider_tier           TEXT NOT NULL,
    test_mode               BOOLEAN NOT NULL,
    status                  TEXT NOT NULL,
    created_at              BIGINT NOT NULL,
    confirmed_at            BIGINT
);
