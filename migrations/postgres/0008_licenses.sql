CREATE TABLE IF NOT EXISTS licenses (
    id                UUID PRIMARY KEY,
    customer_id       UUID NOT NULL REFERENCES customers(id),
    product_id        UUID NOT NULL REFERENCES products(id),
    bundle_version    TEXT NOT NULL,
    connectivity_mode TEXT NOT NULL,
    seat_count        BIGINT NOT NULL,
    expiry_at         BIGINT,
    status            TEXT NOT NULL,
    superseded_by     UUID REFERENCES licenses(id),
    revoked_at        BIGINT,
    revocation_reason TEXT,
    created_at        BIGINT NOT NULL,
    email_sent_at     BIGINT
);
