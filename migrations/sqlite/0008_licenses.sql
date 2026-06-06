CREATE TABLE IF NOT EXISTS licenses (
    id                BLOB PRIMARY KEY,
    customer_id       BLOB NOT NULL REFERENCES customers(id),
    product_id        BLOB NOT NULL REFERENCES products(id),
    bundle_version    TEXT NOT NULL,
    connectivity_mode TEXT NOT NULL,
    seat_count        INTEGER NOT NULL,
    expiry_at         INTEGER,
    status            TEXT NOT NULL,
    superseded_by     BLOB REFERENCES licenses(id),
    revoked_at        INTEGER,
    revocation_reason TEXT,
    created_at        INTEGER NOT NULL,
    email_sent_at     INTEGER
);
