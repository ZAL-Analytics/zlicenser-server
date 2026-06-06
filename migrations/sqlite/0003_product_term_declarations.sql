CREATE TABLE IF NOT EXISTS product_term_declarations (
    product_id         BLOB PRIMARY KEY REFERENCES products(id),
    warranty           TEXT NOT NULL,
    refund             TEXT NOT NULL,
    revocation         TEXT NOT NULL,
    expiry             TEXT NOT NULL,
    support_available  INTEGER NOT NULL CHECK (support_available IN (0, 1)),
    support_channels   TEXT NOT NULL,
    response_sla_hours INTEGER,
    support_scope      TEXT,
    support_coverage   TEXT,
    updates_policy     TEXT NOT NULL
);
