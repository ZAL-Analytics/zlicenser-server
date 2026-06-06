CREATE TABLE IF NOT EXISTS product_term_declarations (
    product_id         UUID PRIMARY KEY REFERENCES products(id),
    warranty           TEXT NOT NULL,
    refund             TEXT NOT NULL,
    revocation         TEXT NOT NULL,
    expiry             TEXT NOT NULL,
    support_available  BOOLEAN NOT NULL,
    support_channels   TEXT NOT NULL,
    response_sla_hours BIGINT,
    support_scope      TEXT,
    support_coverage   TEXT,
    updates_policy     TEXT NOT NULL
);
