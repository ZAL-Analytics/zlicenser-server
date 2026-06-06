CREATE TABLE IF NOT EXISTS product_terms_documents (
    id                           BLOB PRIMARY KEY,
    product_id                   BLOB NOT NULL REFERENCES products(id),
    typst_source                 TEXT NOT NULL,
    rendered_hash                TEXT NOT NULL,
    validation_status            TEXT NOT NULL,
    validation_findings          TEXT NOT NULL,
    vendor_acknowledged_at       INTEGER,
    vendor_acknowledged_findings TEXT,
    activated_at                 INTEGER,
    created_at                   INTEGER NOT NULL
);
