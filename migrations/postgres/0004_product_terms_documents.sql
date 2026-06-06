CREATE TABLE IF NOT EXISTS product_terms_documents (
    id                           UUID PRIMARY KEY,
    product_id                   UUID NOT NULL REFERENCES products(id),
    typst_source                 TEXT NOT NULL,
    rendered_hash                TEXT NOT NULL,
    validation_status            TEXT NOT NULL,
    validation_findings          TEXT NOT NULL,
    vendor_acknowledged_at       BIGINT,
    vendor_acknowledged_findings TEXT,
    activated_at                 BIGINT,
    created_at                   BIGINT NOT NULL
);
