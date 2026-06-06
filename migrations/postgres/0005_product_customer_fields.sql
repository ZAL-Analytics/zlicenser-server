CREATE TABLE IF NOT EXISTS product_customer_fields (
    id          UUID PRIMARY KEY,
    product_id  UUID NOT NULL REFERENCES products(id),
    field_key   TEXT NOT NULL,
    required    BOOLEAN NOT NULL,
    gdpr_basis  TEXT NOT NULL,
    UNIQUE (product_id, field_key)
);
