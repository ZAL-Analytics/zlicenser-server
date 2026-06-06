CREATE TABLE IF NOT EXISTS product_customer_fields (
    id          BLOB PRIMARY KEY,
    product_id  BLOB NOT NULL REFERENCES products(id),
    field_key   TEXT NOT NULL,
    required    INTEGER NOT NULL CHECK (required IN (0, 1)),
    gdpr_basis  TEXT NOT NULL,
    UNIQUE (product_id, field_key)
);
