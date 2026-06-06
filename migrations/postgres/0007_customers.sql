CREATE TABLE IF NOT EXISTS customers (
    id           UUID PRIMARY KEY,
    product_id   UUID NOT NULL REFERENCES products(id),
    full_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    field_values TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    updated_at   BIGINT NOT NULL
);
