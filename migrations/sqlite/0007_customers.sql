CREATE TABLE IF NOT EXISTS customers (
    id           BLOB PRIMARY KEY,
    product_id   BLOB NOT NULL REFERENCES products(id),
    full_name    TEXT NOT NULL,
    email        TEXT NOT NULL,
    field_values TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
