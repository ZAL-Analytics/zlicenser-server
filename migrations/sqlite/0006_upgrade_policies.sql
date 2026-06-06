CREATE TABLE IF NOT EXISTS upgrade_policies (
    id            BLOB PRIMARY KEY,
    product_id    BLOB NOT NULL REFERENCES products(id),
    from_version  TEXT NOT NULL,
    to_version    TEXT NOT NULL,
    policy        TEXT NOT NULL,
    UNIQUE (product_id, from_version, to_version)
);
