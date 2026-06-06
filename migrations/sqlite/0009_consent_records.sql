CREATE TABLE IF NOT EXISTS consent_records (
    id                    BLOB PRIMARY KEY,
    customer_id           BLOB NOT NULL REFERENCES customers(id),
    license_id            BLOB NOT NULL REFERENCES licenses(id),
    terms_document_id     BLOB NOT NULL REFERENCES product_terms_documents(id),
    terms_rendered_hash   TEXT NOT NULL,
    checkboxes_ticked     TEXT NOT NULL,
    accepted_at_ns        INTEGER NOT NULL,
    ip_address            TEXT NOT NULL,
    client_version        TEXT NOT NULL,
    protocol_version      INTEGER NOT NULL,
    terms_findings_shown  TEXT NOT NULL,
    payment_provider      TEXT NOT NULL,
    payment_provider_tier TEXT NOT NULL
);
