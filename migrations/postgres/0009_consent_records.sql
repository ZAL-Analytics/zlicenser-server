CREATE TABLE IF NOT EXISTS consent_records (
    id                    UUID PRIMARY KEY,
    customer_id           UUID NOT NULL REFERENCES customers(id),
    license_id            UUID NOT NULL REFERENCES licenses(id),
    terms_document_id     UUID NOT NULL REFERENCES product_terms_documents(id),
    terms_rendered_hash   TEXT NOT NULL,
    checkboxes_ticked     TEXT NOT NULL,
    accepted_at_ns        BIGINT NOT NULL,
    ip_address            TEXT NOT NULL,
    client_version        TEXT NOT NULL,
    protocol_version      BIGINT NOT NULL,
    terms_findings_shown  TEXT NOT NULL,
    payment_provider      TEXT NOT NULL,
    payment_provider_tier TEXT NOT NULL
);
