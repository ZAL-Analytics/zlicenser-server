ALTER TABLE fingerprint_seat_bindings ADD COLUMN transfer_pending_at BIGINT;

CREATE TABLE IF NOT EXISTS enrollment_sessions (
    id                      UUID PRIMARY KEY,
    product_id              UUID NOT NULL REFERENCES products(id),
    fingerprint_commitment  BYTEA NOT NULL,
    customer_pubkey         BYTEA NOT NULL,
    client_version          TEXT NOT NULL,
    protocol_version        BIGINT NOT NULL,
    state                   TEXT NOT NULL,
    offer_nonce             BYTEA,
    offer_expires_at        BIGINT,
    terms_document_id       UUID REFERENCES product_terms_documents(id),
    request_bytes           BYTEA NOT NULL,
    offer_bytes             BYTEA,
    receipt_bytes           BYTEA,
    payment_intent_id       TEXT,
    payment_captured        BOOLEAN NOT NULL DEFAULT FALSE,
    grant_bytes             BYTEA,
    transfer_request_id     UUID REFERENCES transfer_requests(id),
    license_id              UUID REFERENCES licenses(id),
    abandon_reason          TEXT,
    created_at              BIGINT NOT NULL,
    updated_at              BIGINT NOT NULL
);

CREATE INDEX enrollment_sessions_payment_intent_id ON enrollment_sessions(payment_intent_id);
