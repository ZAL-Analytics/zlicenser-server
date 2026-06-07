ALTER TABLE fingerprint_seat_bindings ADD COLUMN transfer_pending_at INTEGER;

CREATE TABLE IF NOT EXISTS enrollment_sessions (
    id                      BLOB PRIMARY KEY,
    product_id              BLOB NOT NULL REFERENCES products(id),
    fingerprint_commitment  BLOB NOT NULL,
    customer_pubkey         BLOB NOT NULL,
    client_version          TEXT NOT NULL,
    protocol_version        INTEGER NOT NULL,
    state                   TEXT NOT NULL,
    offer_nonce             BLOB,
    offer_expires_at        INTEGER,
    terms_document_id       BLOB REFERENCES product_terms_documents(id),
    request_bytes           BLOB NOT NULL,
    offer_bytes             BLOB,
    receipt_bytes           BLOB,
    payment_intent_id       TEXT,
    payment_captured        INTEGER NOT NULL DEFAULT 0,
    grant_bytes             BLOB,
    transfer_request_id     BLOB REFERENCES transfer_requests(id),
    license_id              BLOB REFERENCES licenses(id),
    abandon_reason          TEXT,
    created_at              INTEGER NOT NULL,
    updated_at              INTEGER NOT NULL
);

CREATE INDEX enrollment_sessions_payment_intent_id ON enrollment_sessions(payment_intent_id);
