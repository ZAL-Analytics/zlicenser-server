ALTER TABLE security_events ADD COLUMN false_positive_at INTEGER;

CREATE TABLE vendor_audit_log (
    id            BLOB    NOT NULL PRIMARY KEY,
    occurred_at   INTEGER NOT NULL,
    auth_method   TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    target_type   TEXT    NOT NULL,
    target_id     BLOB,
    detail        TEXT
);

CREATE INDEX idx_vendor_audit_log_occurred_at ON vendor_audit_log (occurred_at);
CREATE INDEX idx_vendor_audit_log_action       ON vendor_audit_log (action);
CREATE INDEX idx_vendor_audit_log_target_id    ON vendor_audit_log (target_id);
