ALTER TABLE security_events ADD COLUMN false_positive_at BIGINT;

CREATE TABLE vendor_audit_log (
    id            UUID   NOT NULL PRIMARY KEY,
    occurred_at   BIGINT NOT NULL,
    auth_method   TEXT   NOT NULL,
    action        TEXT   NOT NULL,
    target_type   TEXT   NOT NULL,
    target_id     UUID,
    detail        TEXT
);

CREATE INDEX idx_vendor_audit_log_occurred_at ON vendor_audit_log (occurred_at);
CREATE INDEX idx_vendor_audit_log_action       ON vendor_audit_log (action);
CREATE INDEX idx_vendor_audit_log_target_id    ON vendor_audit_log (target_id);
