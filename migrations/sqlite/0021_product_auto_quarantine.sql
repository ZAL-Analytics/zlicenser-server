ALTER TABLE products
    ADD COLUMN auto_quarantine_on_critical INTEGER NOT NULL DEFAULT 1;
