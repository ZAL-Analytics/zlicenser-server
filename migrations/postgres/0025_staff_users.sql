CREATE TABLE IF NOT EXISTS staff_users (
    id            TEXT NOT NULL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_by    TEXT REFERENCES staff_users(id),
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    last_login_at BIGINT
);
