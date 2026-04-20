-- Initial schema for Zixiao Labs Cloud Account.
-- The account directory is intentionally minimal: this service exists only
-- to sign users into relying parties (like yuxu-server) via OAuth 2.0, and
-- does not host any downstream business data of its own.

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    avatar_url    TEXT NOT NULL DEFAULT '',
    bio           TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
