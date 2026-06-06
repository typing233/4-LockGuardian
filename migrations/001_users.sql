CREATE TABLE IF NOT EXISTS users (
    uuid              TEXT PRIMARY KEY NOT NULL,
    email             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name              TEXT NOT NULL DEFAULT '',
    password_hash     TEXT NOT NULL,
    salt              TEXT NOT NULL,
    kdf_type          INTEGER NOT NULL DEFAULT 0,
    kdf_iterations    INTEGER NOT NULL DEFAULT 600000,
    kdf_memory        INTEGER,
    kdf_parallelism   INTEGER,
    security_stamp    TEXT NOT NULL,
    key_              TEXT,
    public_key        TEXT,
    private_key       TEXT,
    premium           INTEGER NOT NULL DEFAULT 1,
    email_verified    INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
