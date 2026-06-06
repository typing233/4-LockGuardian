CREATE TABLE IF NOT EXISTS twofactor (
    uuid      TEXT PRIMARY KEY NOT NULL,
    user_uuid TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    type_     INTEGER NOT NULL,
    enabled   INTEGER NOT NULL DEFAULT 1,
    data      TEXT NOT NULL,
    last_used TEXT,
    UNIQUE(user_uuid, type_)
);
