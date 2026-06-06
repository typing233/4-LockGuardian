CREATE TABLE IF NOT EXISTS folders (
    uuid       TEXT PRIMARY KEY NOT NULL,
    user_uuid  TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_uuid);
