CREATE TABLE IF NOT EXISTS devices (
    uuid          TEXT PRIMARY KEY NOT NULL,
    user_uuid     TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    type_         INTEGER NOT NULL,
    push_token    TEXT,
    refresh_token TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_uuid);
CREATE INDEX IF NOT EXISTS idx_devices_refresh ON devices(refresh_token);
