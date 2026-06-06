CREATE TABLE IF NOT EXISTS ciphers (
    uuid              TEXT PRIMARY KEY NOT NULL,
    user_uuid         TEXT REFERENCES users(uuid) ON DELETE CASCADE,
    organization_uuid TEXT REFERENCES organizations(uuid) ON DELETE CASCADE,
    type_             INTEGER NOT NULL,
    name              TEXT NOT NULL,
    notes             TEXT,
    fields            TEXT,
    data              TEXT NOT NULL,
    favorite          INTEGER NOT NULL DEFAULT 0,
    reprompt          INTEGER NOT NULL DEFAULT 0,
    folder_uuid       TEXT REFERENCES folders(uuid) ON DELETE SET NULL,
    deleted_at        TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_ciphers_user ON ciphers(user_uuid);
CREATE INDEX IF NOT EXISTS idx_ciphers_org ON ciphers(organization_uuid);
CREATE INDEX IF NOT EXISTS idx_ciphers_folder ON ciphers(folder_uuid);
