CREATE TABLE IF NOT EXISTS collections (
    uuid       TEXT PRIMARY KEY NOT NULL,
    org_uuid   TEXT NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_collections_org ON collections(org_uuid);

CREATE TABLE IF NOT EXISTS users_collections (
    user_uuid       TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    collection_uuid TEXT NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    read_only       INTEGER NOT NULL DEFAULT 0,
    hide_passwords  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE IF NOT EXISTS ciphers_collections (
    cipher_uuid     TEXT NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    collection_uuid TEXT NOT NULL REFERENCES collections(uuid) ON DELETE CASCADE,
    PRIMARY KEY (cipher_uuid, collection_uuid)
);
