CREATE TABLE IF NOT EXISTS attachments (
    id          TEXT PRIMARY KEY NOT NULL,
    cipher_uuid TEXT NOT NULL REFERENCES ciphers(uuid) ON DELETE CASCADE,
    file_name   TEXT NOT NULL,
    file_size   INTEGER NOT NULL,
    key_        TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_uuid);
