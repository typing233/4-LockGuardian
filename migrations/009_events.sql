CREATE TABLE IF NOT EXISTS events (
    uuid             TEXT PRIMARY KEY NOT NULL,
    type_            INTEGER NOT NULL,
    user_uuid        TEXT REFERENCES users(uuid),
    org_uuid         TEXT REFERENCES organizations(uuid),
    cipher_uuid      TEXT,
    collection_uuid  TEXT,
    acting_user_uuid TEXT REFERENCES users(uuid),
    device_type      INTEGER,
    ip_address       TEXT,
    event_date       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_events_acting_user ON events(acting_user_uuid, event_date);
CREATE INDEX IF NOT EXISTS idx_events_org ON events(org_uuid, event_date);
