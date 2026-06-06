CREATE TABLE IF NOT EXISTS organizations (
    uuid          TEXT PRIMARY KEY NOT NULL,
    name          TEXT NOT NULL,
    billing_email TEXT NOT NULL,
    plan_type     INTEGER NOT NULL DEFAULT 0,
    key_          TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now'))
);

CREATE TABLE IF NOT EXISTS users_organizations (
    uuid       TEXT PRIMARY KEY NOT NULL,
    user_uuid  TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    org_uuid   TEXT NOT NULL REFERENCES organizations(uuid) ON DELETE CASCADE,
    access_all INTEGER NOT NULL DEFAULT 1,
    key_       TEXT,
    status     INTEGER NOT NULL DEFAULT 0,
    type_      INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000Z', 'now')),
    UNIQUE(user_uuid, org_uuid)
);
