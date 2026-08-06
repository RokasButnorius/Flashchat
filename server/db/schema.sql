-- server/db/schema.sql
--
-- SECURITY NOTE: Every column in this schema is either:
--   (a) a PUBLIC key (safe for the server to see by design), or
--   (b) OPAQUE ciphertext/blob the server cannot decrypt, or
--   (c) social-graph metadata (contacts, group membership, profile info)
--       -- this was always visible to a relay server in any messenger,
--       E2EE protects message CONTENT, not who-knows-who.
-- There is no column anywhere for a private key.

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,      -- the user_id string itself (e.g. "alice")
    bio             TEXT DEFAULT '',
    avatar_id       TEXT DEFAULT 'default',
    is_anonymous    INTEGER NOT NULL DEFAULT 0,
    last_seen       REAL,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id                  TEXT PRIMARY KEY,      -- uuid, one per device (multi-device support)
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    identity_pubkey     TEXT NOT NULL,         -- base64 X25519 public key
    identity_ed25519_pubkey TEXT NOT NULL,     -- base64 Ed25519 public key (verifies signed_prekey_sig)
    signed_prekey       TEXT NOT NULL,         -- base64 X25519 public key, rotated client-side periodically
    signed_prekey_sig   TEXT NOT NULL,         -- base64 Ed25519 signature (proves signed_prekey belongs to identity key)
    registered_at       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    pubkey          TEXT NOT NULL,             -- base64 X25519 public key
    used            INTEGER NOT NULL DEFAULT 0 -- one-time-use, marked consumed after handout
);

-- Ciphertext queue: server is a dead-drop mailbox. Rows are purged
-- as soon as the recipient ACKs delivery -- minimizes what's ever
-- sitting on disk if the box is compromised.
CREATE TABLE IF NOT EXISTS message_queue (
    id                      TEXT PRIMARY KEY,   -- envelope_id (uuid)
    sender_id               TEXT NOT NULL,
    recipient_id            TEXT NOT NULL,
    sender_device_id        TEXT NOT NULL,
    recipient_device_id     TEXT NOT NULL,
    ciphertext              TEXT NOT NULL,       -- base64 OPAQUE
    header                  TEXT NOT NULL,       -- base64 OPAQUE ratchet header
    is_prekey_message       INTEGER NOT NULL DEFAULT 0,
    group_id                TEXT,                -- NULL for DMs, set for group messages
    created_at              REAL NOT NULL,
    delivered               INTEGER NOT NULL DEFAULT 0
);

-- Friends list. Simplified (no request/accept flow yet) -- adding is
-- instant and one-directional; the client shows it as mutual once both
-- sides have added each other, similar to following.
CREATE TABLE IF NOT EXISTS contacts (
    owner_id        TEXT NOT NULL,
    contact_id      TEXT NOT NULL,
    added_at        REAL NOT NULL,
    PRIMARY KEY (owner_id, contact_id)
);

CREATE TABLE IF NOT EXISTS groups (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    owner_id        TEXT NOT NULL,
    invite_token    TEXT UNIQUE NOT NULL,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id        TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL,
    joined_at       REAL NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_queue_recipient ON message_queue(recipient_id, delivered);
CREATE INDEX IF NOT EXISTS idx_queue_group ON message_queue(group_id, delivered);
CREATE INDEX IF NOT EXISTS idx_prekeys_device ON one_time_prekeys(device_id, used);
CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

