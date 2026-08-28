from __future__ import annotations

"""
server/db/models.py

Thin DB access layer. Notice: every function signature here only ever
accepts/returns PUBLIC keys, OPAQUE ciphertext strings, or social-graph
metadata (contacts/groups/profile info). There's no private key anywhere
in scope, and no plaintext message content.
"""

import sqlite3
import time
import uuid
import secrets
from pathlib import Path
from typing import Optional, List, Dict
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "relay.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ---------- Users / profiles ----------

def get_or_create_user(user_id: str, is_anonymous: bool = False) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row:
            return dict(row)
        conn.execute(
            "INSERT INTO users (id, bio, avatar_id, is_anonymous, last_seen, created_at) "
            "VALUES (?, '', 'default', ?, ?, ?)",
            (user_id, int(is_anonymous), time.time(), time.time()),
        )
        return {"id": user_id, "bio": "", "avatar_id": "default",
                "is_anonymous": int(is_anonymous), "last_seen": time.time(), "created_at": time.time()}


def update_profile(user_id: str, bio: Optional[str] = None, avatar_id: Optional[str] = None):
    with get_conn() as conn:
        if bio is not None:
            conn.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, user_id))
        if avatar_id is not None:
            conn.execute("UPDATE users SET avatar_id = ? WHERE id = ?", (avatar_id, user_id))


def get_profile(user_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def touch_last_seen(user_id: str):
    with get_conn() as conn:
        conn.execute("UPDATE users SET last_seen = ? WHERE id = ?", (time.time(), user_id))


def search_users(query: str, exclude_user_id: str, limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, bio, avatar_id, is_anonymous FROM users "
            "WHERE id LIKE ? AND id != ? AND is_anonymous = 0 LIMIT ?",
            (f"%{query}%", exclude_user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- Contacts (friends) ----------

def add_contact(owner_id: str, contact_id: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO contacts (owner_id, contact_id, added_at) VALUES (?, ?, ?)",
            (owner_id, contact_id, time.time()),
        )


def remove_contact(owner_id: str, contact_id: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM contacts WHERE owner_id = ? AND contact_id = ?", (owner_id, contact_id))


def list_contacts(owner_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT u.id, u.bio, u.avatar_id, u.last_seen FROM contacts c
               JOIN users u ON u.id = c.contact_id WHERE c.owner_id = ?""",
            (owner_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_watchers(user_id: str) -> list[str]:
    """Who has `user_id` added as a contact -- these are the people who
    should be notified of this user's presence changes."""
    with get_conn() as conn:
        rows = conn.execute("SELECT owner_id FROM contacts WHERE contact_id = ?", (user_id,)).fetchall()
        return [r["owner_id"] for r in rows]


# ---------- Devices ----------

def register_device(user_id: str, identity_pubkey: str, identity_ed25519_pubkey: str,
                    signed_prekey: str, signed_prekey_sig: str, one_time_prekeys: list[str]) -> str:
    get_or_create_user(user_id)
    device_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO devices (id, user_id, identity_pubkey, identity_ed25519_pubkey,
               signed_prekey, signed_prekey_sig, registered_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (device_id, user_id, identity_pubkey, identity_ed25519_pubkey,
             signed_prekey, signed_prekey_sig, time.time()),
        )
        for pk in one_time_prekeys:
            conn.execute(
                "INSERT INTO one_time_prekeys (device_id, pubkey, used) VALUES (?, ?, 0)",
                (device_id, pk),
            )
    return device_id


def get_prekey_bundle(user_id: str) -> Optional[dict]:
    with get_conn() as conn:
        device = conn.execute(
            "SELECT * FROM devices WHERE user_id = ? ORDER BY registered_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if not device:
            return None

        otk_row = conn.execute(
            "SELECT id, pubkey FROM one_time_prekeys WHERE device_id = ? AND used = 0 LIMIT 1",
            (device["id"],),
        ).fetchone()

        one_time_prekey, prekey_id = None, None
        if otk_row:
            one_time_prekey, prekey_id = otk_row["pubkey"], otk_row["id"]
            conn.execute("UPDATE one_time_prekeys SET used = 1 WHERE id = ?", (prekey_id,))

        return {
            "user_id": user_id,
            "device_id": device["id"],
            "identity_pubkey": device["identity_pubkey"],
            "identity_ed25519_pubkey": device["identity_ed25519_pubkey"],
            "signed_prekey": device["signed_prekey"],
            "signed_prekey_sig": device["signed_prekey_sig"],
            "one_time_prekey": one_time_prekey,
            "prekey_id": prekey_id,
        }


# ---------- Groups ----------

def create_group(name: str, owner_id: str) -> dict:
    group_id = str(uuid.uuid4())
    invite_token = secrets.token_urlsafe(12)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO groups (id, name, owner_id, invite_token, created_at) VALUES (?, ?, ?, ?, ?)",
            (group_id, name, owner_id, invite_token, time.time()),
        )
        conn.execute(
            "INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)",
            (group_id, owner_id, time.time()),
        )
    return {"id": group_id, "name": name, "owner_id": owner_id, "invite_token": invite_token}


def join_group_by_token(invite_token: str, user_id: str) -> Optional[dict]:
    with get_conn() as conn:
        group = conn.execute("SELECT * FROM groups WHERE invite_token = ?", (invite_token,)).fetchone()
        if not group:
            return None
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, user_id, joined_at) VALUES (?, ?, ?)",
            (group["id"], user_id, time.time()),
        )
        return dict(group)


def list_group_members(group_id: str) -> list[str]:
    with get_conn() as conn:
        rows = conn.execute("SELECT user_id FROM group_members WHERE group_id = ?", (group_id,)).fetchall()
        return [r["user_id"] for r in rows]


def list_user_groups(user_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT g.* FROM groups g JOIN group_members m ON m.group_id = g.id
               WHERE m.user_id = ?""",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- Message queue (dead-drop mailbox) ----------

def enqueue_message(envelope: dict):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO message_queue
               (id, sender_id, recipient_id, sender_device_id, recipient_device_id,
                ciphertext, header, is_prekey_message, group_id, created_at, delivered)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
            (envelope["envelope_id"], envelope["sender_id"], envelope["recipient_id"],
             envelope["sender_device_id"], envelope["recipient_device_id"],
             envelope["ciphertext"], envelope["header"],
             int(envelope["is_prekey_message"]), envelope.get("group_id"), time.time()),
        )


def fetch_pending(recipient_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM message_queue WHERE recipient_id = ? AND delivered = 0",
            (recipient_id,),
        ).fetchall()
        envelopes = []
        for r in rows:
            d = dict(r)
            d["envelope_id"] = d.pop("id")  # normalize to match the live-delivery envelope shape
            envelopes.append(d)
        return envelopes


def ack_delivered(envelope_id: str):
    """Recipient confirmed receipt -> purge ciphertext from disk.
    Minimizes what's ever at rest on the relay."""
    with get_conn() as conn:
        conn.execute("DELETE FROM message_queue WHERE id = ?", (envelope_id,))