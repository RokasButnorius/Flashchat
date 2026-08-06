"""
server/server.py

The "dumb relay" -- now also handling social-graph metadata (contacts,
groups, profiles, presence). This is still NOT the same as message
content: E2EE protects what you say, not who you know. Every chat
platform's server sees the social graph; this one is no different.

It never imports a crypto library that does decryption, never sees a
private key, and has no code path capable of reading message plaintext.
Run behind Cloudflare Tunnel; keep this box hardened + minimal attack
surface.
"""

import asyncio
import json
import logging
import websockets
from websockets.server import WebSocketServerProtocol

from db import models

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("relay")

# user_id -> set of connected sockets (multi-device)
CONNECTED: dict[str, set[WebSocketServerProtocol]] = {}


async def broadcast_presence(user_id: str, online: bool):
    watchers = models.get_watchers(user_id)
    payload = json.dumps({"type": "presence_online" if online else "presence_offline", "user_id": user_id})
    for watcher_id in watchers:
        for ws in CONNECTED.get(watcher_id, ()):
            await ws.send(payload)


async def push_pending(user_id: str, ws: WebSocketServerProtocol):
    for envelope in models.fetch_pending(user_id):
        await ws.send(json.dumps({"type": "incoming_message", "envelope": envelope}))


async def handler(ws: WebSocketServerProtocol):
    user_id = None
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send(json.dumps({"type": "error", "reason": "bad_json"}))
                continue

            msg_type = msg.get("type")

            if msg_type == "hello":
                user_id = msg["user_id"]
                is_anon = msg.get("is_anonymous", False)
                models.get_or_create_user(user_id, is_anonymous=is_anon)
                models.touch_last_seen(user_id)
                CONNECTED.setdefault(user_id, set()).add(ws)
                await push_pending(user_id, ws)
                await broadcast_presence(user_id, online=True)
                continue

            if msg_type == "register":
                device_id = models.register_device(
                    user_id=msg["user_id"],
                    identity_pubkey=msg["identity_pubkey"],
                    identity_ed25519_pubkey=msg["identity_ed25519_pubkey"],
                    signed_prekey=msg["signed_prekey"],
                    signed_prekey_sig=msg["signed_prekey_sig"],
                    one_time_prekeys=msg["one_time_prekeys"],
                )
                await ws.send(json.dumps({"type": "registered", "device_id": device_id}))
                continue

            if msg_type == "fetch_bundle":
                bundle = models.get_prekey_bundle(msg["target_user_id"])
                if bundle is None:
                    await ws.send(json.dumps({"type": "error", "reason": "no_such_user"}))
                else:
                    await ws.send(json.dumps({"type": "prekey_bundle", "bundle": bundle}))
                continue

            if msg_type == "send_message":
                envelope = msg["envelope"]
                group_id = envelope.get("group_id")
                if group_id:
                    models.enqueue_message(envelope)
                    for member_id in models.list_group_members(group_id):
                        if member_id == envelope["sender_id"]:
                            continue
                        for peer_ws in CONNECTED.get(member_id, ()):
                            await peer_ws.send(json.dumps({"type": "incoming_message", "envelope": envelope}))
                else:
                    models.enqueue_message(envelope)
                    recipient = envelope["recipient_id"]
                    for peer_ws in CONNECTED.get(recipient, ()):
                        await peer_ws.send(json.dumps({"type": "incoming_message", "envelope": envelope}))
                continue

            if msg_type == "ack":
                models.ack_delivered(msg["envelope_id"])
                continue

            if msg_type in ("rtc_offer", "rtc_answer", "rtc_ice_candidate"):
                target = msg["to_user"]
                for peer_ws in CONNECTED.get(target, ()):
                    await peer_ws.send(raw)
                continue

            # ---------- social graph: search / contacts / profile ----------

            if msg_type == "search_users":
                results = models.search_users(msg["query"], exclude_user_id=user_id)
                await ws.send(json.dumps({"type": "search_results", "results": results}))
                continue

            if msg_type == "add_contact":
                models.add_contact(user_id, msg["contact_id"])
                profile = models.get_profile(msg["contact_id"])
                online = bool(CONNECTED.get(msg["contact_id"]))
                await ws.send(json.dumps({"type": "contact_added", "contact": profile, "online": online}))
                continue

            if msg_type == "remove_contact":
                models.remove_contact(user_id, msg["contact_id"])
                await ws.send(json.dumps({"type": "contact_removed", "contact_id": msg["contact_id"]}))
                continue

            if msg_type == "list_contacts":
                contacts = models.list_contacts(user_id)
                for c in contacts:
                    c["online"] = bool(CONNECTED.get(c["id"]))
                await ws.send(json.dumps({"type": "contacts_list", "contacts": contacts}))
                continue

            if msg_type == "update_profile":
                models.update_profile(user_id, bio=msg.get("bio"), avatar_id=msg.get("avatar_id"))
                await ws.send(json.dumps({"type": "profile_updated"}))
                continue

            # ---------- groups ----------

            if msg_type == "create_group":
                group = models.create_group(msg["name"], user_id)
                await ws.send(json.dumps({"type": "group_created", "group": group}))
                continue

            if msg_type == "join_group":
                group = models.join_group_by_token(msg["invite_token"], user_id)
                if group is None:
                    await ws.send(json.dumps({"type": "error", "reason": "invalid_invite"}))
                else:
                    members = models.list_group_members(group["id"])
                    await ws.send(json.dumps({"type": "group_joined", "group": group, "members": members}))
                    # notify existing online members someone joined
                    for member_id in members:
                        if member_id == user_id:
                            continue
                        for peer_ws in CONNECTED.get(member_id, ()):
                            await peer_ws.send(json.dumps({
                                "type": "group_member_joined", "group_id": group["id"], "user_id": user_id,
                            }))
                continue

            if msg_type == "list_groups":
                groups = models.list_user_groups(user_id)
                for g in groups:
                    g["members"] = models.list_group_members(g["id"])
                await ws.send(json.dumps({"type": "groups_list", "groups": groups}))
                continue

            await ws.send(json.dumps({"type": "error", "reason": "unknown_type"}))

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if user_id and ws in CONNECTED.get(user_id, ()):
            CONNECTED[user_id].discard(ws)
            if not CONNECTED[user_id]:
                models.touch_last_seen(user_id)
                await broadcast_presence(user_id, online=False)


async def main(host="0.0.0.0", port=8765):
    models.init_db()
    log.info(f"Relay listening on {host}:{port} (behind Cloudflare Tunnel, no direct exposure)")
    async with websockets.serve(handler, host, port, max_size=2 * 1024 * 1024):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
