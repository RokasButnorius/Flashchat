"""
client/network/ws_client.py

Talks to the relay server. This layer only ever moves already-encrypted
blobs / public keys across the wire -- it has no access to plaintext
or private keys (those live in crypto/vault.py and stay in the crypto layer).
"""

import asyncio
import json
import ssl
import websockets


class RelayClient:
    def __init__(self, url: str, user_id: str):
        self.url = url
        self.user_id = user_id
        self.ws: websockets.WebSocketClientProtocol | None = None
        self._handlers = {}

    def on(self, msg_type: str):
        def deco(fn):
            self._handlers[msg_type] = fn
            return fn
        return deco

    async def connect(self, is_anonymous: bool = False):
        ssl_context = None
        try:
            import certifi
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            print("[ws_client] SSL: certifi CA bundle loaded")
        except Exception as e:
            print(f"[ws_client] SSL: certifi failed ({e}), trying requests.certs")
            try:
                import requests.certs
                ssl_context = ssl.create_default_context(cafile=requests.certs.where())
                print("[ws_client] SSL: requests.certs CA bundle loaded")
            except Exception as e2:
                print(f"[ws_client] SSL: NONE -- wss will fail ({e2})")

        connect_kwargs = {"ping_interval": 20, "ping_timeout": 20}
        if self.url.startswith("wss://") and ssl_context is not None:
            connect_kwargs["ssl"] = ssl_context

        self.ws = await websockets.connect(self.url, **connect_kwargs)
        await self.ws.send(json.dumps({"type": "hello", "user_id": self.user_id, "is_anonymous": is_anonymous}))
        asyncio.create_task(self._listen())

    async def _listen(self):
        async for raw in self.ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                print(f"[ws_client] received malformed JSON, skipping: {raw[:200]}")
                continue

            handler = self._handlers.get(msg.get("type"))
            if handler:
                try:
                    await handler(msg)
                except Exception as e:
                    import traceback
                    print(f"[ws_client] handler for '{msg.get('type')}' raised an error (message dropped, listener stays alive):")
                    traceback.print_exc()

    async def register_device(self, public_registration: dict):
        await self.ws.send(json.dumps({
            "type": "register",
            "user_id": self.user_id,
            **public_registration,
        }))

    async def fetch_prekey_bundle(self, target_user_id: str):
        await self.ws.send(json.dumps({"type": "fetch_bundle", "target_user_id": target_user_id}))

    async def send_envelope(self, envelope: dict):
        await self.ws.send(json.dumps({"type": "send_message", "envelope": envelope}))

    async def ack(self, envelope_id: str):
        await self.ws.send(json.dumps({"type": "ack", "envelope_id": envelope_id}))

    async def send_signal(self, kind: str, to_user: str, payload: str):
        await self.ws.send(json.dumps({
            "type": f"rtc_{kind}", "to_user": to_user, "from_user": self.user_id, "payload": payload,
        }))

    # ---------- social graph ----------

    async def search_users(self, query: str):
        await self.ws.send(json.dumps({"type": "search_users", "query": query}))

    async def add_contact(self, contact_id: str):
        await self.ws.send(json.dumps({"type": "add_contact", "contact_id": contact_id}))

    async def remove_contact(self, contact_id: str):
        await self.ws.send(json.dumps({"type": "remove_contact", "contact_id": contact_id}))

    async def list_contacts(self):
        await self.ws.send(json.dumps({"type": "list_contacts"}))

    async def update_profile(self, bio: str = None, avatar_id: str = None):
        payload = {"type": "update_profile"}
        if bio is not None:
            payload["bio"] = bio
        if avatar_id is not None:
            payload["avatar_id"] = avatar_id
        await self.ws.send(json.dumps(payload))

    async def create_group(self, name: str):
        await self.ws.send(json.dumps({"type": "create_group", "name": name}))

    async def join_group(self, invite_token: str):
        await self.ws.send(json.dumps({"type": "join_group", "invite_token": invite_token}))

    async def list_groups(self):
        await self.ws.send(json.dumps({"type": "list_groups"}))
