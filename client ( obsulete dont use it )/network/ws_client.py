"""
client/network/ws_client.py

Talks to the relay server. This layer only ever moves already-encrypted
blobs / public keys across the wire -- it has no access to plaintext
or private keys (those live in crypto/vault.py and stay in the crypto layer).
"""

import asyncio
import json
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

    async def connect(self):
        self.ws = await websockets.connect(self.url, ping_interval=20, ping_timeout=20)
        await self.ws.send(json.dumps({"type": "hello", "user_id": self.user_id}))
        asyncio.create_task(self._listen())

    async def _listen(self):
        async for raw in self.ws:
            msg = json.loads(raw)
            handler = self._handlers.get(msg.get("type"))
            if handler:
                await handler(msg)

    async def register_device(self, public_registration: dict):
        await self.ws.send(json.dumps({
            "type": "register",
            "user_id": self.user_id,
            **public_registration,
        }))

    async def fetch_prekey_bundle(self, target_user_id: str):
        await self.ws.send(json.dumps({"type": "fetch_bundle", "target_user_id": target_user_id}))

    async def send_envelope(self, envelope: dict):
        # envelope["ciphertext"] / ["header"] must already be encrypted
        # by the ratchet before this is ever called.
        await self.ws.send(json.dumps({"type": "send_message", "envelope": envelope}))

    async def ack(self, envelope_id: str):
        await self.ws.send(json.dumps({"type": "ack", "envelope_id": envelope_id}))

    async def send_signal(self, kind: str, to_user: str, payload: str):
        await self.ws.send(json.dumps({
            "type": f"rtc_{kind}", "to_user": to_user, "payload": payload,
        }))
