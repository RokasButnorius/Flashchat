# FlashChat

End-to-end encrypted messaging and calling in Python.

Desktop and mobile clients talk to a dumb relay: the server never sees message plaintext or private keys. A public relay is available for normal use; you can also run your own if you want.

> **Status:** early / experimental. Protocol and APIs will change. Not audited — use at your own risk.

## Downloads

All builds (desktop + Android) are on the website: **[flashchat.store](https://flashchat.store)**

The debug APK under `client-mobile/bin/` is only a convenience copy for people browsing the source.

## Features

- **E2EE messaging** — X3DH-style session setup + Double Ratchet (PyNaCl / libsodium)
- **Voice & video calls** (desktop) — WebRTC via aiortc (DTLS-SRTP encrypted media)
- **Encrypted local vault** — private keys stay on your device, protected by a passphrase
- **Anonymous mode** — temporary identity, nothing written to disk
- **Contacts, groups, presence** — social graph lives on the relay (same tradeoff as other chat apps)

## Clients

| Client | Stack | Messaging | Calling |
|--------|--------|-----------|---------|
| **Desktop** | PySide6 + qasync | ✅ | ✅ |
| **Mobile** | Kivy (Android via Buildozer) | ✅ | Not yet |

Clients connect by default to **`wss://relay.flashchat.store`**.

## Quick start (from source)

### Desktop

```bash
cd client-desktop
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
Mobile (Android)
Prefer the APK from the website. To build yourself:
Bashcd client-mobile
buildozer -v android debug
Or sideload the debug APK in client-mobile/bin/.
How it works
textYou  ── encrypted message ──►  Relay  ── encrypted message ──►  Peer
         (server can't read)              (server can't read)

Clients hold the private keys and perform all encryption / decryption.
Relay only stores public prekey bundles, queues opaque ciphertext, and handles contacts, groups, and presence.
Private keys never leave your device.

Run your own relay (optional)
If you prefer not to use the public relay:
Bashcd server
pip install websockets
python server.py    # listens on 0.0.0.0:8765
Put TLS in front (for example a Cloudflare Tunnel), then point the client RELAY_URL in session.py at your server.
Security notes

Message content is end-to-end encrypted; the relay cannot read it.
The relay can see the social graph (who you contact, groups, online status).
There is no real account authentication yet — anyone can pick a user ID. Fine for early testing; not production-hardened.
This is hobby / research software. Review the code yourself before trusting it with anything sensitive.

Project layout
textclient-desktop/   PySide6 desktop client + calling
client-mobile/    Kivy Android client
server/           Dumb relay + SQLite social graph
shared/           Wire protocol definitions (no crypto)
