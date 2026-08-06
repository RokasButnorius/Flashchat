# FlashChat

End-to-end encrypted messaging and calling in Python.

Desktop and mobile clients talk to a dumb relay: the server never sees message plaintext or private keys. A public relay is available for normal use; you can also run your own if you want.

> **Status:** early / experimental. Protocol and APIs will change. Not audited — use at your own risk.

## Features

- **E2EE messaging** — X3DH-style setup + Double Ratchet (PyNaCl / libsodium)
- **Voice & video calls** (desktop) — WebRTC via aiortc (DTLS-SRTP)
- **Encrypted local vault** — private keys stay on device, protected by passphrase
- **Anonymous mode** — temporary identity, nothing saved to disk
- **Contacts, groups, presence** — social graph is on the relay (same tradeoff as other chat apps)

## Clients

| Client | Stack | Messaging | Calling |
|--------|--------|-----------|---------|
| **Desktop** | PySide6 | ✅ | ✅ |
| **Mobile** | Kivy (Android) | ✅ | Not yet |

Debug Android APK: `client-mobile/bin/` (sideload to try without building).

Clients connect by default to **`wss://relay.flashchat.store`**.

## Quick start

### Desktop

```bash
cd client-desktop
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
Mobile
Install the APK from client-mobile/bin/, or build:
Bashcd client-mobile
buildozer -v android debug
How it works
textYou  ── encrypted message ──►  Relay  ── encrypted message ──►  Peer
         (server can't read)              (server can't read)

Clients hold keys and do all encryption/decryption.
Relay only stores public prekeys, queues opaque ciphertext, and handles contacts/groups/presence.
Private keys never leave your device.

Run your own relay (optional)
If you prefer not to use the public relay:
Bashcd server
pip install websockets
python server.py    # 0.0.0.0:8765
Put TLS in front (e.g. Cloudflare Tunnel), then point the client RELAY_URL in session.py at your server.
Security notes

Message content is E2EE; the relay cannot read it.
The relay can see the social graph (who talks to whom, contacts, groups, online status).
No real account auth yet — anyone can pick a user ID. Fine for testing; not production-hardened.
This is hobby/research code. Review it yourself before trusting it with anything sensitive.

Layout
textclient-desktop/   PySide6 client + calling
client-mobile/    Kivy Android client
server/           Relay + SQLite
shared/           Wire protocol (no crypto)
