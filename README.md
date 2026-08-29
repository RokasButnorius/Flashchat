# FlashChat

**End-to-end encrypted messaging and calling**

Project started 2026-06 · First public release 2026-08-07  
Made by [Rokas Butnorius](https://github.com/RokasButnorius)

Desktop and mobile clients talk to a **dumb relay**: the server never sees message plaintext or private keys.

> **Status:** Early / experimental pre-release.  
> Protocol and APIs will change. **Not audited** — use at your own risk.

---

## Downloads

All builds are on the website: **[flashchatmain.netlify.app](https://flashchatmain.netlify.app/)**

| Platform | Version | Notes |
|----------|---------|-------|
| **Android** | v0.2 | Debug APK (arm64-v8a + armeabi-v7a) |
| **Windows** | v0.1 | x64 build |
| **Web** | WIP | Not E2EE yet |

The debug APK under `client-mobile/bin/` is only a convenience copy for people browsing the source.

---

## Features

- **E2EE messaging** — X3DH-style session setup + Double Ratchet (PyNaCl / libsodium)
- **Voice & video calls** (desktop) — WebRTC via aiortc (DTLS-SRTP encrypted media)
- **Encrypted local vault** — private keys stay on your device, protected by a passphrase
- **Anonymous mode** — temporary identity, nothing written to disk
- **Contacts, groups, presence** — social graph lives on the relay (same trade-off as other chat apps)

---

## Clients

| Client | Stack | Messaging | Calling |
|--------|-------|-----------|---------|
| **Desktop** | PySide6 + qasync | ✅ | ✅ |
| **Mobile** | Kivy (Android via Buildozer) | ✅ | Not yet |

Clients connect by default to **`wss://relay.flashchat.store`**.

---

## Quick start (from source)

### Desktop

```bash
cd client-desktop
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

**Dependencies:** `PySide6`, `qasync`, `aiortc`, `av`, `websockets`, `pynacl`

### Mobile (Android)

Prefer the APK from the website. To build yourself:

```bash
cd client-mobile
buildozer -v android debug
```

Or sideload the debug APK in `client-mobile/bin/`.

**Buildozer requirements:** `python3`, `kivy`, `pynacl`, `websockets`, `cffi`, `pycparser`, `certifi`  
(Calling is not yet ported to mobile.)

---

## How it works

```
You  ── encrypted message ──►  Relay  ── encrypted message ──►  Peer
         (server can't read)              (server can't read)
```

- Clients hold the private keys and perform **all** encryption / decryption.
- The relay only stores public prekey bundles, queues opaque ciphertext, and handles contacts, groups, and presence.
- Private keys **never** leave your device.
- Wire protocol (`shared/protocol.py`) contains **zero** cryptographic logic — the server only ever sees opaque base64 blobs.

Crypto stack (client-side only):
- X3DH-style session setup
- Double Ratchet
- XChaCha20-Poly1305 AEAD
- X25519 / Ed25519 via PyNaCl (libsodium)

---

## Project layout

```
client-desktop/     PySide6 desktop client + calling
  ├── main.py
  ├── session.py
  ├── calling.py
  ├── theme.py
  ├── crypto/         keygen, ratchet, vault, sodium wrapper…
  └── network/

client-mobile/      Kivy Android client
  ├── main.py
  ├── session.py
  ├── calling.py      (stub / not fully ported)
  ├── buildozer.spec
  ├── crypto/         same crypto modules as desktop
  └── network/

server/             Dumb relay + SQLite social graph
  ├── server.py
  └── db/

shared/             Wire protocol definitions (no crypto)
  └── protocol.py
```

---

## Security notes

- Message **content** is end-to-end encrypted; the relay cannot read it.
- The relay **can** see the social graph (who you contact, groups, online status).
- There is **no real account authentication** yet — anyone can pick a user ID. Fine for early testing; not production-hardened.
- This is hobby / research software. Review the code yourself before trusting it with anything sensitive.
- **Not audited.**


## Support

Even €1 helps development: **[ko-fi.com/flashchat](https://ko-fi.com/flashchat)**

**Contact / bug reports**
- rokasbutnorius12@gmail.com
- b.rokas@yahoo.com

---

<p align="center">
  <b>Flash Chat</b> — made by Rokas Butnorius
</p>
