"""
client/crypto/session_persist.py

Persists Double Ratchet session state (crypto/ratchet.py's RatchetState)
to disk, encrypted the same way as the vault (Argon2id-derived key +
XChaCha20-Poly1305), but with its own independent key/salt -- compromising
one doesn't help decrypt the other.

Without this, a ratchet session only lives in memory and is lost every time
the app restarts. Any message that arrives afterward for a session the app
has "forgotten" becomes permanently undecryptable, even though it's sitting
safely in the server's queue waiting for delivery.

Anonymous-mode users don't get persistence here (no passphrase to derive a
key from) -- their sessions stay RAM-only, consistent with the ephemeral
nature of anonymous mode elsewhere in the app.
"""

import json
from pathlib import Path
from typing import Dict, Optional

from . import sodium_wrapper as sw
from .ratchet import RatchetState
from .vault import wrap_vault_key_with_platform_keystore, unwrap_vault_key_with_platform_keystore


def _state_to_dict(state: RatchetState) -> dict:
    def b64_or_none(b):
        return sw.b64(b) if b is not None else None

    return {
        "root_key": sw.b64(state.root_key),
        "dh_self_priv": sw.b64(state.dh_self_priv),
        "dh_self_pub": sw.b64(state.dh_self_pub),
        "dh_remote_pub": b64_or_none(state.dh_remote_pub),
        "send_chain_key": b64_or_none(state.send_chain_key),
        "recv_chain_key": b64_or_none(state.recv_chain_key),
        "send_count": state.send_count,
        "recv_count": state.recv_count,
        "skipped_keys": [
            [sw.b64(dh_pub), counter, sw.b64(msg_key)]
            for (dh_pub, counter), msg_key in state.skipped_keys.items()
        ],
    }


def _dict_to_state(d: dict) -> RatchetState:
    def unb64_or_none(s):
        return sw.unb64(s) if s is not None else None

    state = RatchetState(
        root_key=sw.unb64(d["root_key"]),
        dh_self_priv=sw.unb64(d["dh_self_priv"]),
        dh_self_pub=sw.unb64(d["dh_self_pub"]),
        dh_remote_pub=unb64_or_none(d.get("dh_remote_pub")),
        send_chain_key=unb64_or_none(d.get("send_chain_key")),
        recv_chain_key=unb64_or_none(d.get("recv_chain_key")),
        send_count=d.get("send_count", 0),
        recv_count=d.get("recv_count", 0),
    )
    for dh_pub_b64, counter, msg_key_b64 in d.get("skipped_keys", []):
        state.skipped_keys[(sw.unb64(dh_pub_b64), counter)] = sw.unb64(msg_key_b64)
    return state


class SessionStore:
    """Encrypted on-disk persistence for a user's active ratchet sessions,
    keyed by peer_user_id."""

    def __init__(self, sessions_path: Path, salt_path: Path):
        self.sessions_path = sessions_path
        self.salt_path = salt_path
        self._key: Optional[bytes] = None

    def unlock(self, passphrase: str):
        if self.salt_path.exists():
            salt = self.salt_path.read_bytes()
        else:
            _, salt = sw.derive_vault_key(passphrase)
            self.salt_path.parent.mkdir(parents=True, exist_ok=True)
            self.salt_path.write_bytes(salt)
        key, _ = sw.derive_vault_key(passphrase, salt=salt)
        self._key = key

    def save(self, sessions: Dict[str, RatchetState]):
        if self._key is None:
            return
        payload = {peer_id: _state_to_dict(state) for peer_id, state in sessions.items()}
        plaintext = json.dumps(payload).encode("utf-8")
        blob = sw.aead_encrypt(self._key, plaintext)
        self.sessions_path.parent.mkdir(parents=True, exist_ok=True)
        self.sessions_path.write_text(json.dumps({"version": 1, "blob": sw.b64(blob)}))

    def load(self) -> Dict[str, RatchetState]:
        if self._key is None or not self.sessions_path.exists():
            return {}
        try:
            raw = json.loads(self.sessions_path.read_text())
            blob = sw.unb64(raw["blob"])
            plaintext = sw.aead_decrypt(self._key, blob)
            payload = json.loads(plaintext)
            return {peer_id: _dict_to_state(d) for peer_id, d in payload.items()}
        except Exception as e:
            print(f"[session_persist] failed to load saved sessions, starting fresh: {e}")
            return {}

    # ---------- stay-signed-in (mirrors crypto/vault.py's Vault) ----------

    def _remember_path(self) -> Path:
        return self.sessions_path.with_name(self.sessions_path.stem + "_remember.bin")

    def save_remember_me(self, passphrase: str, platform: str):
        if not self.salt_path.exists():
            return  # unlock() always creates this; bail out if called before unlock()
        salt = self.salt_path.read_bytes()
        key, _ = sw.derive_vault_key(passphrase, salt=salt)
        try:
            wrapped = wrap_vault_key_with_platform_keystore(bytes(key), platform)
            self._remember_path().write_bytes(wrapped)
        finally:
            key = bytearray(key)
            sw.secure_wipe(key)

    def try_auto_unlock(self, platform: str) -> Optional[Dict[str, RatchetState]]:
        remember_path = self._remember_path()
        if not (remember_path.exists() and self.sessions_path.exists()):
            return None
        try:
            self._key = unwrap_vault_key_with_platform_keystore(remember_path.read_bytes(), platform)
            return self.load()
        except Exception as e:
            print(f"[session_persist] auto-unlock failed, falling back to manual login: {e}")
            self._key = None
            return None

    def clear_remember_me(self):
        p = self._remember_path()
        if p.exists():
            p.unlink()
