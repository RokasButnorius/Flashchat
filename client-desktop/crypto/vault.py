"""
client/crypto/vault.py

Local encrypted key storage. Private keys are NEVER written to disk
in plaintext. The vault file itself is useless without the user's
passphrase (or platform secure-storage-derived key).

Layered defense, in priority order:
  1. Where available, defer to platform secure storage (Android
     Keystore / TPM+DPAPI on Windows) to wrap the vault key itself,
     so it never exists in raw form outside hardware.
  2. Fallback: Argon2id-derived key from user passphrase encrypts
     the vault blob at rest.

This module implements layer 2 (portable, works everywhere including
PC). Hook platform Keystore/TPM APIs in on top of this for layer 1
via `wrap_vault_key_with_platform_keystore()` (stubbed below).
"""

import json
import os
from pathlib import Path
from dataclasses import asdict

from . import sodium_wrapper as sw


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, path: Path):
        self.path = path

    def create(self, passphrase: str, private_bundle: dict):
        """Encrypt and write the private key bundle to disk."""
        key, salt = sw.derive_vault_key(passphrase)
        try:
            plaintext = json.dumps(private_bundle).encode("utf-8")
            blob = sw.aead_encrypt(key, plaintext)
            payload = {
                "version": 1,
                "kdf": "argon2id",
                "salt": sw.b64(salt),
                "blob": sw.b64(blob),
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(payload))
            # restrict file perms to owner-only (POSIX)
            os.chmod(self.path, 0o600)
        finally:
            key = bytearray(key)
            sw.secure_wipe(key)

    def unlock(self, passphrase: str) -> dict:
        """Decrypt and return the private key bundle. Caller is
        responsible for wiping the returned dict from memory ASAP
        after use."""
        if not self.path.exists():
            raise VaultError("no vault found on this device")

        payload = json.loads(self.path.read_text())
        salt = sw.unb64(payload["salt"])
        key, _ = sw.derive_vault_key(passphrase, salt=salt)
        try:
            blob = sw.unb64(payload["blob"])
            try:
                plaintext = sw.aead_decrypt(key, blob)
            except Exception:
                raise VaultError("wrong passphrase or corrupted vault")
            return json.loads(plaintext)
        finally:
            key = bytearray(key)
            sw.secure_wipe(key)

    def exists(self) -> bool:
        return self.path.exists()


def wrap_vault_key_with_platform_keystore(raw_key: bytes, platform: str) -> bytes:
    """
    STUB: integrate with platform secure storage so the Argon2id-derived
    key itself is sealed behind hardware, not just a passphrase.

    - Android: use Android Keystore (StrongBox/TEE-backed) via a JNI/Kivy
      bridge to wrap `raw_key` -- the app never has to hold it in plain
      Python memory longer than one call.
    - Windows/PC: use DPAPI (CryptProtectData) or a TPM-backed key via
      Windows Hello / `python-tpm2-pytss`, so disk theft alone doesn't
      yield the vault key.
    - Web build (if using Pyodide/WASM client): use the WebCrypto
      `crypto.subtle` API with a non-extractable CryptoKey stored in
      IndexedDB -- raw bytes never enter JS-readable memory at all.

    Left unimplemented here since it's platform-SDK-specific; wire this
    in before shipping to production.
    """
    raise NotImplementedError("wire up platform keystore before production use")
