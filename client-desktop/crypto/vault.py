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
import sys
from pathlib import Path
from dataclasses import asdict
from typing import Optional

from . import sodium_wrapper as sw


class VaultError(Exception):
    pass


def current_platform() -> str:
    """Best-effort detection of which platform-keystore backend to use.
    'unsupported' means stay-signed-in silently isn't offered (e.g. plain
    Linux dev machine with no DPAPI/Keystore equivalent wired up here)."""
    if "ANDROID_PRIVATE" in os.environ or "ANDROID_ARGUMENT" in os.environ:
        return "android"
    if sys.platform == "win32":
        return "windows"
    return "unsupported"


# ---------- Windows: DPAPI (CryptProtectData / CryptUnprotectData) ----------
# Ties the wrapped blob to the current Windows user account -- another user
# or another machine can't unwrap it, even with the file. No passphrase
# needed to unwrap: Windows itself gates access via the logged-in session.

def _win_dpapi_protect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise VaultError("Windows DPAPI CryptProtectData failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def _win_dpapi_unprotect(data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    )
    if not ok:
        raise VaultError("Windows DPAPI CryptUnprotectData failed (different user/machine, or corrupted)")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# ---------- Android: hardware-backed Keystore (AES/GCM key, non-exportable) ----------
# The AES key itself never leaves the TEE/StrongBox -- Python only ever
# sends plaintext in and gets ciphertext out (and vice versa) via JNI calls.
# NOTE: untested on-device from here (this environment has no Android
# runtime) -- verify with a real `buildozer deploy` + relogin/relaunch test.

_ANDROID_KEY_ALIAS = "flashchat_remember_me"


def _android_keystore_encrypt(data: bytes) -> bytes:
    from jnius import autoclass

    KeyStore = autoclass("java.security.KeyStore")
    KeyGenerator = autoclass("javax.crypto.KeyGenerator")
    KeyGenParameterSpecBuilder = autoclass("android.security.keystore.KeyGenParameterSpec$Builder")
    KeyProperties = autoclass("android.security.keystore.KeyProperties")
    Cipher = autoclass("javax.crypto.Cipher")

    ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(None)
    if not ks.containsAlias(_ANDROID_KEY_ALIAS):
        kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        spec = (KeyGenParameterSpecBuilder(
                    _ANDROID_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes([KeyProperties.BLOCK_MODE_GCM])
                .setEncryptionPaddings([KeyProperties.ENCRYPTION_PADDING_NONE])
                .build())
        kg.init(spec)
        kg.generateKey()

    key = ks.getKey(_ANDROID_KEY_ALIAS, None)
    cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    iv = bytes(cipher.getIV())  # 12 bytes, GCM standard
    ciphertext = bytes(cipher.doFinal(data))
    return iv + ciphertext


def _android_keystore_decrypt(blob: bytes) -> bytes:
    from jnius import autoclass

    KeyStore = autoclass("java.security.KeyStore")
    Cipher = autoclass("javax.crypto.Cipher")
    GCMParameterSpec = autoclass("javax.crypto.spec.GCMParameterSpec")

    ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(None)
    key = ks.getKey(_ANDROID_KEY_ALIAS, None)
    if key is None:
        raise VaultError("Android Keystore key missing (app data cleared or uninstalled/reinstalled)")

    iv, ciphertext = blob[:12], blob[12:]
    cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
    return bytes(cipher.doFinal(ciphertext))


# ---------- dispatch ----------

def wrap_vault_key_with_platform_keystore(raw_key: bytes, platform: str) -> bytes:
    if platform == "android":
        return _android_keystore_encrypt(raw_key)
    if platform == "windows":
        return _win_dpapi_protect(raw_key)
    raise NotImplementedError(f"no platform keystore wiring for '{platform}'")


def unwrap_vault_key_with_platform_keystore(wrapped: bytes, platform: str) -> bytes:
    if platform == "android":
        return _android_keystore_decrypt(wrapped)
    if platform == "windows":
        return _win_dpapi_unprotect(wrapped)
    raise NotImplementedError(f"no platform keystore wiring for '{platform}'")


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

    # ---------- stay-signed-in (hardware-keystore-backed) ----------

    def _remember_path(self) -> Path:
        return self.path.with_name(self.path.stem + "_remember.bin")

    def save_remember_me(self, passphrase: str, platform: str):
        """Call after a successful manual unlock/create if the user opted
        into staying signed in. Re-derives the vault key from the salt
        already on disk, wraps it via the platform keystore, and writes
        the wrapped blob next to the vault. The passphrase itself is
        never stored anywhere."""
        payload = json.loads(self.path.read_text())
        salt = sw.unb64(payload["salt"])
        key, _ = sw.derive_vault_key(passphrase, salt=salt)
        try:
            wrapped = wrap_vault_key_with_platform_keystore(bytes(key), platform)
            self._remember_path().write_bytes(wrapped)
        finally:
            key = bytearray(key)
            sw.secure_wipe(key)

    def try_auto_unlock(self, platform: str) -> Optional[dict]:
        """Returns the private key bundle if a remember-me blob exists and
        the platform keystore will still unwrap it, else None (caller
        should fall back to the normal passphrase login screen)."""
        remember_path = self._remember_path()
        if not (remember_path.exists() and self.path.exists()):
            return None
        try:
            key = unwrap_vault_key_with_platform_keystore(remember_path.read_bytes(), platform)
            payload = json.loads(self.path.read_text())
            plaintext = sw.aead_decrypt(key, sw.unb64(payload["blob"]))
            return json.loads(plaintext)
        except Exception as e:
            print(f"[vault] auto-unlock failed, falling back to manual login: {e}")
            return None

    def has_remember_me(self) -> bool:
        return self._remember_path().exists()

    def clear_remember_me(self):
        """Call on explicit logout -- forces the passphrase screen next launch."""
        p = self._remember_path()
        if p.exists():
            p.unlink()

