"""
client/crypto/sodium_wrapper.py

Thin, boring wrapper around PyNaCl (libsodium bindings). Deliberately
minimal -- no custom crypto logic, just convenience calls into
well-audited primitives:

  - X25519          : key agreement (Diffie-Hellman)
  - Ed25519          : signatures (signing prekeys)
  - XChaCha20-Poly1305 (via nacl.secret / nacl.bindings) : AEAD encryption
  - Argon2id          : password-based key derivation (vault encryption)
  - HKDF (via hashlib/hmac, HKDF-SHA256) : ratchet key derivation

Install: pip install pynacl
"""

import os
import base64
import hashlib
import hmac as hmac_lib

import nacl.utils
import nacl.public
import nacl.signing
import nacl.pwhash
import nacl.secret
import nacl.bindings


# ---------- encoding helpers ----------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


# ---------- X25519 key agreement ----------

def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Returns (private_bytes, public_bytes)."""
    sk = nacl.public.PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)


def x25519_shared_secret(private_key: bytes, public_key: bytes) -> bytes:
    """Raw ECDH shared secret. Do NOT use directly as an encryption key --
    always run it through HKDF first (see hkdf() below)."""
    sk = nacl.public.PrivateKey(private_key)
    pk = nacl.public.PublicKey(public_key)
    box = nacl.public.Box(sk, pk)
    return box.shared_key()


# ---------- Ed25519 signatures (for signed prekeys) ----------

def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def sign(private_key: bytes, message: bytes) -> bytes:
    sk = nacl.signing.SigningKey(private_key)
    return sk.sign(message).signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    vk = nacl.signing.VerifyKey(public_key)
    try:
        vk.verify(message, signature)
        return True
    except Exception:
        return False


# ---------- AEAD encryption (XChaCha20-Poly1305) ----------

def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Returns nonce || ciphertext (ciphertext includes auth tag)."""
    nonce = nacl.utils.random(nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
    ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    nonce = blob[:nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]
    ct = blob[nacl.bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:]
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)


# ---------- HKDF-SHA256 (for ratchet key derivation) ----------

def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_lib.new(salt, input_key_material, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac_lib.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# ---------- Argon2id (password -> vault encryption key) ----------

def derive_vault_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derives a 32-byte key from a user passphrase using Argon2id
    (memory-hard, resistant to GPU/ASIC brute force). Returns (key, salt).
    Store the salt alongside the vault; NEVER store the derived key.
    """
    if salt is None:
        salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    key = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE,
    )
    return key, salt


def secure_wipe(buf: bytearray):
    """Best-effort zeroing of key material in memory. Python's GC/refcounting
    means this isn't airtight, but it shrinks the exposure window."""
    for i in range(len(buf)):
        buf[i] = 0
