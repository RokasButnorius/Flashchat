"""
client/crypto/keygen.py

Everything here runs 100% locally. The server NEVER sees anything
generated in this file except the public halves, which get pushed
via register_device().
"""

from dataclasses import dataclass, field
from typing import List
import time

from . import sodium_wrapper as sw


@dataclass
class IdentityKeys:
    """Long-term identity keypair. Generated once per device, on first launch."""
    ed25519_private: bytes   # for signing (proves ownership of signed prekeys)
    ed25519_public: bytes
    x25519_private: bytes    # for DH key agreement (X3DH / ratchet)
    x25519_public: bytes


@dataclass
class SignedPrekey:
    private: bytes
    public: bytes
    signature: bytes         # Ed25519 sig over public, using identity key
    created_at: float = field(default_factory=time.time)


@dataclass
class OneTimePrekey:
    private: bytes
    public: bytes


def generate_identity_keys() -> IdentityKeys:
    ed_sk, ed_pk = sw.generate_ed25519_keypair()
    x_sk, x_pk = sw.generate_x25519_keypair()
    return IdentityKeys(ed_sk, ed_pk, x_sk, x_pk)


def generate_signed_prekey(identity: IdentityKeys) -> SignedPrekey:
    """Rotate this periodically (e.g. weekly) -- limits exposure if a
    prekey private key is ever compromised."""
    sk, pk = sw.generate_x25519_keypair()
    sig = sw.sign(identity.ed25519_private, pk)
    return SignedPrekey(sk, pk, sig)


def generate_one_time_prekeys(count: int = 100) -> List[OneTimePrekey]:
    """A batch of single-use X25519 keys. Server hands one out per
    handshake and marks it consumed. Client should replenish the
    server's supply when it runs low."""
    return [OneTimePrekey(*sw.generate_x25519_keypair()) for _ in range(count)]


def bootstrap_new_device() -> dict:
    """
    Full first-launch flow. Returns everything needed to:
      1. populate the local encrypted vault (private halves)
      2. register with the server (public halves only)
    """
    identity = generate_identity_keys()
    signed_prekey = generate_signed_prekey(identity)
    one_time_prekeys = generate_one_time_prekeys()

    private_bundle = {
        "identity_ed25519_private": sw.b64(identity.ed25519_private),
        "identity_x25519_private": sw.b64(identity.x25519_private),
        "signed_prekey_private": sw.b64(signed_prekey.private),
        "signed_prekey_public": sw.b64(signed_prekey.public),
        "one_time_prekeys_private": [sw.b64(k.private) for k in one_time_prekeys],
        "one_time_prekeys_public": [sw.b64(k.public) for k in one_time_prekeys],
    }

    public_registration = {
        "identity_pubkey": sw.b64(identity.x25519_public),
        "identity_ed25519_pubkey": sw.b64(identity.ed25519_public),
        "signed_prekey": sw.b64(signed_prekey.public),
        "signed_prekey_sig": sw.b64(signed_prekey.signature),
        "one_time_prekeys": [sw.b64(k.public) for k in one_time_prekeys],
    }

    return {"private_bundle": private_bundle, "public_registration": public_registration}
