"""
client/crypto/ratchet.py

Implements the Signal-style X3DH handshake + Double Ratchet.
This is where all the actual message encryption/decryption happens --
entirely client-side. The server never sees any key or state from
this module except the public keys that get embedded in the
`header` field of an EncryptedEnvelope (also public/opaque to server).

Reference: Signal's X3DH + Double Ratchet specs (signal.org/docs).
This is a compact, readable implementation -- audit before production use.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
import os

from . import sodium_wrapper as sw

INFO_X3DH = b"PrivacyMessenger_X3DH_v1"
INFO_RATCHET = b"PrivacyMessenger_Ratchet_v1"


# ---------------- X3DH: initial handshake to establish a shared root key ----------------

def x3dh_initiate(my_identity_priv: bytes, my_ephemeral_priv: bytes,
                   their_identity_pub: bytes, their_signed_prekey_pub: bytes,
                   their_one_time_prekey_pub: Optional[bytes]) -> bytes:
    """
    Sender side (Alice). Combines multiple DH outputs so that
    compromising any single key doesn't break the session.
    """
    dh1 = sw.x25519_shared_secret(my_identity_priv, their_signed_prekey_pub)
    dh2 = sw.x25519_shared_secret(my_ephemeral_priv, their_identity_pub)
    dh3 = sw.x25519_shared_secret(my_ephemeral_priv, their_signed_prekey_pub)
    material = dh1 + dh2 + dh3
    if their_one_time_prekey_pub:
        dh4 = sw.x25519_shared_secret(my_ephemeral_priv, their_one_time_prekey_pub)
        material += dh4
    return sw.hkdf(material, salt=b"\x00" * 32, info=INFO_X3DH, length=32)


def x3dh_respond(my_identity_priv: bytes, my_signed_prekey_priv: bytes,
                  my_one_time_prekey_priv: Optional[bytes],
                  their_identity_pub: bytes, their_ephemeral_pub: bytes) -> bytes:
    """Receiver side (Bob), mirrors the same DH computations in the
    order that produces an identical shared secret."""
    dh1 = sw.x25519_shared_secret(my_signed_prekey_priv, their_identity_pub)
    dh2 = sw.x25519_shared_secret(my_identity_priv, their_ephemeral_pub)
    dh3 = sw.x25519_shared_secret(my_signed_prekey_priv, their_ephemeral_pub)
    material = dh1 + dh2 + dh3
    if my_one_time_prekey_priv:
        dh4 = sw.x25519_shared_secret(my_one_time_prekey_priv, their_ephemeral_pub)
        material += dh4
    return sw.hkdf(material, salt=b"\x00" * 32, info=INFO_X3DH, length=32)


# ---------------- Double Ratchet: per-message forward-secret encryption ----------------

@dataclass
class RatchetState:
    root_key: bytes
    dh_self_priv: bytes
    dh_self_pub: bytes
    dh_remote_pub: Optional[bytes] = None
    send_chain_key: Optional[bytes] = None
    recv_chain_key: Optional[bytes] = None
    send_count: int = 0
    recv_count: int = 0
    # skipped message keys, keyed by (remote_dh_pub, counter), for out-of-order delivery
    skipped_keys: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)


def _kdf_root(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
    out = sw.hkdf(dh_output, salt=root_key, info=INFO_RATCHET, length=64)
    return out[:32], out[32:]  # new_root_key, new_chain_key


def _kdf_chain(chain_key: bytes) -> Tuple[bytes, bytes]:
    """Derives (next_chain_key, message_key) from current chain key.
    Each call ratchets forward -- old chain_key is discarded, giving
    forward secrecy within a chain."""
    next_chain_key = sw.hkdf(chain_key, salt=b"\x01", info=INFO_RATCHET, length=32)
    message_key = sw.hkdf(chain_key, salt=b"\x02", info=INFO_RATCHET, length=32)
    return next_chain_key, message_key


def init_ratchet_sender(root_key: bytes, their_signed_prekey_pub: bytes) -> RatchetState:
    dh_priv, dh_pub = sw.generate_x25519_keypair()
    dh_out = sw.x25519_shared_secret(dh_priv, their_signed_prekey_pub)
    new_root, send_chain = _kdf_root(root_key, dh_out)
    return RatchetState(root_key=new_root, dh_self_priv=dh_priv, dh_self_pub=dh_pub,
                         dh_remote_pub=their_signed_prekey_pub, send_chain_key=send_chain)


def init_ratchet_receiver(root_key: bytes, my_signed_prekey_priv: bytes,
                           my_signed_prekey_pub: bytes) -> RatchetState:
    # receiver's chain key gets populated on first received message (see ratchet_step below)
    return RatchetState(root_key=root_key, dh_self_priv=my_signed_prekey_priv,
                         dh_self_pub=my_signed_prekey_pub)


def encrypt_message(state: RatchetState, plaintext: bytes) -> Tuple[dict, bytes]:
    """Returns (header, ciphertext). header carries the current DH pubkey
    + counter -- needed by the recipient to derive the matching key.
    header is not secret, but it IS authenticated (bound as AEAD AAD)."""
    if state.send_chain_key is None:
        raise RuntimeError("ratchet not initialized for sending")
    state.send_chain_key, msg_key = _kdf_chain(state.send_chain_key)
    header = {"dh_pub": sw.b64(state.dh_self_pub), "n": state.send_count}
    aad = (header["dh_pub"] + ":" + str(header["n"])).encode()
    ciphertext = sw.aead_encrypt(msg_key, plaintext, aad=aad)
    state.send_count += 1
    return header, ciphertext


MAX_SKIP = 1000  # safety cap on how many message keys we'll cache while catching up -- prevents a malicious/corrupt counter from forcing unbounded key derivation


def _skip_message_keys(state: RatchetState, until: int):
    """Derive and cache message keys for counters recv_count..until-1 on the
    current receive chain, so a message that arrives later out of order can
    still find its key and decrypt, instead of failing because the ratchet
    already moved past it."""
    if until - state.recv_count > MAX_SKIP:
        raise RuntimeError("too many skipped messages -- refusing to cache (possible DoS)")
    while state.recv_count < until:
        state.recv_chain_key, msg_key = _kdf_chain(state.recv_chain_key)
        state.skipped_keys[(state.dh_remote_pub, state.recv_count)] = msg_key
        state.recv_count += 1


def decrypt_message(state: RatchetState, header: dict, ciphertext: bytes) -> bytes:
    remote_dh_pub = sw.unb64(header["dh_pub"])
    counter = header["n"]
    aad = (header["dh_pub"] + ":" + str(counter)).encode()

    # Check the skipped-key cache first -- handles a message that arrives
    # late/out-of-order, whose key we already derived and stored while
    # skipping ahead for an earlier message.
    cache_key = (remote_dh_pub, counter)
    if cache_key in state.skipped_keys:
        msg_key = state.skipped_keys.pop(cache_key)
        return sw.aead_decrypt(msg_key, ciphertext, aad=aad)

    # DH ratchet step: new remote pubkey means we advance the root chain
    if state.dh_remote_pub != remote_dh_pub:
        dh_out = sw.x25519_shared_secret(state.dh_self_priv, remote_dh_pub)
        state.root_key, state.recv_chain_key = _kdf_root(state.root_key, dh_out)
        state.dh_remote_pub = remote_dh_pub
        state.recv_count = 0
        # also generate our next sending keypair for the reply
        state.dh_self_priv, state.dh_self_pub = sw.generate_x25519_keypair()
        dh_out2 = sw.x25519_shared_secret(state.dh_self_priv, remote_dh_pub)
        state.root_key, state.send_chain_key = _kdf_root(state.root_key, dh_out2)
        state.send_count = 0

    # Cache any keys we're skipping forward over on the current chain, so a
    # message arriving later out of order can still be decrypted.
    if counter > state.recv_count:
        _skip_message_keys(state, counter)

    state.recv_chain_key, msg_key = _kdf_chain(state.recv_chain_key)
    state.recv_count += 1
    return sw.aead_decrypt(msg_key, ciphertext, aad=aad)
