"""
shared/protocol.py

Wire format definitions shared between client and server.
IMPORTANT: This file contains ZERO cryptographic logic. It only defines
the shape of messages that cross the network. The server only ever
sees the fields marked OPAQUE below as base64 blobs it cannot interpret.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List
import time
import uuid


class MsgType(str, Enum):
    # --- Account / key management ---
    REGISTER = "register"                # client -> server: publish identity + prekeys
    FETCH_PREKEY_BUNDLE = "fetch_bundle"  # client -> server: request a user's public bundle
    PREKEY_BUNDLE = "prekey_bundle"       # server -> client: bundle response

    # --- Messaging (server treats ciphertext as OPAQUE bytes) ---
    SEND_MESSAGE = "send_message"         # client -> server: deliver ciphertext to recipient
    INCOMING_MESSAGE = "incoming_message" # server -> client: deliver queued ciphertext
    ACK = "ack"                           # client -> server: confirm delivery, ok to purge

    # --- WebRTC signaling (SDP/ICE payloads are also OPAQUE-ish; server just forwards) ---
    RTC_OFFER = "rtc_offer"
    RTC_ANSWER = "rtc_answer"
    RTC_ICE_CANDIDATE = "rtc_ice_candidate"

    # --- Presence ---
    PRESENCE_ONLINE = "presence_online"
    PRESENCE_OFFLINE = "presence_offline"


@dataclass
class PrekeyBundle:
    """Public material only. Never contains private keys."""
    user_id: str
    device_id: str
    identity_pubkey: str      # base64, X25519 public key
    signed_prekey: str        # base64, X25519 public key (rotated periodically)
    signed_prekey_sig: str    # base64, Ed25519 signature over signed_prekey
    one_time_prekey: Optional[str] = None  # base64, consumed on use (or None if exhausted)
    prekey_id: Optional[int] = None


@dataclass
class EncryptedEnvelope:
    """
    What actually rides over the wire for a message.
    `ciphertext` is OPAQUE to the server -- it is the output of the
    client's Double Ratchet encryption (XChaCha20-Poly1305 AEAD).
    """
    envelope_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender_id: str = ""
    recipient_id: str = ""
    sender_device_id: str = ""
    recipient_device_id: str = ""
    ciphertext: str = ""          # base64 OPAQUE blob
    header: str = ""              # base64 OPAQUE ratchet header (DH pubkey, counters) - encrypted-adjacent metadata
    is_prekey_message: bool = False  # true only for the first message in a session (carries X3DH init material)
    timestamp: float = field(default_factory=time.time)


@dataclass
class SignalingPayload:
    """WebRTC SDP/ICE relay - server forwards blind, does not parse semantics."""
    from_user: str
    to_user: str
    kind: str          # "offer" | "answer" | "ice"
    payload: str        # base64 OPAQUE (SDP/ICE candidate, itself should be sent over an already-encrypted channel where possible)
