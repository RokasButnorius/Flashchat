"""
client-desktop/session.py

Backend session logic for the desktop GUI. Reuses the exact same
X3DH + Double Ratchet crypto engine that was tested end-to-end in the
CLI client -- this file just adds Qt-friendly callback hooks and the
social graph calls (search/contacts/groups/profile/presence).
"""

import asyncio
import json
import uuid
from pathlib import Path

from nacl.public import PrivateKey

from crypto import keygen, sodium_wrapper as sw
from crypto import vault
from crypto.vault import Vault, VaultError
from crypto.ratchet import (
    RatchetState, x3dh_initiate, x3dh_respond,
    init_ratchet_sender, init_ratchet_receiver,
    encrypt_message, decrypt_message,
)
from network.ws_client import RelayClient
from crypto.session_persist import SessionStore

DATA_DIR = Path.home() / ".privacy-messenger"
RELAY_URL = "wss://relay.flashchat.store"  # swap to "ws://localhost:8765" for local testing


def _safe_filename(user_id: str) -> str:
    return "".join(c for c in user_id if c.isalnum() or c in ("-", "_")) or "user"


BUILT_IN_AVATARS = ["default", "red_fox", "blue_wolf", "green_frog", "purple_owl",
                     "orange_cat", "teal_bear", "pink_bunny", "yellow_duck"]


class GuiSession:
    """
    Callback hooks the GUI should set (all optional, all called from the
    Qt/asyncio event loop so it's safe to touch widgets directly):

      on_message(peer_id, text, mine: bool)
      on_group_message(group_id, sender_id, text)
      on_session_established(peer_id)
      on_presence(user_id, online: bool)
      on_search_results(results: list[dict])
      on_contacts_list(contacts: list[dict])
      on_contact_added(contact: dict, online: bool)
      on_group_created(group: dict)
      on_group_joined(group: dict, members: list[str])
      on_group_member_joined(group_id, user_id)
      on_groups_list(groups: list[dict])
      on_rtc_signal(kind: str, from_user: str, payload: str)
      on_error(reason: str)
    """

    def __init__(self, user_id: str, is_anonymous: bool = False):
        self.user_id = user_id
        self.is_anonymous = is_anonymous
        self.device_id: str | None = None
        safe = _safe_filename(user_id)
        self.vault_path = DATA_DIR / f"{safe}_vault.json"
        self.device_id_path = DATA_DIR / f"{safe}_device_id.txt"
        self.vault = Vault(self.vault_path)
        self.session_store = SessionStore(
            DATA_DIR / f"{safe}_sessions.json",
            DATA_DIR / f"{safe}_sessions_salt.bin",
        )
        self.private_keys: dict | None = None
        self.relay: RelayClient | None = None
        self.sessions: dict[str, RatchetState] = {}
        self._bundle_futures: dict[str, asyncio.Future] = {}

        # GUI hooks -- set these from the GUI layer
        self.on_message = None
        self.on_group_message = None
        self.on_session_established = None
        self.on_presence = None
        self.on_search_results = None
        self.on_contacts_list = None
        self.on_contact_added = None
        self.on_group_created = None
        self.on_group_joined = None
        self.on_group_member_joined = None
        self.on_groups_list = None
        self.on_rtc_signal = None
        self.on_error = None

    # ---------- identity ----------

    def setup_new_identity(self, passphrase: str | None):
        bundle = keygen.bootstrap_new_device()
        if not self.is_anonymous:
            self.vault.create(passphrase, bundle["private_bundle"])
            self.session_store.unlock(passphrase)
        self.private_keys = bundle["private_bundle"]
        return bundle["public_registration"]

    def unlock_existing_identity(self, passphrase: str, remember_me: bool = False):
        self.private_keys = self.vault.unlock(passphrase)
        self.session_store.unlock(passphrase)
        if remember_me:
            self.vault.save_remember_me(passphrase, vault.current_platform())
            self.session_store.save_remember_me(passphrase, vault.current_platform())

    def has_remembered_login(self) -> bool:
        return self.vault.has_remember_me()

    def try_auto_login(self) -> bool:
        """Call at startup before showing the login screen. Returns True
        and populates self.private_keys if a hardware-keystore-backed
        auto-unlock succeeds; False means show the passphrase screen as
        normal (nothing was left in a half-logged-in state)."""
        platform = vault.current_platform()
        bundle = self.vault.try_auto_unlock(platform)
        if bundle is None:
            return False
        self.private_keys = bundle
        session_bundle = self.session_store.try_auto_unlock(platform)
        if session_bundle is not None:
            self.sessions.update(session_bundle)
        return True

    def logout(self):
        """Wipes the remember-me blobs so the next launch requires the
        passphrase again. Does NOT delete the vault/sessions themselves --
        those still unlock normally with the passphrase."""
        self.vault.clear_remember_me()
        self.session_store.clear_remember_me()
        self.private_keys = None

    def load_device_id(self):
        if self.device_id_path.exists() and not self.is_anonymous:
            return self.device_id_path.read_text().strip()
        return None

    def save_device_id(self, device_id: str):
        self.device_id = device_id
        if not self.is_anonymous:
            self.device_id_path.parent.mkdir(parents=True, exist_ok=True)
            self.device_id_path.write_text(device_id)

    def my_identity_x25519_pub_b64(self) -> str:
        priv = sw.unb64(self.private_keys["identity_x25519_private"])
        return sw.b64(bytes(PrivateKey(priv).public_key))

    def rebuild_public_registration(self) -> dict:
        from nacl.signing import SigningKey
        pk = self.private_keys
        ed_sk = SigningKey(sw.unb64(pk["identity_ed25519_private"]))
        return {
            "identity_pubkey": self.my_identity_x25519_pub_b64(),
            "identity_ed25519_pubkey": sw.b64(bytes(ed_sk.verify_key)),
            "signed_prekey": pk["signed_prekey_public"],
            "signed_prekey_sig": sw.b64(sw.sign(sw.unb64(pk["identity_ed25519_private"]), sw.unb64(pk["signed_prekey_public"]))),
            "one_time_prekeys": pk.get("one_time_prekeys_public", []),
        }

    # ---------- networking ----------

    async def connect(self):
        self.sessions.update(self.session_store.load())
        self.relay = RelayClient(RELAY_URL, self.user_id)

        @self.relay.on("incoming_message")
        async def _(msg):
            await self._handle_incoming_envelope(msg["envelope"])

        @self.relay.on("prekey_bundle")
        async def _(msg):
            bundle = msg["bundle"]
            fut = self._bundle_futures.pop(bundle["user_id"], None)
            if fut and not fut.done():
                fut.set_result(bundle)

        @self.relay.on("presence_online")
        async def _(msg):
            if self.on_presence:
                self.on_presence(msg["user_id"], True)

        @self.relay.on("presence_offline")
        async def _(msg):
            if self.on_presence:
                self.on_presence(msg["user_id"], False)

        @self.relay.on("search_results")
        async def _(msg):
            if self.on_search_results:
                self.on_search_results(msg["results"])

        @self.relay.on("contacts_list")
        async def _(msg):
            if self.on_contacts_list:
                self.on_contacts_list(msg["contacts"])

        @self.relay.on("contact_added")
        async def _(msg):
            if self.on_contact_added:
                self.on_contact_added(msg["contact"], msg["online"])

        @self.relay.on("group_created")
        async def _(msg):
            if self.on_group_created:
                self.on_group_created(msg["group"])

        @self.relay.on("group_joined")
        async def _(msg):
            if self.on_group_joined:
                self.on_group_joined(msg["group"], msg["members"])

        @self.relay.on("group_member_joined")
        async def _(msg):
            if self.on_group_member_joined:
                self.on_group_member_joined(msg["group_id"], msg["user_id"])

        @self.relay.on("groups_list")
        async def _(msg):
            if self.on_groups_list:
                self.on_groups_list(msg["groups"])

        @self.relay.on("rtc_offer")
        async def _(msg):
            if self.on_rtc_signal:
                self.on_rtc_signal("offer", msg["from_user"], msg["payload"])

        @self.relay.on("rtc_answer")
        async def _(msg):
            if self.on_rtc_signal:
                self.on_rtc_signal("answer", msg["from_user"], msg["payload"])

        @self.relay.on("rtc_ice_candidate")
        async def _(msg):
            if self.on_rtc_signal:
                self.on_rtc_signal("ice", msg["from_user"], msg["payload"])

        @self.relay.on("error")
        async def _(msg):
            reason = msg.get("reason", "unknown error")
            for fut in self._bundle_futures.values():
                if not fut.done():
                    fut.set_exception(RuntimeError(reason))
            self._bundle_futures.clear()
            if self.on_error:
                self.on_error(reason)

        await self.relay.connect(is_anonymous=self.is_anonymous)

    async def register(self, public_registration: dict):
        got_response = asyncio.get_event_loop().create_future()

        @self.relay.on("registered")
        async def _(msg):
            if not got_response.done():
                got_response.set_result(msg["device_id"])

        await self.relay.register_device(public_registration)
        device_id = await asyncio.wait_for(got_response, timeout=10)
        self.save_device_id(device_id)

    # ---------- X3DH session bootstrap ----------

    async def start_session(self, peer_user_id: str) -> dict:
        bundle = await self._fetch_bundle(peer_user_id)
        valid = sw.verify(
            sw.unb64(bundle["identity_ed25519_pubkey"]),
            sw.unb64(bundle["signed_prekey"]),
            sw.unb64(bundle["signed_prekey_sig"]),
        )
        if not valid:
            raise RuntimeError(f"SECURITY: signed prekey signature invalid for {peer_user_id} -- possible MITM")

        my_identity_priv = sw.unb64(self.private_keys["identity_x25519_private"])
        ephemeral_priv, ephemeral_pub = sw.generate_x25519_keypair()

        root_key = x3dh_initiate(
            my_identity_priv=my_identity_priv,
            my_ephemeral_priv=ephemeral_priv,
            their_identity_pub=sw.unb64(bundle["identity_pubkey"]),
            their_signed_prekey_pub=sw.unb64(bundle["signed_prekey"]),
            their_one_time_prekey_pub=sw.unb64(bundle["one_time_prekey"]) if bundle.get("one_time_prekey") else None,
        )
        state = init_ratchet_sender(root_key, sw.unb64(bundle["signed_prekey"]))
        self.sessions[peer_user_id] = state
        self.session_store.save(self.sessions)

        return {
            "x3dh_ephemeral_pub": sw.b64(ephemeral_pub),
            "sender_identity_pub": self.my_identity_x25519_pub_b64(),
            "one_time_prekey_used": bundle.get("one_time_prekey"),
            "peer_device_id": bundle["device_id"],
        }

    async def _fetch_bundle(self, peer_user_id: str) -> dict:
        fut = asyncio.get_event_loop().create_future()
        self._bundle_futures[peer_user_id] = fut
        await self.relay.fetch_prekey_bundle(peer_user_id)
        return await asyncio.wait_for(fut, timeout=10)

    def _bootstrap_receiver_session(self, sender_identity_pub_b64, sender_ephemeral_pub_b64, one_time_prekey_used_b64):
        my_identity_priv = sw.unb64(self.private_keys["identity_x25519_private"])
        my_signed_prekey_priv = sw.unb64(self.private_keys["signed_prekey_private"])
        my_signed_prekey_pub = sw.unb64(self.private_keys["signed_prekey_public"])

        my_one_time_priv = None
        if one_time_prekey_used_b64:
            pub_list = self.private_keys.get("one_time_prekeys_public", [])
            priv_list = self.private_keys.get("one_time_prekeys_private", [])
            for pub_b64, priv_b64 in zip(pub_list, priv_list):
                if pub_b64 == one_time_prekey_used_b64:
                    my_one_time_priv = sw.unb64(priv_b64)
                    break

        root_key = x3dh_respond(
            my_identity_priv=my_identity_priv,
            my_signed_prekey_priv=my_signed_prekey_priv,
            my_one_time_prekey_priv=my_one_time_priv,
            their_identity_pub=sw.unb64(sender_identity_pub_b64),
            their_ephemeral_pub=sw.unb64(sender_ephemeral_pub_b64),
        )
        return init_ratchet_receiver(root_key, my_signed_prekey_priv, my_signed_prekey_pub)

    # ---------- send / receive ----------

    async def send_message(self, peer_user_id: str, plaintext: str, x3dh_init: dict | None = None):
        state = self.sessions.get(peer_user_id)
        if state is None:
            raise RuntimeError(f"no session with {peer_user_id}")

        ratchet_header, ciphertext = encrypt_message(state, plaintext.encode("utf-8"))
        header_payload = {"ratchet_header": ratchet_header}
        is_prekey_message = x3dh_init is not None
        if is_prekey_message:
            header_payload["x3dh_init"] = x3dh_init

        envelope = {
            "envelope_id": uuid.uuid4().hex,
            "sender_id": self.user_id,
            "recipient_id": peer_user_id,
            "sender_device_id": self.device_id or "unknown",
            "recipient_device_id": x3dh_init["peer_device_id"] if x3dh_init else "unknown",
            "ciphertext": sw.b64(ciphertext),
            "header": json.dumps(header_payload),
            "is_prekey_message": is_prekey_message,
        }
        await self.relay.send_envelope(envelope)
        self.session_store.save(self.sessions)

    async def send_to_peer(self, peer_user_id: str, text: str):
        """High-level helper: bootstraps a session automatically if needed."""
        if peer_user_id not in self.sessions:
            x3dh_init = await self.start_session(peer_user_id)
            await self.send_message(peer_user_id, text, x3dh_init=x3dh_init)
        else:
            await self.send_message(peer_user_id, text)
        if self.on_message:
            self.on_message(peer_user_id, text, True)

    async def _handle_incoming_envelope(self, envelope: dict):
        peer_id = envelope["sender_id"]
        header_payload = json.loads(envelope["header"])
        ciphertext = sw.unb64(envelope["ciphertext"])

        state = self.sessions.get(peer_id)
        if state is None:
            if not envelope.get("is_prekey_message") or "x3dh_init" not in header_payload:
                return
            init = header_payload["x3dh_init"]
            state = self._bootstrap_receiver_session(
                init["sender_identity_pub"], init["x3dh_ephemeral_pub"], init.get("one_time_prekey_used"),
            )
            self.sessions[peer_id] = state
            if self.on_session_established:
                self.on_session_established(peer_id)

        plaintext = decrypt_message(state, header_payload["ratchet_header"], ciphertext)
        await self.relay.ack(envelope["envelope_id"])
        self.session_store.save(self.sessions)
        if self.on_message:
            self.on_message(peer_id, plaintext.decode("utf-8"), False)

    # ---------- social graph passthroughs ----------

    async def search_users(self, query: str):
        await self.relay.search_users(query)

    async def add_contact(self, contact_id: str):
        await self.relay.add_contact(contact_id)

    async def list_contacts(self):
        await self.relay.list_contacts()

    async def update_profile(self, bio: str = None, avatar_id: str = None):
        await self.relay.update_profile(bio=bio, avatar_id=avatar_id)

    async def create_group(self, name: str):
        await self.relay.create_group(name)

    async def join_group(self, invite_token: str):
        await self.relay.join_group(invite_token)

    async def list_groups(self):
        await self.relay.list_groups()

    async def send_rtc_signal(self, kind: str, to_user: str, payload: str):
        await self.relay.send_signal(kind, to_user, payload)
