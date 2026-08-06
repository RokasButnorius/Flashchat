"""
client-desktop/main.py

Privacy Messenger -- desktop client. PySide6 + qasync (so the existing
asyncio-based E2EE/network code runs on the same event loop as the GUI,
no threading headaches). Run: python main.py
"""

import sys
import asyncio
import uuid as uuid_lib

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QListWidget, QListWidgetItem, QScrollArea,
    QFrame, QDialog, QComboBox, QGridLayout, QMessageBox, QInputDialog,
    QCheckBox, QSizePolicy, QStackedWidget
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QFont, QImage, QPixmap
import qasync

from theme import STYLESHEET, avatar_color, AVATAR_EMOJI
from session import GuiSession, BUILT_IN_AVATARS
from crypto.vault import VaultError
import calling


def avatar_widget(user_id: str, avatar_id: str = "default", size: int = 36) -> QLabel:
    lbl = QLabel(AVATAR_EMOJI.get(avatar_id, "🙂"))
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setFixedSize(size, size)
    lbl.setStyleSheet(
        f"background-color: {avatar_color(user_id)}; border-radius: {size // 2}px; "
        f"font-size: {int(size * 0.55)}px;"
    )
    return lbl


class MessageBubble(QFrame):
    def __init__(self, sender: str, text: str, mine: bool):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)

        bubble = QLabel(text)
        bubble.setWordWrap(True)
        bubble.setMaximumWidth(420)
        bubble.setMinimumWidth(0)
        bubble.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        bg = "#e6394a" if mine else "#2b2e37"
        bubble.setStyleSheet(
            f"background-color: {bg}; color: white; border-radius: 12px; padding: 8px 12px;"
        )
        if mine:
            layout.addStretch()
            layout.addWidget(bubble)
        else:
            layout.addWidget(avatar_widget(sender, size=28))
            layout.addWidget(bubble)
            layout.addStretch()


class SystemNote(QFrame):
    def __init__(self, text: str):
        super().__init__()
        layout = QHBoxLayout(self)
        lbl = QLabel(text)
        lbl.setStyleSheet("color: #5c6068; font-style: italic; font-size: 11px;")
        lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(lbl)


class SettingsDialog(QDialog):
    def __init__(self, session: GuiSession, current_bio: str, current_avatar: str, parent=None):
        super().__init__(parent)
        self.session = session
        self.setWindowTitle("Profile Settings")
        self.setMinimumWidth(360)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Bio"))
        self.bio_input = QLineEdit(current_bio)
        layout.addWidget(self.bio_input)

        layout.addWidget(QLabel("Avatar"))
        grid = QGridLayout()
        self.selected_avatar = current_avatar
        self.avatar_buttons = {}
        for i, av in enumerate(BUILT_IN_AVATARS):
            btn = QPushButton(AVATAR_EMOJI.get(av, "🙂"))
            btn.setCheckable(True)
            btn.setChecked(av == current_avatar)
            btn.setFixedSize(44, 44)
            btn.clicked.connect(lambda _, a=av: self._select_avatar(a))
            self.avatar_buttons[av] = btn
            grid.addWidget(btn, i // 5, i % 5)
        layout.addLayout(grid)

        save_btn = QPushButton("Save")
        save_btn.setObjectName("AccentButton")
        save_btn.clicked.connect(self._save)
        layout.addWidget(save_btn)

    def _select_avatar(self, av):
        self.selected_avatar = av
        for a, btn in self.avatar_buttons.items():
            btn.setChecked(a == av)

    def _save(self):
        asyncio.ensure_future(self.session.update_profile(
            bio=self.bio_input.text(), avatar_id=self.selected_avatar,
        ))
        self.accept()


class CallDialog(QDialog):
    def __init__(self, session: GuiSession, peer_id: str, incoming_offer: str | None, parent=None):
        super().__init__(parent)
        self.session = session
        self.peer_id = peer_id
        self.setWindowTitle(f"Call with {peer_id}")
        self.setMinimumSize(420, 320)
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel(f"Call with {peer_id}"))

        form = QGridLayout()
        form.addWidget(QLabel("Microphone:"), 0, 0)
        self.mic_combo = QComboBox()
        mics = calling.list_audio_input_devices()
        if mics:
            for d in mics:
                self.mic_combo.addItem(d["name"], d["name"])
        else:
            self.mic_combo.addItem("No microphones detected", None)
        form.addWidget(self.mic_combo, 0, 1)

        form.addWidget(QLabel("Speaker:"), 1, 0)
        self.speaker_combo = QComboBox()
        speakers = calling.list_audio_output_devices()
        if speakers:
            for d in speakers:
                self.speaker_combo.addItem(d["name"], d["name"])
        else:
            self.speaker_combo.addItem("No speakers detected", None)
        form.addWidget(self.speaker_combo, 1, 1)

        form.addWidget(QLabel("Camera:"), 2, 0)
        self.camera_combo = QComboBox()
        self.camera_combo.addItem("No camera (voice only)", None)
        cams = calling.list_camera_devices()
        for d in cams:
            self.camera_combo.addItem(d["name"], d["name"])
        form.addWidget(self.camera_combo, 2, 1)

        layout.addLayout(form)

        self.status_label = QLabel("Ready to call" if not incoming_offer else "Incoming call...")
        self.status_label.setStyleSheet("color: #9a9ea8;")
        layout.addWidget(self.status_label)

        self.video_label = QLabel()
        self.video_label.setFixedSize(400, 260)
        self.video_label.setStyleSheet("background-color: #101114; border-radius: 8px;")
        self.video_label.setAlignment(Qt.AlignCenter)
        self.video_label.setText("No video")
        self.video_label.setVisible(False)  # only shown once actual video frames start arriving
        layout.addWidget(self.video_label)

        btn_row = QHBoxLayout()
        if incoming_offer:
            accept_btn = QPushButton("Accept")
            accept_btn.setObjectName("AccentButton")
            accept_btn.clicked.connect(lambda: self._accept(incoming_offer))
            btn_row.addWidget(accept_btn)
        else:
            start_btn = QPushButton("Start Call")
            start_btn.setObjectName("AccentButton")
            start_btn.clicked.connect(self._start)
            btn_row.addWidget(start_btn)

        end_btn = QPushButton("Hang Up / Close")
        end_btn.clicked.connect(self._end)
        btn_row.addWidget(end_btn)
        layout.addLayout(btn_row)

        self.call_manager = calling.CallManager(
            session,
            on_remote_track=lambda track: self.status_label.setText("Connected -- receiving media"),
            on_call_ended=lambda: self.status_label.setText("Call ended"),
            on_state_change=self._on_connection_state_change,
            on_video_frame=self._on_video_frame,
        )

    def _on_video_frame(self, pil_image):
        # Called directly from the asyncio loop (same thread as Qt under
        # qasync), so it's safe to touch widgets here directly.
        img = pil_image.convert("RGB")
        data = img.tobytes("raw", "RGB")
        qimg = QImage(data, img.width, img.height, img.width * 3, QImage.Format_RGB888)
        pixmap = QPixmap.fromImage(qimg).scaled(
            self.video_label.width(), self.video_label.height(),
            Qt.KeepAspectRatio, Qt.SmoothTransformation,
        )
        self.video_label.setPixmap(pixmap)
        if not self.video_label.isVisible():
            self.video_label.setVisible(True)

    def _on_connection_state_change(self, state):
        labels = {
            "new": "Initializing...",
            "connecting": "Connecting (negotiating network path)...",
            "connected": "Connected ✅",
            "disconnected": "Disconnected",
            "failed": "Connection failed -- likely NAT/firewall blocking direct connection",
            "closed": "Call ended",
            "timeout": "Timed out after 20s -- check Windows Firewall allows python.exe, or your network may need a TURN relay (not yet set up)",
        }
        self.status_label.setText(labels.get(state, state))

    def _start(self):
        mic = self.mic_combo.currentData()
        cam = self.camera_combo.currentData()
        speaker = self.speaker_combo.currentData()
        self.status_label.setText("Calling...")
        asyncio.ensure_future(self.call_manager.start_call(self.peer_id, mic_device=mic, camera_device=cam, speaker_device=speaker))

    def _accept(self, offer_payload):
        speaker = self.speaker_combo.currentData()
        self.status_label.setText("Connecting...")
        asyncio.ensure_future(self.call_manager.handle_offer(self.peer_id, offer_payload, speaker_device=speaker))

    def _end(self):
        asyncio.ensure_future(self.call_manager.end_call())
        self.close()


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("FlashChat -- Sign In")
        self.setMinimumWidth(360)
        self.result_user_id = None
        self.result_passphrase = None
        self.result_anonymous = False

        layout = QVBoxLayout(self)
        title = QLabel("🔒 FlashChat")
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        layout.addWidget(title)

        layout.addWidget(QLabel("User ID"))
        self.user_input = QLineEdit()
        layout.addWidget(self.user_input)

        layout.addWidget(QLabel("Vault Passphrase"))
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pass_input)

        self.anon_check = QCheckBox("Anonymous mode (temporary identity, not saved to disk)")
        self.anon_check.stateChanged.connect(self._toggle_anon)
        layout.addWidget(self.anon_check)

        connect_btn = QPushButton("Connect")
        connect_btn.setObjectName("AccentButton")
        connect_btn.clicked.connect(self._submit)
        layout.addWidget(connect_btn)

    def _toggle_anon(self, state):
        anon = bool(state)
        self.pass_input.setEnabled(not anon)
        if anon:
            self.user_input.setText("anon_" + uuid_lib.uuid4().hex[:8])

    def _submit(self):
        if not self.user_input.text().strip():
            QMessageBox.warning(self, "Missing info", "Enter a user ID.")
            return
        self.result_user_id = self.user_input.text().strip()
        self.result_passphrase = self.pass_input.text()
        self.result_anonymous = self.anon_check.isChecked()
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self, session: GuiSession):
        super().__init__()
        self.session = session
        self.setWindowTitle(f"FlashChat -- {session.user_id}")
        self.resize(1000, 640)

        self.active_peer = None
        self.contacts = {}   # user_id -> {bio, avatar_id, online}
        self.groups = {}     # group_id -> {name, members, invite_token}
        self.message_widgets = {}  # peer_id -> list of widgets (for rebuild)
        self.chat_history = {}     # peer_id -> [(sender, text, mine)]
        self._open_call_dialogs = []  # tracks open CallDialog instances so incoming answer/ice signals can be routed to the right one

        self._build_ui()
        self._wire_session_hooks()

        asyncio.ensure_future(self.session.list_contacts())
        asyncio.ensure_future(self.session.list_groups())

    # ---------- UI construction ----------

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --- Sidebar ---
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(300)
        sb_layout = QVBoxLayout(sidebar)

        profile_row = QHBoxLayout()
        self.my_avatar_lbl = avatar_widget(self.session.user_id, size=40)
        profile_row.addWidget(self.my_avatar_lbl)
        name_col = QVBoxLayout()
        name_col.addWidget(QLabel(f"<b>{self.session.user_id}</b>"))
        self.my_bio_lbl = QLabel("")
        self.my_bio_lbl.setStyleSheet("color: #9a9ea8; font-size: 11px;")
        name_col.addWidget(self.my_bio_lbl)
        profile_row.addLayout(name_col)
        profile_row.addStretch()
        settings_btn = QPushButton("⚙")
        settings_btn.setObjectName("IconButton")
        settings_btn.clicked.connect(self._open_settings)
        profile_row.addWidget(settings_btn)
        sb_layout.addLayout(profile_row)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search people...")
        self.search_input.textChanged.connect(self._on_search_text_changed)
        sb_layout.addWidget(self.search_input)

        self.search_results_list = QListWidget()
        self.search_results_list.setTextElideMode(Qt.ElideNone)
        self.search_results_list.setWordWrap(True)
        self.search_results_list.setMaximumHeight(120)
        self.search_results_list.setVisible(False)
        self.search_results_list.itemClicked.connect(self._on_search_result_clicked)
        sb_layout.addWidget(self.search_results_list)

        sb_layout.addWidget(self._section_label("FRIENDS"))
        self.friends_list = QListWidget()
        self.friends_list.setTextElideMode(Qt.ElideNone)
        self.friends_list.setWordWrap(True)
        self.friends_list.itemClicked.connect(self._on_friend_clicked)
        sb_layout.addWidget(self.friends_list, stretch=1)

        groups_header = QHBoxLayout()
        groups_header.addWidget(self._section_label("GROUPS"))
        groups_header.addStretch()
        new_group_btn = QPushButton("+ New")
        new_group_btn.clicked.connect(self._create_group_dialog)
        join_group_btn = QPushButton("Join")
        join_group_btn.clicked.connect(self._join_group_dialog)
        groups_header.addWidget(new_group_btn)
        groups_header.addWidget(join_group_btn)
        sb_layout.addLayout(groups_header)

        self.groups_list = QListWidget()
        self.groups_list.setTextElideMode(Qt.ElideNone)
        self.groups_list.setWordWrap(True)
        self.groups_list.itemClicked.connect(self._on_group_clicked)
        self.groups_list.setMaximumHeight(140)
        sb_layout.addWidget(self.groups_list)

        root.addWidget(sidebar)

        # --- Chat panel ---
        chat_panel = QWidget()
        chat_panel.setObjectName("ChatPanel")
        cp_layout = QVBoxLayout(chat_panel)
        cp_layout.setContentsMargins(0, 0, 0, 0)
        cp_layout.setSpacing(0)

        header = QWidget()
        header.setObjectName("ChatHeader")
        header.setFixedHeight(56)
        h_layout = QHBoxLayout(header)
        name_col2 = QVBoxLayout()
        self.peer_name_lbl = QLabel("Select a contact")
        self.peer_name_lbl.setObjectName("PeerName")
        self.peer_sub_lbl = QLabel("")
        self.peer_sub_lbl.setObjectName("PeerSub")
        name_col2.addWidget(self.peer_name_lbl)
        name_col2.addWidget(self.peer_sub_lbl)
        h_layout.addLayout(name_col2)
        h_layout.addStretch()

        voice_btn = QPushButton("📞")
        voice_btn.setObjectName("IconButton")
        voice_btn.clicked.connect(lambda: self._open_call(video=False))
        video_btn = QPushButton("🎥")
        video_btn.setObjectName("IconButton")
        video_btn.clicked.connect(lambda: self._open_call(video=True))
        h_layout.addWidget(voice_btn)
        h_layout.addWidget(video_btn)
        cp_layout.addWidget(header)

        self.messages_scroll = QScrollArea()
        self.messages_scroll.setWidgetResizable(True)
        self.messages_container = QWidget()
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.addStretch()
        self.messages_scroll.setWidget(self.messages_container)
        cp_layout.addWidget(self.messages_scroll, stretch=1)

        composer = QHBoxLayout()
        self.composer_input = QLineEdit()
        self.composer_input.setPlaceholderText("Message...")
        self.composer_input.setEnabled(False)
        self.composer_input.returnPressed.connect(self._send_message)
        composer.addWidget(self.composer_input)

        for emoji in ["👍", "❤️", "😂"]:
            btn = QPushButton(emoji)
            btn.setFixedWidth(36)
            btn.clicked.connect(lambda _, e=emoji: self._send_quick_reaction(e))
            composer.addWidget(btn)

        send_btn = QPushButton("Send")
        send_btn.setObjectName("AccentButton")
        send_btn.clicked.connect(self._send_message)
        composer.addWidget(send_btn)
        cp_layout.addLayout(composer)

        root.addWidget(chat_panel, stretch=1)

    def _section_label(self, text):
        lbl = QLabel(text)
        lbl.setObjectName("SectionLabel")
        return lbl

    # ---------- session -> GUI hooks ----------

    def _wire_session_hooks(self):
        s = self.session
        s.on_message = self._handle_incoming_message
        s.on_session_established = lambda peer: self._add_system_note(peer, f"Session established with {peer}")
        s.on_presence = self._handle_presence
        s.on_search_results = self._handle_search_results
        s.on_contacts_list = self._handle_contacts_list
        s.on_contact_added = self._handle_contact_added
        s.on_group_created = self._handle_group_created
        s.on_group_joined = self._handle_group_joined
        s.on_group_member_joined = lambda gid, uid: None
        s.on_groups_list = self._handle_groups_list
        s.on_rtc_signal = self._handle_rtc_signal
        s.on_error = lambda reason: QMessageBox.warning(self, "Error", reason)

    # ---------- search / friends ----------

    def _on_search_text_changed(self, text):
        if len(text) >= 2:
            asyncio.ensure_future(self.session.search_users(text))
        else:
            self.search_results_list.setVisible(False)

    def _handle_search_results(self, results):
        self.search_results_list.clear()
        self.search_results_list.setVisible(bool(results))
        for r in results:
            item = QListWidgetItem(f"{AVATAR_EMOJI.get(r['avatar_id'], '🙂')}  {r['id']}")
            item.setData(Qt.UserRole, r["id"])
            self.search_results_list.addItem(item)

    def _on_search_result_clicked(self, item):
        contact_id = item.data(Qt.UserRole)
        asyncio.ensure_future(self.session.add_contact(contact_id))
        self.search_input.clear()
        self.search_results_list.setVisible(False)

    def _handle_contact_added(self, contact, online):
        self.contacts[contact["id"]] = {"bio": contact.get("bio", ""), "avatar_id": contact.get("avatar_id", "default"), "online": online}
        self._refresh_friends_list()

    def _handle_contacts_list(self, contacts):
        for c in contacts:
            self.contacts[c["id"]] = {"bio": c.get("bio", ""), "avatar_id": c.get("avatar_id", "default"), "online": c.get("online", False)}
        self._refresh_friends_list()

    def _refresh_friends_list(self):
        self.friends_list.clear()
        for user_id, info in self.contacts.items():
            dot = "🟢" if info["online"] else "⚪"
            item = QListWidgetItem(f"{dot} {AVATAR_EMOJI.get(info['avatar_id'], '🙂')} {user_id}")
            item.setData(Qt.UserRole, user_id)
            self.friends_list.addItem(item)

    def _handle_presence(self, user_id, online):
        if user_id in self.contacts:
            self.contacts[user_id]["online"] = online
            self._refresh_friends_list()
            if self.active_peer == user_id:
                self._update_peer_header()

    def _on_friend_clicked(self, item):
        self._select_peer(item.data(Qt.UserRole))

    # ---------- groups ----------

    def _create_group_dialog(self):
        name, ok = QInputDialog.getText(self, "New Group", "Group name:")
        if ok and name.strip():
            asyncio.ensure_future(self.session.create_group(name.strip()))

    def _join_group_dialog(self):
        token, ok = QInputDialog.getText(self, "Join Group", "Paste invite link/code:")
        if ok and token.strip():
            asyncio.ensure_future(self.session.join_group(token.strip().split("/")[-1]))

    def _handle_group_created(self, group):
        self.groups[group["id"]] = {"name": group["name"], "members": [self.session.user_id],
                                     "invite_token": group["invite_token"]}
        self._refresh_groups_list()
        QMessageBox.information(self, "Group created",
                                 f"'{group['name']}' created.\nInvite link:\nflashchat.store/invite/{group['invite_token']}")

    def _handle_group_joined(self, group, members):
        self.groups[group["id"]] = {"name": group["name"], "members": members, "invite_token": group["invite_token"]}
        self._refresh_groups_list()

    def _handle_groups_list(self, groups):
        for g in groups:
            self.groups[g["id"]] = {"name": g["name"], "members": g.get("members", []), "invite_token": g["invite_token"]}
        self._refresh_groups_list()

    def _refresh_groups_list(self):
        self.groups_list.clear()
        for gid, info in self.groups.items():
            item = QListWidgetItem(f"# {info['name']} ({len(info['members'])})")
            item.setData(Qt.UserRole, gid)
            self.groups_list.addItem(item)

    def _on_group_clicked(self, item):
        gid = item.data(Qt.UserRole)
        QMessageBox.information(self, self.groups[gid]["name"],
                                 f"Members: {', '.join(self.groups[gid]['members'])}\n"
                                 f"Invite link: flashchat.store/invite/{self.groups[gid]['invite_token']}\n\n"
                                 f"(group messaging UI is basic in this build -- DM chat is the fully wired path)")

    # ---------- chat ----------

    def _select_peer(self, peer_id):
        self.active_peer = peer_id
        self._update_peer_header()
        self.composer_input.setEnabled(True)
        self._rebuild_message_view()

    def _update_peer_header(self):
        info = self.contacts.get(self.active_peer, {})
        status = "Online" if info.get("online") else "Offline"
        self.peer_name_lbl.setText(self.active_peer)
        self.peer_sub_lbl.setText(status)

    def _clear_messages_layout(self):
        while self.messages_layout.count() > 1:
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _rebuild_message_view(self):
        self._clear_messages_layout()
        for sender, text, mine in self.chat_history.get(self.active_peer, []):
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, MessageBubble(sender, text, mine))

    def _add_system_note(self, peer_id, text):
        self.chat_history.setdefault(peer_id, [])
        if peer_id == self.active_peer:
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, SystemNote(text))

    def _send_message(self):
        text = self.composer_input.text().strip()
        if not text or not self.active_peer:
            return
        self.composer_input.clear()
        asyncio.ensure_future(self._send_async(self.active_peer, text))

    def _send_quick_reaction(self, emoji):
        if self.active_peer:
            asyncio.ensure_future(self._send_async(self.active_peer, emoji))

    async def _send_async(self, peer_id, text):
        try:
            await self.session.send_to_peer(peer_id, text)
        except Exception as e:
            QMessageBox.warning(self, "Send failed", str(e))

    def _handle_incoming_message(self, peer_id, text, mine):
        self.chat_history.setdefault(peer_id, []).append((peer_id if not mine else self.session.user_id, text, mine))
        if peer_id == self.active_peer:
            self.messages_layout.insertWidget(self.messages_layout.count() - 1, MessageBubble(peer_id, text, mine))
            self.messages_scroll.verticalScrollBar().setValue(self.messages_scroll.verticalScrollBar().maximum())
        if peer_id not in self.contacts:
            self.contacts[peer_id] = {"bio": "", "avatar_id": "default", "online": True}
            self._refresh_friends_list()

    # ---------- settings ----------

    def _open_settings(self):
        info = self.contacts.get(self.session.user_id, {})
        dlg = SettingsDialog(self.session, self.my_bio_lbl.text(), "default", self)
        dlg.exec()

    # ---------- calling ----------

    def _open_call(self, video: bool):
        if not self.active_peer:
            QMessageBox.information(self, "No contact selected", "Select a friend to call first.")
            return
        dlg = CallDialog(self.session, self.active_peer, incoming_offer=None, parent=self)
        if not hasattr(self, "_open_call_dialogs"):
            self._open_call_dialogs = []
        self._open_call_dialogs.append(dlg)
        dlg.finished.connect(lambda _: self._open_call_dialogs.remove(dlg) if dlg in self._open_call_dialogs else None)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _handle_rtc_signal(self, kind, from_user, payload):
        if kind == "offer":
            dlg = CallDialog(self.session, from_user, incoming_offer=payload, parent=self)
            # IMPORTANT: this fires from inside the async websocket message
            # listener. Calling dlg.exec() here would open a nested Qt
            # event loop from inside a running coroutine, which conflicts
            # with qasync and can silently break the message listener
            # (same root cause as the earlier login-dialog crash). Using
            # .show() instead keeps it non-blocking and safe.
            if not hasattr(self, "_open_call_dialogs"):
                self._open_call_dialogs = []
            self._open_call_dialogs.append(dlg)
            dlg.finished.connect(lambda _: self._open_call_dialogs.remove(dlg) if dlg in self._open_call_dialogs else None)
            dlg.show()
            dlg.raise_()
            dlg.activateWindow()
            return

        # THE ACTUAL BUG: this used to be a no-op comment. Without this,
        # the caller's side never learns the callee's network info at
        # all -- the connection is permanently stuck at "connecting"
        # regardless of firewall/network setup, because it never even
        # receives the other side's answer.
        target_dlg = None
        for dlg in getattr(self, "_open_call_dialogs", []):
            if dlg.call_manager.peer_id == from_user:
                target_dlg = dlg
                break

        if target_dlg is None:
            print(f"[calling] received '{kind}' from {from_user} but no matching open call dialog found -- dropping")
            return

        if kind == "answer":
            asyncio.ensure_future(target_dlg.call_manager.handle_answer(payload))
        elif kind == "ice":
            asyncio.ensure_future(target_dlg.call_manager.handle_ice(payload))


async def do_connect(user_id: str, passphrase: str, is_anonymous: bool, session_holder: dict):
    session = GuiSession(user_id, is_anonymous=is_anonymous)
    public_reg = None
    is_new_identity = False

    if not is_anonymous and session.vault.exists():
        try:
            session.unlock_existing_identity(passphrase)
        except VaultError as e:
            QMessageBox.critical(None, "Unlock failed", str(e))
            return
        session.device_id = session.load_device_id()
    else:
        public_reg = session.setup_new_identity(passphrase if not is_anonymous else None)
        is_new_identity = True

    await session.connect()

    if is_new_identity or not session.device_id:
        if public_reg is None:
            public_reg = session.rebuild_public_registration()
        await session.register(public_reg)

    session_holder["session"] = session


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Windows native style ignores most QSS -- Fusion respects it
    app.setStyleSheet(STYLESHEET)

    # IMPORTANT: run the login dialog under plain Qt, BEFORE qasync's
    # event loop is created. Calling a blocking QDialog.exec() from
    # *inside* a coroutine running on qasync's loop causes a nested
    # event loop conflict (surfaces as "Event loop stopped before
    # Future completed" -- misleading, but that's the real cause).
    login = LoginDialog()
    if login.exec() != QDialog.Accepted:
        return

    user_id = login.result_user_id
    passphrase = login.result_passphrase
    is_anonymous = login.result_anonymous

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    session_holder = {}
    with loop:
        try:
            loop.run_until_complete(do_connect(user_id, passphrase, is_anonymous, session_holder))
        except Exception as e:
            import traceback
            print("REAL ERROR during connect/register:")
            traceback.print_exc()
            QMessageBox.critical(None, "Connection failed", f"{type(e).__name__}: {e}")
            return

        session = session_holder.get("session")
        if not session:
            print("No session created -- check the error above (or Unlock failed dialog).")
            return

        window = MainWindow(session)
        window.show()
        loop.run_forever()


if __name__ == "__main__":
    main()
