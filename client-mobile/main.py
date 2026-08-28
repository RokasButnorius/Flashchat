"""
client-mobile/main.py

FlashChat -- mobile client (Kivy). Text messaging only for this pass
(no calling/groups yet -- deliberately scoped small to keep the first
mobile build simple to debug). Reuses the exact same E2EE session
engine (session.py) as the desktop client -- same X3DH + Double
Ratchet crypto, already tested extensively there.

ARCHITECTURE NOTE: Kivy has its own event loop (not asyncio-based).
websockets/async code runs on a background thread with its own
async loop. Any UI update from that thread MUST go through
Clock.schedule_once() to safely marshal back onto Kivy's main thread --
touching Kivy widgets directly from the background thread will crash
or corrupt the UI.

Build with Buildozer (see buildozer.spec in this folder):
    buildozer -v android debug
"""

import asyncio
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.animation import Animation
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.uix.checkbox import CheckBox
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle

from session import GuiSession, DATA_DIR
from crypto import vault
from crypto.vault import VaultError

# -- FlashChat red/dark theme colors (0-1 float RGBA, Kivy convention) --
COL_BG = (0.118, 0.122, 0.137, 1)       # ~#1e1f22
COL_PANEL = (0.169, 0.176, 0.192, 1)    # ~#2b2d31
COL_INPUT = (0.220, 0.227, 0.251, 1)    # ~#383a40
COL_ACCENT = (0.902, 0.224, 0.290, 1)   # ~#e6394a
COL_TEXT = (0.949, 0.953, 0.961, 1)     # ~#f2f3f5
COL_MUTED = (0.588, 0.596, 0.616, 1)    # ~#96989d

Window.clearcolor = COL_BG


class AsyncBridge:
    """Runs an async event loop on a background thread and lets Kivy
    code schedule coroutines onto it safely."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_coro(self, coro):
        """Schedule a coroutine on the background loop from Kivy's main thread."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)


def flat_bg(widget, color):
    with widget.canvas.before:
        Color(*color)
        rect = Rectangle(pos=widget.pos, size=widget.size)
    def update(*_):
        rect.pos = widget.pos
        rect.size = widget.size
    widget.bind(pos=update, size=update)


class LoginScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        root = BoxLayout(orientation="vertical", padding=24, spacing=14)
        flat_bg(root, COL_BG)

        title = Label(text="[b]FlashChat[/b]", markup=True, font_size=28,
                      color=COL_TEXT, size_hint=(1, 0.15))
        root.add_widget(title)

        self.user_input = TextInput(hint_text="User ID", multiline=False,
                                    size_hint=(1, 0.1), background_color=COL_INPUT,
                                    foreground_color=COL_TEXT, padding=[12, 12, 12, 12])
        root.add_widget(self.user_input)

        self.pass_input = TextInput(hint_text="Vault passphrase", multiline=False,
                                    password=True, size_hint=(1, 0.1),
                                    background_color=COL_INPUT, foreground_color=COL_TEXT,
                                    padding=[12, 12, 12, 12])
        root.add_widget(self.pass_input)

        anon_row = BoxLayout(size_hint=(1, 0.08), spacing=8)
        self.anon_check = CheckBox()
        anon_row.add_widget(self.anon_check)
        anon_row.add_widget(Label(text="Anonymous mode", color=COL_MUTED))
        root.add_widget(anon_row)

        remember_row = BoxLayout(size_hint=(1, 0.08), spacing=8)
        self.remember_check = CheckBox()
        remember_row.add_widget(self.remember_check)
        remember_row.add_widget(Label(text="Stay signed in", color=COL_MUTED))
        root.add_widget(remember_row)

        self.status_label = Label(text="", color=COL_MUTED, size_hint=(1, 0.1))
        root.add_widget(self.status_label)

        connect_btn = Button(text="Connect", size_hint=(1, 0.12),
                             background_color=COL_ACCENT, color=(1, 1, 1, 1))
        connect_btn.bind(on_release=self._connect)
        root.add_widget(connect_btn)

        root.add_widget(BoxLayout(size_hint=(1, 0.35)))  # spacer
        self.add_widget(root)

    def _connect(self, *_):
        user_id = self.user_input.text.strip()
        passphrase = self.pass_input.text
        is_anon = self.anon_check.active
        remember_me = self.remember_check.active and not is_anon  # no keystore benefit for anon mode
        if not user_id:
            self.status_label.text = "Enter a user ID first."
            return
        self.status_label.text = "Connecting..."
        self.app.begin_login(user_id, passphrase, is_anon, self._on_result, remember_me=remember_me)

    def _on_result(self, ok, error_message=None):
        def update(_dt):
            if ok:
                self.app.show_chat_screen()
            else:
                self.status_label.text = f"Failed: {error_message}"
        Clock.schedule_once(update)


class FriendsPanel(FloatLayout):
    """Slide-in sidebar: search box + search results + friends list.
    Mirrors desktop's sidebar (search_input / search_results_list /
    friends_list) so the two clients behave the same way."""

    PANEL_WIDTH_FRAC = 0.8  # fraction of screen width the panel takes up when open

    def __init__(self, app, on_friend_selected, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.on_friend_selected = on_friend_selected
        self.contacts = {}  # user_id -> {bio, avatar_id, online}
        self._is_open = False

        panel_width = Window.width * self.PANEL_WIDTH_FRAC

        # dim/click-catcher behind the panel, closes it when tapped.
        # NOT added to the widget tree here on purpose -- a disabled=True
        # widget still ABSORBS any touch that lands on it (Kivy blocks
        # click-through to disabled widgets rather than passing it on),
        # so a full-screen disabled scrim was still swallowing every tap
        # even while closed. Instead we add/remove it from the tree
        # entirely in open()/close() below.
        self.scrim = Button(background_color=(0, 0, 0, 0), background_normal="",
                            size_hint=(1, 1), opacity=0)
        self.scrim.bind(on_release=lambda *_: self.close())

        # NOTE: deliberately NOT using pos_hint={"x": ...} here. FloatLayout
        # re-applies pos_hint on every layout pass (e.g. triggered by
        # add_widget/remove_widget of the scrim in open()/close() below),
        # which snaps the panel straight back to the pos_hint x and fights
        # the Animation(x=...) below -- this was why the panel appeared to
        # not open at all. Setting x manually (once) avoids that fight;
        # only "top" stays in pos_hint since nothing animates y.
        self.panel = BoxLayout(orientation="vertical", padding=12, spacing=8,
                               size_hint=(None, 1), width=panel_width,
                               pos_hint={"top": 1})
        self.panel.x = -panel_width
        flat_bg(self.panel, COL_PANEL)

        header = Label(text="[b]FlashChat[/b]", markup=True, font_size=18,
                       color=COL_TEXT, size_hint=(1, 0.08))
        self.panel.add_widget(header)

        search_row = BoxLayout(size_hint=(1, 0.08), spacing=6)
        self.search_input = TextInput(hint_text="Search people...", multiline=False,
                                      background_color=COL_INPUT,
                                      foreground_color=COL_TEXT, padding=[10, 10, 10, 10])
        self.search_input.bind(text=self._on_search_text_changed)
        search_row.add_widget(self.search_input)
        add_btn = Button(text="Add", size_hint=(0.28, 1),
                         background_color=COL_ACCENT, color=(1, 1, 1, 1))
        add_btn.bind(on_release=self._add_by_typed_name)
        search_row.add_widget(add_btn)
        self.panel.add_widget(search_row)

        self.results_scroll = ScrollView(size_hint=(1, 0.25))
        self.results_box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=2)
        self.results_box.bind(minimum_height=self.results_box.setter("height"))
        self.results_scroll.add_widget(self.results_box)
        self.panel.add_widget(self.results_scroll)

        self.panel.add_widget(Label(text="FRIENDS", color=COL_MUTED, font_size=11,
                                    size_hint=(1, 0.05), halign="left"))

        self.friends_scroll = ScrollView(size_hint=(1, 0.54))
        self.friends_box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=2)
        self.friends_box.bind(minimum_height=self.friends_box.setter("height"))
        self.friends_scroll.add_widget(self.friends_box)
        self.panel.add_widget(self.friends_scroll)

        self.status_label = Label(text="", color=COL_MUTED, font_size=12, size_hint=(1, 0.05))
        self.panel.add_widget(self.status_label)

        self.add_widget(self.panel)

    # -- open / close --

    def toggle(self):
        self.close() if self._is_open else self.open()

    def open(self):
        self._is_open = True
        if self.scrim.parent is None:
            self.add_widget(self.scrim, index=len(self.children))
        self.scrim.opacity = 1
        Animation(x=0, d=0.18, t="out_quad").start(self.panel)

    def close(self):
        self._is_open = False
        self.scrim.opacity = 0
        if self.scrim.parent is not None:
            self.remove_widget(self.scrim)
        Animation(x=-self.panel.width, d=0.18, t="in_quad").start(self.panel)

    # -- search --

    def _on_search_text_changed(self, _instance, text):
        text = text.strip()
        if len(text) >= 2:
            self.app.bridge.run_coro(self.app.session.search_users(text))
        else:
            self.results_box.clear_widgets()

    def show_search_results(self, results):
        self.results_box.clear_widgets()
        for r in results:
            btn = self._make_row(f"{r['id']}", on_press=lambda _i, uid=r["id"]: self._add_contact(uid))
            self.results_box.add_widget(btn)

    def _add_contact(self, contact_id):
        self.app.bridge.run_coro(self.app.session.add_contact(contact_id))
        self.search_input.text = ""
        self.results_box.clear_widgets()

    def _add_by_typed_name(self, *_):
        """Adds exactly what's typed in the search box, without requiring
        the user to first tap a row in the search-results dropdown."""
        name = self.search_input.text.strip()
        if name:
            self._add_contact(name)

    # -- friends list --

    def update_contacts(self, contacts: dict):
        self.contacts = contacts
        self._refresh_friends_list()

    def _refresh_friends_list(self):
        self.friends_box.clear_widgets()
        for user_id, info in self.contacts.items():
            dot = "\U0001F7E2" if info.get("online") else "\u26AA"  # green/white circle
            btn = self._make_row(f"{dot} {user_id}",
                                 on_press=lambda _i, uid=user_id: self._select_friend(uid))
            self.friends_box.add_widget(btn)

    def _select_friend(self, user_id):
        self.on_friend_selected(user_id)
        self.close()

    def _make_row(self, text, on_press):
        btn = Button(text=text, size_hint_y=None, height=44,
                     background_color=COL_INPUT, color=COL_TEXT,
                     halign="left", valign="middle")
        btn.bind(size=lambda i, *_: setattr(i, "text_size", (i.width - 20, None)))
        btn.bind(on_release=on_press)
        return btn


class ChatScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.active_peer = None
        self.chat_history = {}  # peer_id -> [(sender_label, text, mine)]

        outer = FloatLayout()
        root = BoxLayout(orientation="vertical", padding=10, spacing=8)
        flat_bg(root, COL_BG)

        header = BoxLayout(size_hint=(1, 0.08), spacing=8)
        menu_btn = Button(text="\u2630", size_hint=(0.15, 1),
                          background_color=COL_INPUT, color=COL_TEXT)
        menu_btn.bind(on_release=lambda *_: self.friends_panel.toggle())
        header.add_widget(menu_btn)
        self.peer_header_lbl = Label(text="Select a friend", color=COL_TEXT, bold=True)
        header.add_widget(self.peer_header_lbl)
        logout_btn = Button(text="Sign out", size_hint=(0.28, 1),
                            background_color=COL_INPUT, color=COL_TEXT)
        logout_btn.bind(on_release=lambda *_: self.app.logout())
        header.add_widget(logout_btn)
        root.add_widget(header)

        self.scroll = ScrollView(size_hint=(1, 0.76))
        self.log_box = BoxLayout(orientation="vertical", size_hint_y=None, spacing=4, padding=4)
        self.log_box.bind(minimum_height=self.log_box.setter("height"))
        self.scroll.add_widget(self.log_box)
        root.add_widget(self.scroll)

        composer = BoxLayout(size_hint=(1, 0.1), spacing=8)
        self.msg_input = TextInput(hint_text="Type a message...", multiline=False,
                                   background_color=COL_INPUT, foreground_color=COL_TEXT)
        self.msg_input.bind(on_text_validate=self._send)
        composer.add_widget(self.msg_input)
        send_btn = Button(text="Send", size_hint=(0.25, 1), background_color=COL_ACCENT)
        send_btn.bind(on_release=self._send)
        composer.add_widget(send_btn)
        root.add_widget(composer)

        outer.add_widget(root)

        self.friends_panel = FriendsPanel(app, on_friend_selected=self._select_peer)
        outer.add_widget(self.friends_panel)

        self.add_widget(outer)

    # -- peer selection --

    def _select_peer(self, peer_id):
        self.active_peer = peer_id
        self.peer_header_lbl.text = peer_id
        self.msg_input.disabled = False
        self._rebuild_log()

    def _rebuild_log(self):
        self.log_box.clear_widgets()
        for sender, text, mine in self.chat_history.get(self.active_peer, []):
            self._append_widget(f"[You]: {text}" if mine else f"[{sender}]: {text}")

    def _append_widget(self, text):
        self.log_box.add_widget(Label(text=text, color=COL_TEXT, size_hint_y=None,
                                      height=28, halign="left", text_size=(Window.width - 40, None)))
        if self.log_box.children:
            self.scroll.scroll_to(self.log_box.children[0])

    # -- sending --

    def _send(self, *_):
        text = self.msg_input.text.strip()
        if not text or not self.active_peer:
            return
        self.msg_input.text = ""
        self.chat_history.setdefault(self.active_peer, []).append((self.app.session.user_id, text, True))
        if self.active_peer == self.active_peer:  # always true; kept for symmetry with desktop
            self._append_widget(f"[You]: {text}")
        self.app.send_message(self.active_peer, text)

    # -- incoming --

    def on_incoming_message(self, peer_id, text, mine):
        if mine:
            return  # already shown locally when sent
        self.chat_history.setdefault(peer_id, []).append((peer_id, text, False))
        if peer_id not in self.friends_panel.contacts:
            self.friends_panel.contacts[peer_id] = {"bio": "", "avatar_id": "default", "online": True}
            self.friends_panel._refresh_friends_list()
        if peer_id == self.active_peer:
            self._append_widget(f"[{peer_id}]: {text}")

    def on_contacts_list(self, contacts):
        merged = dict(self.friends_panel.contacts)
        for c in contacts:
            merged[c["id"]] = {"bio": c.get("bio", ""), "avatar_id": c.get("avatar_id", "default"),
                               "online": c.get("online", False)}
        self.friends_panel.update_contacts(merged)

    def on_contact_added(self, contact, online):
        if contact is None:
            self.friends_panel.status_label.text = "No user with that name."
            return
        merged = dict(self.friends_panel.contacts)
        merged[contact["id"]] = {"bio": contact.get("bio", ""), "avatar_id": contact.get("avatar_id", "default"),
                                 "online": online}
        self.friends_panel.update_contacts(merged)
        self.friends_panel.status_label.text = ""

    def on_error(self, reason):
        if reason == "no_such_user":
            self.friends_panel.status_label.text = "No user with that name."

    def on_search_results(self, results):
        self.friends_panel.show_search_results(results)

    def on_presence(self, user_id, online):
        if user_id in self.friends_panel.contacts:
            self.friends_panel.contacts[user_id]["online"] = online
            self.friends_panel._refresh_friends_list()


class FlashChatApp(App):
    LAST_USER_PATH = DATA_DIR / "last_user.txt"

    def build(self):
        self.bridge = AsyncBridge()
        self.session: GuiSession | None = None
        self.sm = ScreenManager()
        self.login_screen = LoginScreen(self, name="login")
        self.sm.add_widget(self.login_screen)
        self._try_saved_login()
        return self.sm

    def _hook_session_callbacks(self, session):
        session.on_message = self._on_message
        session.on_contacts_list = self._on_contacts_list
        session.on_contact_added = self._on_contact_added
        session.on_search_results = self._on_search_results
        session.on_presence = self._on_presence
        session.on_error = self._on_error

    def _try_saved_login(self):
        """Runs once at startup. Silent -- on any failure (no saved user,
        keystore unwrap fails, app reinstalled, etc.) it just leaves the
        normal passphrase login screen showing, no error shown to the user."""
        if not self.LAST_USER_PATH.exists():
            return
        user_id = self.LAST_USER_PATH.read_text().strip()
        if not user_id:
            return

        async def do_auto():
            try:
                session = GuiSession(user_id, is_anonymous=False)
                if not session.has_remembered_login() or not session.try_auto_login():
                    return
                session.device_id = session.load_device_id()
                await session.connect()
                self.session = session
                self._hook_session_callbacks(session)
                Clock.schedule_once(lambda _dt: self.show_chat_screen())
            except Exception as e:
                print(f"[auto-login] skipped, showing login screen: {e}")

        self.bridge.run_coro(do_auto())

    def begin_login(self, user_id, passphrase, is_anonymous, callback, remember_me=False):
        async def do_login():
            try:
                session = GuiSession(user_id, is_anonymous=is_anonymous)
                public_reg = None
                is_new_identity = False

                if not is_anonymous and session.vault.exists():
                    session.unlock_existing_identity(passphrase, remember_me=remember_me)
                    session.device_id = session.load_device_id()
                else:
                    public_reg = session.setup_new_identity(passphrase if not is_anonymous else None)
                    is_new_identity = True
                    if remember_me and not is_anonymous:
                        platform = vault.current_platform()
                        session.vault.save_remember_me(passphrase, platform)
                        session.session_store.save_remember_me(passphrase, platform)

                await session.connect()

                if is_new_identity or not session.device_id:
                    if public_reg is None:
                        public_reg = session.rebuild_public_registration()
                    await session.register(public_reg)

                if remember_me and not is_anonymous:
                    self.LAST_USER_PATH.parent.mkdir(parents=True, exist_ok=True)
                    self.LAST_USER_PATH.write_text(user_id)

                self.session = session
                self._hook_session_callbacks(session)
                callback(True)
            except VaultError as e:
                callback(False, str(e))
            except Exception as e:
                callback(False, f"{type(e).__name__}: {e}")

        self.bridge.run_coro(do_login())

    def logout(self):
        if self.session:
            self.session.logout()
        if self.LAST_USER_PATH.exists():
            self.LAST_USER_PATH.unlink()
        self.session = None
        if hasattr(self, "chat_screen"):
            self.sm.remove_widget(self.chat_screen)
            del self.chat_screen
        self.login_screen.status_label.text = "Signed out."
        self.sm.current = "login"

    def _on_message(self, peer_id, text, mine):
        def update(_dt):
            if hasattr(self, "chat_screen"):
                self.chat_screen.on_incoming_message(peer_id, text, mine)
        Clock.schedule_once(update)

    def _on_contacts_list(self, contacts):
        def update(_dt):
            if hasattr(self, "chat_screen"):
                self.chat_screen.on_contacts_list(contacts)
        Clock.schedule_once(update)

    def _on_contact_added(self, contact, online):
        def update(_dt):
            if hasattr(self, "chat_screen"):
                self.chat_screen.on_contact_added(contact, online)
        Clock.schedule_once(update)

    def _on_search_results(self, results):
        def update(_dt):
            if hasattr(self, "chat_screen"):
                self.chat_screen.on_search_results(results)
        Clock.schedule_once(update)

    def _on_presence(self, user_id, online):
        def update(_dt):
            if hasattr(self, "chat_screen"):
                self.chat_screen.on_presence(user_id, online)
        Clock.schedule_once(update)

    def _on_error(self, reason):
        def update(_dt):
            if hasattr(self, "chat_screen"):
                self.chat_screen.on_error(reason)
        Clock.schedule_once(update)

    def show_chat_screen(self):
        self.chat_screen = ChatScreen(self, name="chat")
        self.sm.add_widget(self.chat_screen)
        self.sm.current = "chat"
        self.bridge.run_coro(self.session.list_contacts())

    def send_message(self, peer_id, text):
        async def do_send():
            try:
                await self.session.send_to_peer(peer_id, text)
            except Exception as e:
                print(f"[send error] {e}")   # <-- FIX: missing opening quote corrected
        self.bridge.run_coro(do_send())


if __name__ == "__main__":
    FlashChatApp().run()