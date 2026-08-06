"""
client-mobile/main.py

FlashChat -- mobile client (Kivy). Text messaging only for this pass
(no calling/groups yet -- deliberately scoped small to keep the first
mobile build simple to debug). Reuses the exact same E2EE session
engine (session.py) as the desktop client -- same X3DH + Double
Ratchet crypto, already tested extensively there.

ARCHITECTURE NOTE: Kivy has its own event loop (not asyncio-based).
websockets/asyncio code runs on a background thread with its own
asyncio loop. Any UI update from that thread MUST go through
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
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.uix.checkbox import CheckBox
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle

from session import GuiSession
from crypto.vault import VaultError

# --- FlashChat red/dark theme colors (0-1 float RGBA, Kivy convention) ---
COL_BG = (0.118, 0.122, 0.137, 1)       # ~#1e1f22
COL_PANEL = (0.169, 0.176, 0.192, 1)    # ~#2b2d31
COL_INPUT = (0.220, 0.227, 0.251, 1)    # ~#383a40
COL_ACCENT = (0.902, 0.224, 0.290, 1)   # ~#e6394a
COL_TEXT = (0.949, 0.953, 0.961, 1)     # ~#f2f3f5
COL_MUTED = (0.588, 0.596, 0.616, 1)    # ~#96989d

Window.clearcolor = COL_BG


class AsyncBridge:
    """Runs an asyncio event loop on a background thread and lets Kivy
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
        is_anonymous = self.anon_check.active
        if not user_id:
            self.status_label.text = "Enter a user ID first."
            return
        self.status_label.text = "Connecting..."
        self.app.begin_login(user_id, passphrase, is_anonymous, self._on_result)

    def _on_result(self, ok, error_message=None):
        def update(_dt):
            if ok:
                self.app.show_chat_screen()
            else:
                self.status_label.text = f"Failed: {error_message}"
        Clock.schedule_once(update)


class ChatScreen(Screen):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        root = BoxLayout(orientation="vertical", padding=10, spacing=8)
        flat_bg(root, COL_BG)

        header = Label(text=f"Signed in as: {app.session.user_id}", color=COL_MUTED,
                        size_hint=(1, 0.06))
        root.add_widget(header)

        peer_row = BoxLayout(size_hint=(1, 0.08), spacing=8)
        self.peer_input = TextInput(hint_text="Message to (user ID)", multiline=False,
                                     background_color=COL_INPUT, foreground_color=COL_TEXT)
        peer_row.add_widget(self.peer_input)
        root.add_widget(peer_row)

        self.scroll = ScrollView(size_hint=(1, 0.72))
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

        self.add_widget(root)

    def _send(self, *_):
        peer_id = self.peer_input.text.strip()
        text = self.msg_input.text.strip()
        if not peer_id or not text:
            return
        self.msg_input.text = ""
        self._append_log(f"[You -> {peer_id}]: {text}")
        self.app.send_message(peer_id, text)

    def _append_log(self, text):
        self.log_box.add_widget(Label(text=text, color=COL_TEXT, size_hint_y=None,
                                       height=28, halign="left", text_size=(Window.width - 40, None)))
        self.scroll.scroll_to(self.log_box.children[0])

    def on_incoming_message(self, peer_id, text, mine):
        if mine:
            return  # already shown locally when sent
        def update(_dt):
            self._append_log(f"[{peer_id}]: {text}")
        Clock.schedule_once(update)


class FlashChatApp(App):
    def build(self):
        self.bridge = AsyncBridge()
        self.session: GuiSession | None = None
        self.sm = ScreenManager()
        self.login_screen = LoginScreen(self, name="login")
        self.sm.add_widget(self.login_screen)
        return self.sm

    def begin_login(self, user_id, passphrase, is_anonymous, callback):
        async def do_login():
            try:
                session = GuiSession(user_id, is_anonymous=is_anonymous)
                public_reg = None
                is_new_identity = False

                if not is_anonymous and session.vault.exists():
                    session.unlock_existing_identity(passphrase)
                    session.device_id = session.load_device_id()
                else:
                    public_reg = session.setup_new_identity(passphrase if not is_anonymous else None)
                    is_new_identity = True

                await session.connect()

                if is_new_identity or not session.device_id:
                    if public_reg is None:
                        public_reg = session.rebuild_public_registration()
                    await session.register(public_reg)

                self.session = session
                session.on_message = self._on_message
                callback(True)
            except VaultError as e:
                callback(False, str(e))
            except Exception as e:
                callback(False, f"{type(e).__name__}: {e}")

        self.bridge.run_coro(do_login())

    def _on_message(self, peer_id, text, mine):
        if hasattr(self, "chat_screen"):
            self.chat_screen.on_incoming_message(peer_id, text, mine)

    def show_chat_screen(self):
        self.chat_screen = ChatScreen(self, name="chat")
        self.sm.add_widget(self.chat_screen)
        self.sm.current = "chat"

    def send_message(self, peer_id, text):
        async def do_send():
            try:
                await self.session.send_to_peer(peer_id, text)
            except Exception as e:
                print(f"[send error] {e}")
        self.bridge.run_coro(do_send())


if __name__ == "__main__":
    FlashChatApp().run()
