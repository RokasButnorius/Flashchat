"""client-desktop/theme.py -- FlashChat theme: flat/matte dark UI, red accents, Discord-real greys."""

# Matched closer to Discord's actual palette (warm neutral greys, not blue-tinted)
BG_DEEPEST = "#1e1f22"
BG_SIDEBAR = "#2b2d31"
BG_PANEL = "#313338"
BG_INPUT = "#383a40"
BG_HOVER = "#3f4147"
ACCENT = "#e6394a"
ACCENT_BRIGHT = "#ff4d5e"
ACCENT_DIM = "#8a2a33"
ONLINE = "#3ba55d"
TEXT_MAIN = "#f2f3f5"
TEXT_MUTED = "#96989d"
TEXT_DIM = "#6d6f78"
BORDER = "#1a1b1e"

STYLESHEET = f"""
QWidget {{
    background-color: {BG_DEEPEST};
    color: {TEXT_MAIN};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
    outline: none;
}}
QMainWindow {{ background-color: {BG_DEEPEST}; }}

#Sidebar {{ background-color: {BG_SIDEBAR}; border-right: 1px solid {BORDER}; }}
#ChatPanel {{ background-color: {BG_PANEL}; }}
#ChatHeader {{ background-color: {BG_PANEL}; border-bottom: 1px solid {BORDER}; }}

/* --- Flat, matte inputs -- explicit borders everywhere to override
   Fusion's default bevel/gradient shading on native widgets --- */
QLineEdit, QTextEdit {{
    background-color: {BG_INPUT};
    border: 1px solid {BG_INPUT};
    border-radius: 4px;
    padding: 8px 10px;
    color: {TEXT_MAIN};
}}
QLineEdit:focus, QTextEdit:focus {{ border: 1px solid {ACCENT}; }}

QPushButton {{
    background-color: {BG_INPUT};
    border: 1px solid {BG_INPUT};
    border-radius: 4px;
    padding: 8px 14px;
    color: {TEXT_MAIN};
}}
QPushButton:hover {{ background-color: {BG_HOVER}; border: 1px solid {BG_HOVER}; }}
QPushButton:pressed {{ background-color: {ACCENT_DIM}; border: 1px solid {ACCENT_DIM}; }}
QPushButton:disabled {{ background-color: {BG_INPUT}; color: {TEXT_DIM}; }}

QPushButton#AccentButton {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
    font-weight: 600;
}}
QPushButton#AccentButton:hover {{ background-color: {ACCENT_BRIGHT}; border: 1px solid {ACCENT_BRIGHT}; }}

QPushButton#IconButton {{
    background-color: {BG_INPUT};
    border: 1px solid {BG_INPUT};
    border-radius: 18px;
    min-width: 36px; max-width: 36px;
    min-height: 36px; max-height: 36px;
    font-size: 15px;
}}
QPushButton#IconButton:hover {{ background-color: {BG_HOVER}; border: 1px solid {BG_HOVER}; }}
QPushButton#IconButton:checked {{ background-color: {ACCENT}; border: 1px solid {ACCENT}; }}

QListWidget {{
    background-color: transparent;
    border: none;
    outline: none;
}}
QListWidget::item {{
    padding: 8px;
    border-radius: 4px;
    margin: 1px 4px;
    border: none;
}}
QListWidget::item:hover {{ background-color: {BG_HOVER}; }}
QListWidget::item:selected {{ background-color: {ACCENT}; color: white; }}

QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: #4a4d54;
    border-radius: 4px;
    min-height: 24px;
    border: none;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; border: none; background: none; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}

QLabel#SectionLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    background: transparent;
}}
QLabel#PeerName {{ font-size: 15px; font-weight: 700; background: transparent; }}
QLabel#PeerSub {{ color: {TEXT_MUTED}; font-size: 11px; background: transparent; }}
QLabel {{ background: transparent; }}

QDialog {{ background-color: {BG_PANEL}; }}

/* --- ComboBox: explicitly flatten every sub-part, this is usually
   where Fusion's native shading leaks through even with QSS applied --- */
QComboBox {{
    background-color: {BG_INPUT};
    border: 1px solid {BG_INPUT};
    border-radius: 4px;
    padding: 6px 10px;
}}
QComboBox:hover {{ background-color: {BG_HOVER}; border: 1px solid {BG_HOVER}; }}
QComboBox::drop-down {{
    border: none;
    background: transparent;
    width: 24px;
}}
QComboBox::down-arrow {{
    width: 10px; height: 10px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    selection-background-color: {ACCENT};
    outline: none;
}}

QCheckBox {{ background: transparent; spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border-radius: 3px;
    background-color: {BG_INPUT};
    border: 1px solid #4a4d54;
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border: 1px solid {ACCENT};
}}

QMessageBox {{ background-color: {BG_PANEL}; }}
QInputDialog {{ background-color: {BG_PANEL}; }}
"""


def avatar_color(user_id: str) -> str:
    """Deterministic accent-ish color per user, for avatar circles."""
    palette = [ACCENT, "#5865f2", "#3ba55d", "#f0b232", "#9b59b6", "#1abc9c", "#e67e22"]
    return palette[sum(ord(c) for c in user_id) % len(palette)]


AVATAR_EMOJI = {
    "default": "🙂", "red_fox": "🦊", "blue_wolf": "🐺", "green_frog": "🐸",
    "purple_owl": "🦉", "orange_cat": "🐱", "teal_bear": "🐻", "pink_bunny": "🐰",
    "yellow_duck": "🦆",
}
