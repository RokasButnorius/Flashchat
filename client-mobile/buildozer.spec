[app]
title = FlashChat
package.name = flashchat
package.domain = store.flashchat

source.dir = .
source.include_exts = py,png,jpg,kv,atlas
icon.filename = %(source.dir)s/flashchaticon.png

version = 0.1

# Kept deliberately minimal for this first build: no aiortc/opencv
# (calling isn't ported yet), just what text messaging needs.
requirements = python3,kivy,pynacl,websockets,cffi,pycparser,certifi

orientation = portrait
fullscreen = 0

# Network access is required for the websocket relay connection
android.permissions = INTERNET

android.api = 33
android.minapi = 24
android.ndk = 25b
android.archs = arm64-v8a, armeabi-v7a

[buildozer]
log_level = 2
warn_on_root = 1
