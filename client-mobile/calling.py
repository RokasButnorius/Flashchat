"""
client-mobile/calling.py

Voice calling for the mobile client. Deliberately NOT built on aiortc like
the desktop client -- aiortc's C dependencies (PyAV/FFmpeg, pylibsrtp,
cryptography) have no python-for-android recipe and will not cross-compile
for Android. Instead this drives Android's own native WebRTC stack
(Google's official prebuilt AAR, org.webrtc:google-webrtc) directly via
pyjnius JNI calls. Requires the AAR to be pulled in via
buildozer.spec's `android.gradle_dependencies = org.webrtc:google-webrtc:1.0.+`.

Audio-only by design (matches the desktop decision to drop video for now).

IMPORTANT / HONEST STATUS: this file is a first pass, written without a
device to test against. The signaling flow (start_call/handle_offer/
handle_answer/handle_ice/end_call) mirrors client-desktop/calling.py's
CallManager so main.py's wiring is a drop-in match, but the PythonJavaClass
interface implementations below (SdpObserver, PeerConnection.Observer) are
exactly the kind of thing that looks right on paper and then throws a JNI
method-signature error the first time it actually runs on-device. Expect to
need `adb logcat -d 2>&1 | grep -iE "python|webrtc|jnius"` and a real
edit-rebuild-retest loop to get this working -- budget time for that rather
than expecting it to work first try.
"""

import json
import re

from crypto import sodium_wrapper as sw


def _extract_dtls_fingerprint(sdp: str) -> str | None:
    """Same extraction as client-desktop/calling.py -- signing this value
    (not the whole SDP) with our Ed25519 identity key is what stops a
    malicious/compelled relay from swapping in its own cert and MITM'ing
    the call, matching the trust model X3DH already gives messages."""
    m = re.search(r"^a=fingerprint:(\S+ \S+)$", sdp, re.MULTILINE)
    return m.group(1) if m else None


class CallSecurityError(Exception):
    """A call's DTLS fingerprint signature was missing or didn't verify
    against the peer's known identity key. Treat as a possible MITM
    attempt -- never fall back to accepting the call unauthenticated."""
    pass

try:
    from jnius import autoclass, PythonJavaClass, java_method
    HAVE_JNIUS = True
except Exception:
    HAVE_JNIUS = False


# ---------- Java class handles (resolved lazily -- only valid on Android) ----------

def _classes():
    return {
        "PeerConnectionFactory": autoclass("org.webrtc.PeerConnectionFactory"),
        "PeerConnection": autoclass("org.webrtc.PeerConnection"),
        "IceServer": autoclass("org.webrtc.PeerConnection$IceServer"),
        "RtcConfig": autoclass("org.webrtc.PeerConnection$RTCConfiguration"),
        "MediaConstraints": autoclass("org.webrtc.MediaConstraints"),
        "SessionDescription": autoclass("org.webrtc.SessionDescription"),
        "SDPType": autoclass("org.webrtc.SessionDescription$Type"),
        "IceCandidate": autoclass("org.webrtc.IceCandidate"),
        "AudioSource": autoclass("org.webrtc.AudioSource"),
        "AudioTrack": autoclass("org.webrtc.AudioTrack"),
        "PythonActivity": autoclass("org.kivy.android.PythonActivity"),
        "Context": autoclass("android.content.Context"),
        "EglBase": autoclass("org.webrtc.EglBase"),
    }


class _SdpObserver(PythonJavaClass):
    """Implements org.webrtc.SdpObserver. WebRTC calls these back after
    createOffer/createAnswer/setLocalDescription/setRemoteDescription."""
    __javainterfaces__ = ["org/webrtc/SdpObserver"]

    def __init__(self, on_create_success=None, on_set_success=None, on_failure=None):
        super().__init__()
        self._on_create_success = on_create_success
        self._on_set_success = on_set_success
        self._on_failure = on_failure

    @java_method("(Lorg/webrtc/SessionDescription;)V")
    def onCreateSuccess(self, session_description):
        if self._on_create_success:
            self._on_create_success(session_description)

    @java_method("()V")
    def onSetSuccess(self):
        if self._on_set_success:
            self._on_set_success()

    @java_method("(Ljava/lang/String;)V")
    def onCreateFailure(self, error):
        print(f"[calling_mobile] SDP create failure: {error}")
        if self._on_failure:
            self._on_failure(str(error))

    @java_method("(Ljava/lang/String;)V")
    def onSetFailure(self, error):
        print(f"[calling_mobile] SDP set failure: {error}")
        if self._on_failure:
            self._on_failure(str(error))


class _PeerConnectionObserver(PythonJavaClass):
    """Implements org.webrtc.PeerConnection.Observer. Fires on ICE
    candidates, connection state changes, and remote tracks arriving."""
    __javainterfaces__ = ["org/webrtc/PeerConnection$Observer"]

    def __init__(self, on_ice_candidate=None, on_connection_change=None, on_track=None):
        super().__init__()
        self._on_ice_candidate = on_ice_candidate
        self._on_connection_change = on_connection_change
        self._on_track = on_track

    @java_method("(Lorg/webrtc/IceCandidate;)V")
    def onIceCandidate(self, candidate):
        if self._on_ice_candidate:
            self._on_ice_candidate(candidate)

    @java_method("(Lorg/webrtc/PeerConnection$IceConnectionState;)V")
    def onIceConnectionChange(self, state):
        state_str = state.toString() if state else "unknown"
        print(f"[calling_mobile] ICE connection state -> {state_str}")
        if self._on_connection_change:
            self._on_connection_change(state_str)

    @java_method("(Lorg/webrtc/MediaStream;)V")
    def onAddStream(self, stream):
        if self._on_track:
            self._on_track(stream)

    # Below: required by the interface but not used -- no-ops.
    @java_method("(Lorg/webrtc/DataChannel;)V")
    def onDataChannel(self, channel):
        pass

    @java_method("()V")
    def onRenegotiationNeeded(self):
        pass

    @java_method("(Lorg/webrtc/MediaStream;)V")
    def onRemoveStream(self, stream):
        pass

    @java_method("(Z)V")
    def onIceConnectionReceivingChange(self, receiving):
        pass

    @java_method("(Lorg/webrtc/PeerConnection$IceGatheringState;)V")
    def onIceGatheringChange(self, state):
        pass

    @java_method("([Lorg/webrtc/IceCandidate;)V")
    def onIceCandidatesRemoved(self, candidates):
        pass

    @java_method("(Lorg/webrtc/PeerConnection$SignalingState;)V")
    def onSignalingChange(self, state):
        pass


class CallManager:
    """
    Mirrors client-desktop/calling.py's CallManager surface so main.py's
    call-handling code needs minimal changes:
      start_call(peer_id) / handle_offer(from_user, payload) /
      handle_answer(payload) / handle_ice(payload) / end_call()
    Callbacks: on_state_change(str), on_call_ended().

    NOT implemented yet, deliberately left as a clear next step rather than
    guessed at blind: actually attaching the local AudioTrack's captured
    audio to the Android AudioRecord pipeline and the remote track's
    playback are handled internally by WebRTC's own audio device module
    once permissions are granted -- this class's job is just signaling +
    peer connection lifecycle, matching the desktop split of concerns.
    """

    def __init__(self, session, bridge, on_state_change=None, on_call_ended=None):
        if not HAVE_JNIUS:
            raise RuntimeError("calling.py (mobile) requires pyjnius -- only runs on Android")
        self.session = session
        self.bridge = bridge  # AsyncBridge -- needed because Java/JNI callbacks fire on a non-asyncio thread
        self.on_state_change = on_state_change
        self.on_call_ended = on_call_ended
        self.peer_id = None
        self.pc = None
        self._factory = None
        self._local_audio_track = None
        self._pending_ice_before_remote_desc = []

    def _ensure_factory(self):
        if self._factory is not None:
            return
        c = _classes()
        PeerConnectionFactory = c["PeerConnectionFactory"]
        context = c["PythonActivity"].mActivity.getApplicationContext()

        init_options = (
            autoclass("org.webrtc.PeerConnectionFactory$InitializationOptions")
            .builder(context)
            .createInitializationOptions()
        )
        PeerConnectionFactory.initialize(init_options)
        self._factory = PeerConnectionFactory.builder().createPeerConnectionFactory()
        self._classes = c

    def _new_pc(self, peer_id, observer):
        c = self._classes
        ice_server = c["IceServer"].builder("stun:stun.l.google.com:19302").createIceServer()
        rtc_config = c["RtcConfig"]([ice_server])
        return self._factory.createPeerConnection(rtc_config, observer)

    def _local_audio_source_track(self):
        c = self._classes
        constraints = c["MediaConstraints"]()
        audio_source = self._factory.createAudioSource(constraints)
        self._local_audio_track = self._factory.createAudioTrack("audio0", audio_source)
        return self._local_audio_track

    def _on_ice_candidate(self, candidate):
        if self.peer_id is None:
            return
        payload = json.dumps({
            "sdpMid": candidate.sdpMid,
            "sdpMLineIndex": candidate.sdpMLineIndex,
            "candidate": candidate.sdp,
        })
        self.bridge.run_coro(
            self.session.send_rtc_signal("ice", self.peer_id, payload)
        )

    def _on_connection_change(self, state_str):
        if self.on_state_change:
            self.on_state_change(state_str)
        if state_str in ("FAILED", "CLOSED", "DISCONNECTED"):
            if self.on_call_ended:
                self.on_call_ended()

    async def start_call(self, peer_id: str):
        self._ensure_factory()
        self.peer_id = peer_id
        observer = _PeerConnectionObserver(
            on_ice_candidate=self._on_ice_candidate,
            on_connection_change=self._on_connection_change,
        )
        self._observer = observer  # keep a Python-side reference -- pyjnius objects can be GC'd if unreferenced
        self.pc = self._new_pc(peer_id, observer)

        track = self._local_audio_source_track()
        stream = self._factory.createLocalMediaStream("local_stream")
        stream.addTrack(track)
        self.pc.addStream(stream)

        c = self._classes

        def _on_offer_created(sdp):
            set_observer = _SdpObserver(on_set_success=lambda: None)
            self.pc.setLocalDescription(set_observer, sdp)
            fingerprint = _extract_dtls_fingerprint(sdp.description)
            signature = sw.b64(sw.sign(
                sw.unb64(self.session.private_keys["identity_ed25519_private"]), fingerprint.encode()
            )) if fingerprint else None
            payload = json.dumps({"sdp": sdp.description, "type": "offer", "fingerprint_sig": signature})
            self.bridge.run_coro(
                self.session.send_rtc_signal("offer", peer_id, payload)
            )

        create_observer = _SdpObserver(on_create_success=_on_offer_created)
        self.pc.createOffer(create_observer, c["MediaConstraints"]())

    async def handle_offer(self, from_user: str, payload: str):
        data = json.loads(payload)

        fingerprint = _extract_dtls_fingerprint(data["sdp"])
        signature_b64 = data.get("fingerprint_sig")
        if not fingerprint or not signature_b64:
            raise CallSecurityError(f"call from {from_user} has no signed DTLS fingerprint -- refusing (possible tampering)")
        try:
            bundle = await self.session._fetch_bundle(from_user)
            caller_identity_pub = sw.unb64(bundle["identity_ed25519_pubkey"])
        except Exception as e:
            raise CallSecurityError(f"could not fetch {from_user}'s identity key to verify call: {e}")
        if not sw.verify(caller_identity_pub, fingerprint.encode(), sw.unb64(signature_b64)):
            raise CallSecurityError(f"SECURITY: call fingerprint signature invalid for {from_user} -- possible MITM, refusing")

        self._ensure_factory()
        self.peer_id = from_user
        observer = _PeerConnectionObserver(
            on_ice_candidate=self._on_ice_candidate,
            on_connection_change=self._on_connection_change,
        )
        self._observer = observer
        self.pc = self._new_pc(from_user, observer)

        track = self._local_audio_source_track()
        stream = self._factory.createLocalMediaStream("local_stream")
        stream.addTrack(track)
        self.pc.addStream(stream)

        c = self._classes
        remote_desc = c["SessionDescription"](c["SDPType"].fromCanonicalForm(data["type"]), data["sdp"])

        def _on_remote_set():
            for candidate in self._pending_ice_before_remote_desc:
                self.pc.addIceCandidate(candidate)
            self._pending_ice_before_remote_desc = []

            def _on_answer_created(sdp):
                set_observer = _SdpObserver(on_set_success=lambda: None)
                self.pc.setLocalDescription(set_observer, sdp)
                answer_fingerprint = _extract_dtls_fingerprint(sdp.description)
                answer_signature = sw.b64(sw.sign(
                    sw.unb64(self.session.private_keys["identity_ed25519_private"]), answer_fingerprint.encode()
                )) if answer_fingerprint else None
                answer_payload = json.dumps({
                    "sdp": sdp.description, "type": "answer", "fingerprint_sig": answer_signature})
                self.bridge.run_coro(
                    self.session.send_rtc_signal("answer", from_user, answer_payload)
                )

            answer_observer = _SdpObserver(on_create_success=_on_answer_created)
            self.pc.createAnswer(answer_observer, c["MediaConstraints"]())

        set_remote_observer = _SdpObserver(on_set_success=_on_remote_set)
        self.pc.setRemoteDescription(set_remote_observer, remote_desc)

    async def handle_answer(self, payload: str):
        if self.pc is None:
            return
        c = self._classes
        data = json.loads(payload)

        fingerprint = _extract_dtls_fingerprint(data["sdp"])
        signature_b64 = data.get("fingerprint_sig")
        if not fingerprint or not signature_b64:
            raise CallSecurityError(f"answer from {self.peer_id} has no signed DTLS fingerprint -- refusing (possible tampering)")
        try:
            bundle = await self.session._fetch_bundle(self.peer_id)
            peer_identity_pub = sw.unb64(bundle["identity_ed25519_pubkey"])
        except Exception as e:
            raise CallSecurityError(f"could not fetch {self.peer_id}'s identity key to verify call answer: {e}")
        if not sw.verify(peer_identity_pub, fingerprint.encode(), sw.unb64(signature_b64)):
            raise CallSecurityError(f"SECURITY: answer fingerprint signature invalid for {self.peer_id} -- possible MITM, refusing")

        remote_desc = c["SessionDescription"](c["SDPType"].fromCanonicalForm(data["type"]), data["sdp"])
        set_observer = _SdpObserver(on_set_success=lambda: None)
        self.pc.setRemoteDescription(set_observer, remote_desc)

    async def handle_ice(self, payload: str):
        c = self._classes
        data = json.loads(payload)
        candidate = c["IceCandidate"](data["sdpMid"], data["sdpMLineIndex"], data["candidate"])
        if self.pc is None:
            return
        # If the remote description isn't set yet, WebRTC will reject
        # addIceCandidate -- queue it (mirrors desktop's ICE-before-answer handling).
        try:
            self.pc.addIceCandidate(candidate)
        except Exception:
            self._pending_ice_before_remote_desc.append(candidate)

    async def end_call(self, notify_peer: bool = True):
        if self.pc is not None:
            self.pc.close()
            self.pc = None
        if notify_peer and self.peer_id:
            try:
                await self.session.send_rtc_signal("end", self.peer_id, "{}")
            except Exception:
                pass
        self.peer_id = None
        if self.on_call_ended:
            self.on_call_ended()
