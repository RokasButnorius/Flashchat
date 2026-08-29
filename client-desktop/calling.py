"""
client-desktop/calling.py

Voice/video calling using aiortc (real WebRTC in Python -- DTLS-SRTP
encrypted media, same security properties as browser WebRTC). Signaling
rides over the existing relay via rtc_offer/rtc_answer/rtc_ice_candidate,
exactly like the web client used.

Device enumeration is best-effort: audio devices via `sounddevice`,
camera via OpenCV probing. Both degrade gracefully if the library or
hardware isn't available (e.g. no mic/camera present) -- the call UI
will just show "No devices found" rather than crashing.
"""

import asyncio
import json
import re

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
from aiortc.contrib.media import MediaPlayer, MediaRelay
from crypto import sodium_wrapper as sw


def _extract_dtls_fingerprint(sdp: str) -> str | None:
    """Pulls the DTLS certificate fingerprint out of an SDP blob, e.g.
    'a=fingerprint:sha-256 AB:CD:...'. This is the value that actually
    identifies which encryption key a call will use -- signing THIS
    (not the whole SDP) is what stops a malicious relay from swapping in
    its own cert and MITM'ing the call, the same way X3DH's signed
    prekey stops a malicious relay from MITM'ing a chat session."""
    m = re.search(r"^a=fingerprint:(\S+ \S+)$", sdp, re.MULTILINE)
    return m.group(1) if m else None


class CallSecurityError(Exception):
    """Raised when a call's DTLS fingerprint signature is missing or
    doesn't verify against the peer's known identity key -- treat this
    as a possible MITM attempt, never fall back to accepting the call
    unauthenticated."""
    pass

try:
    import sounddevice as sd
    HAVE_SOUNDDEVICE = True
except Exception:
    HAVE_SOUNDDEVICE = False

try:
    import cv2
    HAVE_OPENCV = True
except Exception:
    HAVE_OPENCV = False


def list_audio_input_devices() -> list[dict]:
    if not HAVE_SOUNDDEVICE:
        return []
    try:
        devices = sd.query_devices()
        return [{"index": i, "name": d["name"]} for i, d in enumerate(devices) if d["max_input_channels"] > 0]
    except Exception:
        return []


def list_audio_output_devices() -> list[dict]:
    if not HAVE_SOUNDDEVICE:
        return []
    try:
        devices = sd.query_devices()
        return [{"index": i, "name": d["name"]} for i, d in enumerate(devices) if d["max_output_channels"] > 0]
    except Exception:
        return []


def list_camera_devices(max_probe: int = 5) -> list[dict]:
    if not HAVE_OPENCV:
        return []
    found = []
    for i in range(max_probe):
        cap = cv2.VideoCapture(i)
        if cap is not None and cap.isOpened():
            found.append({"index": i, "name": f"Camera {i}"})
            cap.release()
    return found


def default_input_device_name() -> str | None:
    """
    Best-effort lookup of the system's default microphone name, for use
    when the caller doesn't explicitly pick one. Without this fallback,
    start_call() would silently open NO audio device at all if mic_device
    was never passed in -- meaning the call connects fine, but that side
    never sends any audio track, and the other person hears nothing.
    """
    if not HAVE_SOUNDDEVICE:
        return None
    try:
        default_idx = sd.default.device[0]  # (input_index, output_index)
        if default_idx is None or default_idx < 0:
            return None
        devices = sd.query_devices()
        d = devices[default_idx]
        if d["max_input_channels"] > 0:
            return d["name"]
    except Exception:
        pass
    return None


def default_output_device_name() -> str | None:
    """Speaker/headphone counterpart to default_input_device_name()."""
    if not HAVE_SOUNDDEVICE:
        return None
    try:
        default_idx = sd.default.device[1]  # (input_index, output_index)
        if default_idx is None or default_idx < 0:
            return None
        devices = sd.query_devices()
        d = devices[default_idx]
        if d["max_output_channels"] > 0:
            return d["name"]
    except Exception:
        pass
    return None


class AudioSink:
    """
    Consumes an incoming aiortc audio track and plays it through the
    selected output device.

    IMPORTANT ARCHITECTURE NOTE: playback uses sounddevice's callback
    mode, not blocking stream.write(). PortAudio calls our callback on
    its OWN dedicated thread to pull audio data from a queue -- this
    keeps the asyncio event loop completely free. The earlier blocking
    write() version froze the entire app (network, UI, everything) for
    the duration of every single audio write, which is what caused the
    "recording delay" / hang-up symptoms.

    Also fixes: audio frames can be "planar" (channels, samples) or
    "packed/interleaved" (samples*channels in one row) depending on
    format. Treating packed audio as planar scrambles the waveform,
    which can manifest as distorted/deep-sounding voice.
    """

    def __init__(self, track, output_device_name: str | None = None):
        self.track = track
        self.output_device_name = output_device_name
        self._task: asyncio.Task | None = None
        self._stream = None
        self._queue = None   # created lazily once we know maxsize behavior is fine
        self._channels = None
        self._leftover = None   # carries partial chunk data across callback calls when PortAudio's block size doesn't line up with our chunk size

    def _resolve_device_index(self):
        if not HAVE_SOUNDDEVICE or not self.output_device_name:
            return None
        try:
            devices = sd.query_devices()
            for i, d in enumerate(devices):
                if d["name"] == self.output_device_name and d["max_output_channels"] > 0:
                    return i
        except Exception:
            pass
        return None

    @staticmethod
    def _frame_to_array(frame):
        """Normalizes any aiortc/PyAV audio frame layout to (samples, channels)."""
        arr = frame.to_ndarray()
        try:
            channels = len(frame.layout.channels)
        except Exception:
            channels = arr.shape[0] if arr.ndim == 2 else 1

        if arr.ndim == 1:
            arr = arr.reshape(-1, channels)
        elif arr.shape[0] == channels and arr.shape[1] != channels:
            arr = arr.T  # was planar (channels, samples) -> (samples, channels)
        elif arr.shape[1] != channels:
            arr = arr.reshape(-1, channels)  # was packed/interleaved in one row
        return arr, channels

    def start(self):
        if not HAVE_SOUNDDEVICE:
            print("[calling] WARNING: sounddevice not available -- cannot play received audio")
            return
        import queue as _queue
        self._queue = _queue.Queue(maxsize=40)  # ~800ms worst-case backlog, still gives dropout headroom without letting delay stack up
        self._task = asyncio.ensure_future(self._recv_loop())

    def _audio_callback(self, outdata, frames, time_info, status):
        # Runs on PortAudio's own thread. Must stay fast and non-blocking:
        # no asyncio calls, no locks that the asyncio loop could be holding.
        #
        # IMPORTANT: PortAudio can request a block size larger than any
        # single queued chunk (our chunks are one WebRTC audio frame each,
        # ~10-20ms; PortAudio's requested `frames` depends on the device/
        # driver and is NOT guaranteed to match). The old version only
        # ever pulled ONE chunk per call and silence-padded the rest --
        # if PortAudio asked for more than one chunk's worth (common),
        # that produced a periodic stutter on every single callback.
        # This version drains as many queued chunks as needed and keeps
        # any leftover for the next call.
        import queue as _queue
        filled = 0

        if self._leftover is not None:
            n = min(len(self._leftover), frames)
            outdata[:n] = self._leftover[:n]
            filled = n
            self._leftover = self._leftover[n:] if n < len(self._leftover) else None

        while filled < frames:
            try:
                chunk = self._queue.get_nowait()
            except _queue.Empty:
                outdata[filled:] = 0
                return
            need = frames - filled
            if len(chunk) <= need:
                outdata[filled:filled + len(chunk)] = chunk
                filled += len(chunk)
            else:
                outdata[filled:frames] = chunk[:need]
                self._leftover = chunk[need:]
                filled = frames

    async def _recv_loop(self):
        import queue as _queue
        import time as _time
        priming_frames = []
        PRIME_COUNT = 3   # buffer a few frames before starting playback, avoids an underrun right at call start
        frames_recvd = 0
        _last_log = _time.monotonic()
        try:
            while True:
                frame = await self.track.recv()
                frames_recvd += 1
                arr, channels = self._frame_to_array(frame)

                # DIAGNOSTIC (temporary): logs once a second how deep the
                # playback queue is. If qsize stays near maxsize, audio is
                # arriving faster than it's being played -- points at the
                # OS output stream/device. If qsize stays near 0 but audio
                # is still delayed, the delay is happening BEFORE this
                # point (network/jitter/sender side), not in our buffer.
                now = _time.monotonic()
                if now - _last_log > 1.0 and self._queue is not None:
                    print(f"[calling] diag: recv'd {frames_recvd} frames, queue depth {self._queue.qsize()}/{self._queue.maxsize}")
                    _last_log = now

                if self._stream is None:
                    priming_frames.append(arr)
                    if len(priming_frames) < PRIME_COUNT:
                        continue
                    device = self._resolve_device_index()
                    self._stream = sd.OutputStream(
                        samplerate=frame.sample_rate, channels=channels,
                        dtype=arr.dtype, device=device,
                        callback=self._audio_callback,
                        # "high" trades a bit more latency for much better
                        # resistance to underrun/choppiness -- worth it for
                        # voice quality. "low" was too aggressive and left
                        # no slack for any timing jitter.
                        # NOTE: "low" trades a little dropout resistance for
                        # much less added delay. If you get choppy audio on
                        # a slow/congested network, bump back to "high" --
                        # but with Bluetooth output devices in particular,
                        # "high" here stacks on top of the BT stack's own
                        # buffering and can add seconds of delay.
                        latency="low",
                    )
                    for pf in priming_frames:
                        try:
                            self._queue.put_nowait(pf)
                        except _queue.Full:
                            pass
                    self._stream.start()
                    print(f"[calling] audio playback started ({frame.sample_rate}Hz, {channels}ch, "
                          f"device={self.output_device_name or 'default'})")
                    continue

                # Non-blocking enqueue. On overflow, drop the OLDEST chunk
                # rather than blocking or dropping the new one -- this
                # keeps latency from growing unbounded if playback ever
                # falls behind, instead of the delay compounding forever.
                try:
                    self._queue.put_nowait(arr)
                except _queue.Full:
                    try:
                        self._queue.get_nowait()
                    except _queue.Empty:
                        pass
                    try:
                        self._queue.put_nowait(arr)
                    except _queue.Full:
                        pass
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[calling] audio playback error (call continues, but you won't hear the other side): {e}")
        finally:
            self._close_stream()

    def _close_stream(self):
        if self._stream:
            try:
                self._stream.stop()
                self._stream.close()
            except Exception:
                pass
            self._stream = None

    def stop(self):
        if self._task and not self._task.done():
            self._task.cancel()
        self._close_stream()


class VideoSink:
    """
    Consumes an incoming aiortc video track and hands each frame to a
    callback as a PIL Image for the GUI to render. Unlike audio, video
    doesn't need a separate real-time thread -- frame delivery at
    15-30fps is fine driven directly by the asyncio loop.
    """

    def __init__(self, track, on_frame):
        self.track = track
        self.on_frame = on_frame   # callback(PIL.Image)
        self._task: asyncio.Task | None = None

    def start(self):
        self._task = asyncio.ensure_future(self._run())

    async def _run(self):
        try:
            while True:
                frame = await self.track.recv()
                img = frame.to_image()  # PyAV VideoFrame -> PIL Image (RGB)
                if self.on_frame:
                    self.on_frame(img)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[calling] video render error: {e}")

    def stop(self):
        if self._task and not self._task.done():
            self._task.cancel()


class CallManager:
    """
    One call at a time. Wraps an aiortc RTCPeerConnection and bridges
    its signaling messages through the relay's rtc_* message types.

    NOTE: MediaPlayer capture device syntax is OS-specific (dshow on
    Windows) -- this targets Windows since that's the deployment target.
    """

    def __init__(self, session, on_remote_track=None, on_call_ended=None, on_state_change=None, on_video_frame=None):
        self.session = session
        self.pc: RTCPeerConnection | None = None
        self.peer_id: str | None = None
        self.player: MediaPlayer | None = None
        self.on_remote_track = on_remote_track
        self.on_call_ended = on_call_ended
        self.on_state_change = on_state_change   # callback(state: str)
        self.on_video_frame = on_video_frame     # callback(PIL.Image)
        self._relay = MediaRelay()
        self.last_media_error: str | None = None
        self._watchdog_task: asyncio.Task | None = None
        self._ending = False   # guards against reentrant end_call() calls
        self.speaker_device: str | None = None
        self._audio_sinks: list[AudioSink] = []
        self._video_sinks: list[VideoSink] = []

    def _new_pc(self, peer_id: str) -> RTCPeerConnection:
        config = RTCConfiguration(iceServers=[RTCIceServer(urls="stun:stun.l.google.com:19302")])
        pc = RTCPeerConnection(configuration=config)
        self.peer_id = peer_id

        # Guarantees at least one m-line exists even if media capture
        # fails below -- without this, a failed mic/camera open leaves
        # zero tracks, which means nothing to negotiate, which means
        # ICE gathering never has anything to do and the call hangs on
        # "Calling..." forever with no error shown.
        pc.createDataChannel("keepalive")

        @pc.on("track")
        def on_track(track):
            if track.kind == "audio":
                sink = AudioSink(track, output_device_name=self.speaker_device)
                sink.start()
                self._audio_sinks.append(sink)
            elif track.kind == "video":
                vsink = VideoSink(track, on_frame=self.on_video_frame)
                vsink.start()
                self._video_sinks.append(vsink)
            if self.on_remote_track:
                self.on_remote_track(track)

        @pc.on("connectionstatechange")
        async def on_state_change():
            print(f"[calling] connection state -> {pc.connectionState}")
            if self.on_state_change:
                self.on_state_change(pc.connectionState)
            # NOTE: pc.close() (called from end_call) triggers THIS event
            # firing again with state 'closed' -- without the _ending
            # guard in end_call(), that would re-enter end_call() while
            # the first call is still executing, corrupting state and
            # causing AttributeErrors on subsequent pc property access.
            if pc.connectionState in ("failed", "closed", "disconnected"):
                await self.end_call(notify_peer=False)

        self._watchdog_task = asyncio.ensure_future(self._connection_timeout_watchdog(pc))
        return pc

    async def _connection_timeout_watchdog(self, pc: RTCPeerConnection, timeout: float = 20.0):
        """If the connection hasn't reached 'connected' within `timeout`
        seconds, treat it as failed instead of hanging forever with no
        feedback -- most commonly caused by a firewall silently dropping
        UDP traffic, or both peers being behind NAT types STUN alone
        can't traverse (would need a TURN relay server to fix)."""
        try:
            await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            return  # call ended normally before the timeout -- nothing to do
        if pc.connectionState not in ("connected", "closed"):
            print(f"[calling] TIMEOUT after {timeout}s -- still stuck at '{pc.connectionState}'. "
                  f"Likely a firewall blocking UDP, or NAT type STUN can't traverse (would need TURN).")
            if self.on_state_change:
                self.on_state_change("timeout")
            await self.end_call(notify_peer=False)

    @staticmethod
    async def _wait_for_ice_gathering_complete(pc: RTCPeerConnection, timeout: float = 8.0):
        """
        We're not implementing trickle ICE (candidates sent one-by-one as
        they're discovered) -- instead we wait for gathering to finish and
        send the complete SDP in one shot. Without this wait, the SDP sent
        immediately after setLocalDescription() is often missing candidates
        entirely, so the remote side has no usable network path and the
        call hangs on "Calling..." forever without ever connecting.
        """
        if pc is None:
            return
        if pc.iceGatheringState == "complete":
            return
        done = asyncio.get_event_loop().create_future()

        @pc.on("icegatheringstatechange")
        def on_change():
            if pc.iceGatheringState == "complete" and not done.done():
                done.set_result(None)

        try:
            await asyncio.wait_for(done, timeout=timeout)
        except asyncio.TimeoutError:
            pass  # proceed with whatever candidates were gathered so far

    async def start_call(self, peer_id: str, mic_device: str = None, camera_device: str = None,
                          speaker_device: str = None, with_video: bool = True):
        self.speaker_device = speaker_device
        self.pc = self._new_pc(peer_id)

        # BUGFIX: the old logic was `if mic_device: ... elif camera_device: ...`
        # -- an either/or. That meant a video call NEVER sent audio (camera
        # branch only), and if mic_device was never explicitly passed by the
        # caller (it defaults to None), NO audio device was opened at all --
        # the call would connect fine but that side would send total silence,
        # which matches "we connected but couldn't hear each other".
        #
        # Fix: fall back to the system default mic if none was specified,
        # and build a combined dshow source so audio + video can both be
        # sent in the same call instead of one silently overriding the other.
        resolved_mic = mic_device or default_input_device_name()
        resolved_camera = camera_device if with_video else None

        try:
            if resolved_mic and resolved_camera:
                source = f"video={resolved_camera}:audio={resolved_mic}"
            elif resolved_camera:
                source = f"video={resolved_camera}"
            elif resolved_mic:
                source = f"audio={resolved_mic}"
            else:
                source = None

            self.player = MediaPlayer(source, format="dshow") if source else None
            if self.player is None:
                print("[calling] WARNING: no microphone or camera resolved -- "
                      "this side will send no media. Check that a default "
                      "input device exists and sounddevice is installed.")
        except Exception as e:
            self.player = None
            self.last_media_error = f"{type(e).__name__}: {e}"
            print(f"[calling] WARNING: failed to open media device ({resolved_mic or resolved_camera}): {self.last_media_error}")
            print("[calling] Call will proceed as a connection-only/no-media session unless this is fixed.")

        if self.pc is None:
            return  # call was ended concurrently (e.g. dialog closed) before we got this far
        if self.player and self.player.audio:
            self.pc.addTrack(self._relay.subscribe(self.player.audio))
        if self.player and self.player.video:
            self.pc.addTrack(self._relay.subscribe(self.player.video))

        offer = await self.pc.createOffer()
        if self.pc is None:
            return
        await self.pc.setLocalDescription(offer)
        await self._wait_for_ice_gathering_complete(self.pc)
        if self.pc is None:
            return  # ended while we were gathering ICE candidates

        fingerprint = _extract_dtls_fingerprint(self.pc.localDescription.sdp)
        signature = sw.b64(sw.sign(
            sw.unb64(self.session.private_keys["identity_ed25519_private"]), fingerprint.encode()
        )) if fingerprint else None

        await self.session.send_rtc_signal("offer", peer_id, json.dumps({
            "sdp": self.pc.localDescription.sdp, "type": self.pc.localDescription.type,
            "fingerprint_sig": signature,
        }))

    async def handle_offer(self, from_user: str, payload: str, mic_device: str = None,
                           camera_device: str = None, speaker_device: str = None):
        """BUGFIX: this used to never call addTrack at all -- it only set up
        the remote description and answered, so the answering side always
        sent pure silence back. That's why calls "connected" but only the
        caller could ever be heard. Mirrors start_call's device-resolution
        logic so both sides of a call actually send media."""
        self.speaker_device = speaker_device
        data = json.loads(payload)
        offer = RTCSessionDescription(sdp=data["sdp"], type=data["type"])

        fingerprint = _extract_dtls_fingerprint(offer.sdp)
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

        self.pc = self._new_pc(from_user)
        await self.pc.setRemoteDescription(offer)

        # Only offer a camera back if the caller's offer actually negotiated
        # video -- answering an audio-only offer with a video track can
        # confuse SDP negotiation on some peers.
        offer_has_video = "m=video" in offer.sdp
        resolved_mic = mic_device or default_input_device_name()
        resolved_camera = camera_device if offer_has_video else None

        try:
            if resolved_mic and resolved_camera:
                source = f"video={resolved_camera}:audio={resolved_mic}"
            elif resolved_camera:
                source = f"video={resolved_camera}"
            elif resolved_mic:
                source = f"audio={resolved_mic}"
            else:
                source = None

            self.player = MediaPlayer(source, format="dshow") if source else None
            if self.player is None:
                print("[calling] WARNING: no microphone or camera resolved -- "
                      "this side will send no media. Check that a default "
                      "input device exists and sounddevice is installed.")
        except Exception as e:
            self.player = None
            self.last_media_error = f"{type(e).__name__}: {e}"
            print(f"[calling] WARNING: failed to open media device ({resolved_mic or resolved_camera}): {self.last_media_error}")
            print("[calling] Call will proceed as a connection-only/no-media session unless this is fixed.")

        if self.pc is None:
            return  # call was ended concurrently (e.g. dialog closed) before we got this far
        if self.player and self.player.audio:
            self.pc.addTrack(self._relay.subscribe(self.player.audio))
        if self.player and self.player.video:
            self.pc.addTrack(self._relay.subscribe(self.player.video))

        answer = await self.pc.createAnswer()
        if self.pc is None:
            return
        await self.pc.setLocalDescription(answer)
        await self._wait_for_ice_gathering_complete(self.pc)
        if self.pc is None:
            return
        answer_fingerprint = _extract_dtls_fingerprint(self.pc.localDescription.sdp)
        answer_signature = sw.b64(sw.sign(
            sw.unb64(self.session.private_keys["identity_ed25519_private"]), answer_fingerprint.encode()
        )) if answer_fingerprint else None
        await self.session.send_rtc_signal("answer", from_user, json.dumps({
            "sdp": self.pc.localDescription.sdp, "type": self.pc.localDescription.type,
            "fingerprint_sig": answer_signature,
        }))

    async def handle_answer(self, payload: str, from_user: str = None):
        if not self.pc:
            return
        data = json.loads(payload)
        answer = RTCSessionDescription(sdp=data["sdp"], type=data["type"])

        peer_id = from_user or self.peer_id
        fingerprint = _extract_dtls_fingerprint(answer.sdp)
        signature_b64 = data.get("fingerprint_sig")
        if not fingerprint or not signature_b64:
            raise CallSecurityError(f"answer from {peer_id} has no signed DTLS fingerprint -- refusing (possible tampering)")
        try:
            bundle = await self.session._fetch_bundle(peer_id)
            peer_identity_pub = sw.unb64(bundle["identity_ed25519_pubkey"])
        except Exception as e:
            raise CallSecurityError(f"could not fetch {peer_id}'s identity key to verify call answer: {e}")
        if not sw.verify(peer_identity_pub, fingerprint.encode(), sw.unb64(signature_b64)):
            raise CallSecurityError(f"SECURITY: answer fingerprint signature invalid for {peer_id} -- possible MITM, refusing")

        await self.pc.setRemoteDescription(answer)

    async def handle_ice(self, payload: str):
        # aiortc bundles ICE candidates into the SDP itself (no trickle
        # needed for local/simple NAT setups) -- kept for protocol
        # symmetry with the web client's signaling shape.
        pass

    async def end_call(self, notify_peer: bool = True):
        if self._ending:
            return  # already tearing down -- pc.close() re-triggers this event, ignore the echo
        self._ending = True
        try:
            if self._watchdog_task and not self._watchdog_task.done():
                self._watchdog_task.cancel()
            for sink in self._audio_sinks:
                sink.stop()
            self._audio_sinks.clear()
            for vsink in self._video_sinks:
                vsink.stop()
            self._video_sinks.clear()
            if self.pc:
                pc, self.pc = self.pc, None
                await pc.close()
            self.player = None
            if self.on_call_ended:
                self.on_call_ended()
            self.peer_id = None
        finally:
            self._ending = False