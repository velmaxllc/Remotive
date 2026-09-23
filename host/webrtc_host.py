#!/usr/bin/env python3
"""Remotive WebRTC host — streams the desktop to the *browser* with game-grade latency.

The browser opens the same Remotive link and negotiates a WebRTC connection with this host through the
Cloudflare Worker (which only carries the tiny SDP/ICE handshake). Once connected, H.264 video and input
flow **directly** between the desktop and the browser over WebRTC (UDP/SRTP) — the relay is out of the
media path, and WebRTC's own loss recovery + congestion control replace the TCP-relay bottleneck.

    python webrtc_host.py --url https://remotive.<you>.workers.dev

Reuses the capture + input-injection code from remotive_host.py. Needs: aiortc, av, bettercam.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
import threading
import time
import urllib.error
import urllib.request

import numpy as np
import websockets
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription, VideoStreamTrack
from aiortc.codecs import get_capabilities
from av import VideoFrame

import remotive_host as rh
from aiortc.codecs import h264 as _h264

log = logging.getLogger("webrtc-host")


def set_bitrate_ceiling(kbps_max: int):
    # aiortc caps H.264 at 3 Mbit/s out of the box; raise it so a fast link can actually be used.
    # WebRTC congestion control still adapts *down* from here on a slow connection.
    _h264.MAX_BITRATE = kbps_max * 1000
    _h264.DEFAULT_BITRATE = min(kbps_max, 8000) * 1000
    _h264.MIN_BITRATE = 800_000

AAD_H2V = rh.AAD_H2V
AAD_V2H = rh.AAD_V2H
MSG_JSON = rh.MSG_JSON

# STUN lets each end learn its own public address so the two can connect directly across NATs.
#
# aiortc uses only the *first* STUN server it is given (see connection_kwargs in rtcicetransport), so a
# dead first entry means no public candidate at all — which looks exactly like a firewall problem and is
# the difference between connecting from another network and not. We therefore probe them at startup
# and hand aiortc one that actually answers.
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun1.l.google.com", 19302),
    ("stun.nextcloud.com", 3478),
]
DEFAULT_ICE = [RTCIceServer(urls=["stun:stun.l.google.com:19302"])]


def stun_probe(host: str, port: int, timeout: float = 1.5, sock=None) -> str | None:
    """Send a STUN binding request; return our mapped public address, or None if the server is no use.

    Hand-rolled because it runs before aiortc starts and we only need the one round trip:
    a 20-byte binding request (RFC 5389) and the XOR-MAPPED-ADDRESS attribute out of the reply.

    Pass `sock` to reuse one local port across probes — asking two servers from the *same* socket is
    what distinguishes a symmetric NAT (a different public port per destination) from a friendly one.
    """
    import socket
    import struct

    txid = os.urandom(12)
    request = struct.pack(">HHI12s", 0x0001, 0, 0x2112A442, txid)
    own_socket = sock is None
    if own_socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request, (host, port))
        data, _ = sock.recvfrom(1024)
    except (OSError, socket.timeout):
        return None
    finally:
        if own_socket:
            sock.close()

    if len(data) < 20:
        return None
    msg_type, length, cookie, reply_txid = struct.unpack(">HHI12s", data[:20])
    if msg_type != 0x0101 or cookie != 0x2112A442 or reply_txid != txid:
        return None

    # Walk the attributes looking for XOR-MAPPED-ADDRESS (0x0020).
    offset = 20
    end = min(len(data), 20 + length)
    while offset + 4 <= end:
        attr_type, attr_len = struct.unpack(">HH", data[offset:offset + 4])
        value = data[offset + 4:offset + 4 + attr_len]
        if attr_type == 0x0020 and len(value) >= 8 and value[1] == 0x01:   # IPv4
            mapped_port = struct.unpack(">H", value[2:4])[0] ^ 0x2112
            ip = bytes(b ^ c for b, c in zip(value[4:8], struct.pack(">I", 0x2112A442)))
            return f"{'.'.join(str(b) for b in ip)}:{mapped_port}"
        offset += 4 + attr_len + (-attr_len % 4)     # attributes are padded to 4 bytes
    return None


def working_stun_servers() -> list[RTCIceServer]:
    """Pick a STUN server that actually answers, and report what kind of NAT we are behind."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        alive = []
        for host, port in STUN_SERVERS:
            mapped = stun_probe(host, port, sock=sock)      # same socket every time, on purpose
            if mapped:
                alive.append((host, port, mapped))
                if len(alive) == 2:       # two answers is enough to classify the NAT
                    break
            else:
                log.debug("STUN %s:%d did not answer", host, port)
    finally:
        sock.close()

    if not alive:
        log.warning("no STUN server answered — UDP looks blocked on this network. "
                    "Streaming will only work on this LAN; desktop control still works anywhere.")
        return DEFAULT_ICE

    host, port, mapped = alive[0]
    log.info("STUN ok via %s:%d — this PC is reachable as %s", host, port, mapped.rsplit(":", 1)[0])
    if len(alive) == 2:
        # One socket, two destinations. Same public ip:port for both = cone NAT, which hole punching
        # crosses easily. A different port per destination = symmetric NAT, which it cannot.
        if alive[0][2] == alive[1][2]:
            log.info("NAT looks cone-type — connecting from other networks should work")
        else:
            log.warning("this router uses symmetric NAT (%s vs %s): connections from other networks "
                        "will usually fail. Forwarding a UDP port to this PC, or using desktop "
                        "control instead, is the way around it.", alive[0][2], alive[1][2])
    return [RTCIceServer(urls=[f"stun:{host}:{port}"])]



def fetch_ice_servers(base_url: str, auth_key_hex: str) -> list[RTCIceServer]:
    """Decide which ICE servers to use.

    Asks the relay first: it only has something extra to offer if TURN is configured there. Otherwise
    (the normal case) we probe STUN ourselves, because aiortc uses just one server and a dead one
    leaves us with no public candidate at all.
    """
    endpoint = base_url.rstrip("/") + "/api/ice"
    body = {}
    try:
        req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {auth_key_hex}"})
        with urllib.request.urlopen(req, timeout=10) as res:
            body = json.load(res)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.debug("relay did not supply ICE servers (%s); probing STUN locally", exc)

    if body.get("turn"):
        servers = []
        for entry in body.get("iceServers") or []:
            urls = entry.get("urls") if isinstance(entry, dict) else None
            if urls:
                servers.append(RTCIceServer(urls=urls, username=entry.get("username"),
                                            credential=entry.get("credential")))
        if servers:
            log.info("relay supplied a TURN server — it will be used only if no direct path exists")
            return servers

    return working_stun_servers()


class ScreenTrack(VideoStreamTrack):
    """A WebRTC video track fed by a dedicated screen-capture thread (DXGI/GPU). aiortc encodes it to
    H.264 and its congestion control drives the bitrate automatically."""

    def __init__(self, monitor: int, width: int, height: int, fps: int):
        super().__init__()
        self.width, self.height, self.fps = width, height, fps
        self.monitor = monitor
        self._latest: np.ndarray | None = None
        self._mon = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._capture, name="capture", daemon=True)
        self._thread.start()

    def _capture(self):
        source = rh.ScreenSource(rh.probe_monitors())
        mons = source.monitors
        idx = self.monitor if 0 <= self.monitor < len(mons) else 1
        self._mon = mons[idx]
        interval = 1.0 / max(1, self.fps)
        last = np.zeros((self.height, self.width, 4), np.uint8)
        try:
            while not self._stop.is_set():
                t0 = time.perf_counter()
                try:
                    arr = source.grab(idx, mons[idx])
                except Exception as exc:
                    log.warning("capture failed: %s", exc)
                    time.sleep(0.3)
                    continue
                if arr is not None:
                    last = arr
                with self._lock:
                    self._latest = last
                dt = time.perf_counter() - t0
                if dt < interval:
                    time.sleep(interval - dt)
        finally:
            source.close()

    async def recv(self) -> VideoFrame:
        pts, time_base = await self.next_timestamp()
        with self._lock:
            arr = self._latest
        if arr is None:
            arr = np.zeros((self.height, self.width, 4), np.uint8)
        elif self._mon is not None:
            # Capture never includes the cursor; blend the real one in (cheap; a no-op when it's hidden,
            # e.g. in a game). Copy first so we don't scribble on the shared/last frame.
            arr = arr.copy()
            rh.composite_cursor(arr, self._mon)
        frame = VideoFrame.from_ndarray(arr, format="bgra")
        if frame.width != self.width or frame.height != self.height:
            frame = frame.reformat(width=self.width, height=self.height, format="yuv420p", interpolation="FAST_BILINEAR")
        else:
            frame = frame.reformat(format="yuv420p")
        frame.pts = pts
        frame.time_base = time_base
        return frame

    async def next_timestamp(self):
        # aiortc paces at 30 fps by default; pace at our target fps instead.
        from aiortc.mediastreams import VIDEO_CLOCK_RATE, VIDEO_TIME_BASE
        if hasattr(self, "_ts"):
            self._ts += int(VIDEO_CLOCK_RATE / self.fps)
            wait = self._t0 + (self._ts / VIDEO_CLOCK_RATE) - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
        else:
            self._t0 = time.time(); self._ts = 0
        return self._ts, VIDEO_TIME_BASE

    def stop(self):
        self._stop.set()


class WebRTCHost:
    def __init__(self, url, auth_key_hex, enc_key, monitor, width, height, fps, dry_run):
        self.base_url = url.rstrip("/")
        self.ws_url = self.base_url.replace("https://", "wss://", 1).replace("http://", "ws://", 1) + "/ws/host"
        self.auth_key_hex = auth_key_hex
        self.ice_servers: list[RTCIceServer] | None = None
        self.pending_ice: list[dict] = []   # candidates that arrived before the answer was ready
        self.answered = False
        self.aead = rh.AESGCM(enc_key)
        self.monitor, self.width, self.height, self.fps = monitor, width, height, fps
        self.injector = rh.InputInjector(dry_run=dry_run)
        self.pc: RTCPeerConnection | None = None
        self.track: ScreenTrack | None = None
        self.ws = None
        self.loop = None
        self.seen_events: set[int] = set()

    # ---- E2E relay framing (same as remotive_host so the browser can talk to us) --------------
    def seal(self, obj: dict) -> bytes:
        obj["ts"] = int(time.time() * 1000)
        plain = bytes([MSG_JSON]) + json.dumps(obj, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, plain, AAD_H2V)

    def open(self, data: bytes) -> dict | None:
        if len(data) < 12 + 16 + 1:
            return None
        try:
            plain = self.aead.decrypt(data[:12], data[12:], AAD_V2H)
        except Exception:
            return None
        if plain[0] != MSG_JSON:
            return None
        try:
            msg = json.loads(plain[1:])
        except ValueError:
            return None
        ts = msg.get("ts")
        if not isinstance(ts, (int, float)) or abs(time.time() * 1000 - ts) > 30000:
            return None
        return msg

    async def send(self, obj: dict):
        if self.ws is not None:
            await self.ws.send(self.seal(obj))

    async def _keepalive(self, ws):
        # The relay closes an idle WebSocket, and once WebRTC is up no traffic flows over it — so ping it
        # like the browser does (the relay auto-responds "pong" without waking). Keeps the socket, and thus
        # the live stream, alive.
        try:
            while True:
                await asyncio.sleep(15)
                await ws.send("ping")
        except (asyncio.CancelledError, Exception):
            pass

    # ---- connection ---------------------------------------------------------
    async def run_forever(self):
        self.loop = asyncio.get_running_loop()
        backoff = 1.0
        while True:
            try:
                log.info("connecting to relay %s", self.ws_url)
                async with websockets.connect(self.ws_url, additional_headers={"Authorization": f"Bearer {self.auth_key_hex}"},
                                               max_size=1 << 20, ping_interval=None, open_timeout=15) as ws:
                    self.ws = ws
                    backoff = 1.0
                    log.info("connected to relay; open the Remotive link in your browser and click 'Low latency'")
                    keepalive = asyncio.create_task(self._keepalive(ws))
                    try:
                        async for message in ws:
                            if isinstance(message, str):
                                continue  # relay control (host/viewer presence) or "pong"
                            msg = self.open(message)
                            if msg:
                                await self._on_message(msg)
                    finally:
                        keepalive.cancel()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status == 401:
                    log.error("WRONG PASSWORD OR ANSWER (401). Enter the exact password AND security answer you set "
                              "with `npm run setup` (answer is case-insensitive but must match). Not the relay URL.")
                    backoff = max(backoff, 3)
                elif status == 429:
                    log.error("RATE LIMITED (429): too many wrong logins from your network — the relay blocks you for "
                              "~15 minutes. Wait 15 min, then retry with the correct password + answer.")
                    backoff = max(backoff, 60)
                elif status == 403:
                    log.error("Forbidden (403). Make sure --url has no trailing path (just https://remotive.<you>.workers.dev).")
                    backoff = max(backoff, 5)
                elif status == 503:
                    log.error("Relay not configured (503): run `npm run setup` in the worker folder to set the secrets.")
                    backoff = max(backoff, 10)
                else:
                    log.warning("relay signaling connection lost: %s", exc)
            finally:
                # Keep any live WebRTC peer running — media is P2P and doesn't need the relay. Only the
                # signaling socket is gone; the browser re-offers if it needs to renegotiate.
                self.ws = None
            log.info("reconnecting to relay in %.0fs (any active stream keeps running)", backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def _on_message(self, msg: dict):
        t = msg.get("t")
        if t == "rtc-offer":
            await self._on_offer(msg.get("sdp"))
        elif t == "rtc-ice":
            c = msg.get("candidate")
            if c:
                await self._add_ice(c)
        elif t == "rtc-stop":
            await self._teardown()

    async def _add_ice(self, c: dict):
        """Add one remote candidate, holding it back until the peer can actually accept it.

        The browser trickles candidates the moment it creates its offer, so they routinely arrive
        while we are still building the answer. aiortc drops candidates silently when no transceiver
        exists yet (addIceCandidate just matches nothing), and a lost candidate is often the only
        route the other side had — which is why this failed away from home but never on a LAN.
        """
        if self.pc is None or not self.answered:
            self.pending_ice.append(c)
            if len(self.pending_ice) > 128:        # a peer that never answers must not grow forever
                self.pending_ice.pop(0)
            return
        try:
            from aiortc.sdp import candidate_from_sdp
            cand = candidate_from_sdp(c["candidate"].split(":", 1)[1])
            cand.sdpMid = c.get("sdpMid")
            cand.sdpMLineIndex = c.get("sdpMLineIndex")
            await self.pc.addIceCandidate(cand)
        except Exception as exc:
            log.debug("bad ICE candidate: %s", exc)

    async def _flush_ice(self):
        """Replay everything that arrived too early, now that the answer is in place."""
        queued, self.pending_ice = self.pending_ice, []
        if queued:
            log.info("applying %d ICE candidate(s) that arrived before the answer was ready", len(queued))
        for c in queued:
            await self._add_ice(c)

    async def _on_offer(self, sdp: str):
        if not sdp:
            return
        await self._teardown()
        log.info("browser requested a low-latency (WebRTC) stream; negotiating")
        if self.ice_servers is None:      # fetched once, then reused for later streams
            self.ice_servers = await asyncio.to_thread(fetch_ice_servers, self.base_url, self.auth_key_hex)
        pc = RTCPeerConnection(RTCConfiguration(iceServers=self.ice_servers))
        self.pc = pc
        self.answered = False

        @pc.on("datachannel")
        def on_dc(channel):
            log.info("input datachannel open")

            @channel.on("message")
            def on_msg(message):
                self._handle_input(message)

        @pc.on("connectionstatechange")
        async def on_state():
            if self.pc is not pc:   # a late event from an already-replaced/closed peer
                return
            log.info("webrtc state: %s", pc.connectionState)
            if pc.connectionState in ("failed", "closed", "disconnected"):
                await self._teardown()

        # No "icecandidate" handler: aiortc gathers every candidate *before* setLocalDescription
        # returns and writes them into the answer SDP, so there is nothing to trickle back.

        # Set the remote description first. Building the capture track can take a moment, and until
        # this call lands every candidate the browser sends us would be thrown away.
        await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))

        self.track = ScreenTrack(self.monitor, self.width, self.height, self.fps)
        pc.addTrack(self.track)          # attaches to the browser's recvonly video transceiver
        _prefer_h264(pc)
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)     # gathers ICE; may take a second or two

        n_candidates = pc.localDescription.sdp.count("a=candidate:")
        log.info("answering with %d ICE candidate(s)", n_candidates)
        if not n_candidates:
            log.warning("no ICE candidates gathered — this PC cannot be reached from anywhere")

        await self.send({"t": "rtc-answer", "sdp": pc.localDescription.sdp})
        self.answered = True
        await self._flush_ice()

    def _handle_input(self, message):
        try:
            m = json.loads(message)
        except (ValueError, TypeError):
            return
        t = m.get("t")
        inj = self.injector
        if t == "mr":
            inj.move_rel(int(max(-2000, min(2000, m.get("dx", 0)))), int(max(-2000, min(2000, m.get("dy", 0)))))
        elif t == "md":
            inj.button(int(m.get("b", 0)), True)
        elif t == "mu":
            inj.button(int(m.get("b", 0)), False)
        elif t == "wh":
            inj.scroll(float(m.get("dx", 0)), float(m.get("dy", 0)))
        elif t == "kd":
            inj.key(m.get("key"), m.get("code"), True)
        elif t == "ku":
            inj.key(m.get("key"), m.get("code"), False)

    async def _teardown(self):
        self.answered = False
        self.pending_ice.clear()    # candidates belong to the peer we are dropping
        if self.track is not None:
            self.track.stop()
            self.track = None
        if self.pc is not None:
            pc = self.pc
            self.pc = None
            try:
                await pc.close()
            except Exception:
                pass
            self.injector.release_all()


def _prefer_h264(pc):
    caps = get_capabilities("video")
    pref = [c for c in caps.codecs if c.mimeType == "video/H264"] + [c for c in caps.codecs if c.mimeType == "video/rtx"]
    for tr in pc.getTransceivers():
        if tr.kind == "video" and pref:
            tr.setCodecPreferences(pref)


def main():
    ap = argparse.ArgumentParser(description="Remotive WebRTC host — low-latency browser game streaming")
    ap.add_argument("--url", required=True, help="your Remotive relay URL, e.g. https://remotive.<you>.workers.dev")
    ap.add_argument("--monitor", type=int, default=1)
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=720)
    ap.add_argument("--fps", type=int, default=60)
    ap.add_argument("--bitrate", type=int, default=20000, help="max kbit/s ceiling (default 20000)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("comtypes").setLevel(logging.WARNING)
    logging.getLogger("aioice").setLevel(logging.WARNING)
    logging.getLogger("aiortc").setLevel(logging.WARNING)

    password = os.environ.get("REMOTIVE_PASSWORD") or getpass.getpass("Remotive password: ")
    # Optional second factor: only if the relay was set up with a security question.
    answer = os.environ.get("REMOTIVE_ANSWER")
    if answer is None:
        answer = getpass.getpass("Security answer (press Enter if you didn't set a question): ")
    auth_key_hex, enc_key = rh.derive_keys(password, answer)
    del password, answer
    rh.make_dpi_aware()
    set_bitrate_ceiling(max(2000, min(50000, args.bitrate)))
    log.info("video up to %d kbit/s; WebRTC will adapt to your link", args.bitrate)

    host = WebRTCHost(args.url, auth_key_hex, enc_key, args.monitor, args.width & ~1, args.height & ~1,
                      max(15, min(rh.MAX_FPS, args.fps)), args.dry_run)
    try:
        asyncio.run(host.run_forever())
    except KeyboardInterrupt:
        pass
    finally:
        host.injector.release_all()


if __name__ == "__main__":
    main()
