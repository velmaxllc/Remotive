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

# Public STUN so the two ends can discover their public address and connect directly across NATs.
# STUN alone is enough on a LAN, but many networks (hotspots, hotel/office Wi-Fi, ISP CGNAT) block the
# direct path entirely — then a TURN relay is the only way through. The relay hands us those servers
# from /api/ice; see worker/src/ice.ts.
DEFAULT_ICE = [RTCIceServer(urls=["stun:stun.cloudflare.com:3478", "stun:stun.l.google.com:19302"])]


def fetch_ice_servers(base_url: str, auth_key_hex: str) -> list[RTCIceServer]:
    """Ask the relay for ICE servers. Falls back to public STUN if it cannot say."""
    endpoint = base_url.rstrip("/") + "/api/ice"
    try:
        req = urllib.request.Request(endpoint, headers={"Authorization": f"Bearer {auth_key_hex}"})
        with urllib.request.urlopen(req, timeout=10) as res:
            body = json.load(res)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not fetch ICE servers (%s); using public STUN only", exc)
        return DEFAULT_ICE

    servers = []
    for entry in body.get("iceServers") or []:
        urls = entry.get("urls") if isinstance(entry, dict) else None
        if not urls:
            continue
        servers.append(RTCIceServer(urls=urls, username=entry.get("username"), credential=entry.get("credential")))
    if not servers:
        return DEFAULT_ICE
    if body.get("turn"):
        log.info("using a TURN relay — streaming should work from other networks too")
    else:
        log.info("STUN only: streaming will work on this LAN, but may not from other networks "
                 "(see 'Streaming away from home' in the README)")
    return servers


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
        elif t == "rtc-ice" and self.pc is not None:
            c = msg.get("candidate")
            if c:
                try:
                    from aiortc.sdp import candidate_from_sdp
                    cand = candidate_from_sdp(c["candidate"].split(":", 1)[1])
                    cand.sdpMid = c.get("sdpMid")
                    cand.sdpMLineIndex = c.get("sdpMLineIndex")
                    await self.pc.addIceCandidate(cand)
                except Exception as exc:
                    log.debug("bad ICE candidate: %s", exc)
        elif t == "rtc-stop":
            await self._teardown()

    async def _on_offer(self, sdp: str):
        if not sdp:
            return
        await self._teardown()
        log.info("browser requested a low-latency (WebRTC) stream; negotiating")
        if self.ice_servers is None:      # fetched once, then reused for later streams
            self.ice_servers = await asyncio.to_thread(fetch_ice_servers, self.base_url, self.auth_key_hex)
        pc = RTCPeerConnection(RTCConfiguration(iceServers=self.ice_servers))
        self.pc = pc
        self.track = ScreenTrack(self.monitor, self.width, self.height, self.fps)

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

        @pc.on("icecandidate")
        async def on_ice(candidate):
            if candidate:
                await self.send({"t": "rtc-ice", "candidate": {
                    "candidate": "candidate:" + candidate.to_sdp(),
                    "sdpMid": candidate.sdpMid, "sdpMLineIndex": candidate.sdpMLineIndex}})

        await self.pc.setRemoteDescription(RTCSessionDescription(sdp=sdp, type="offer"))
        self.pc.addTrack(self.track)     # attaches to the browser's recvonly video transceiver
        _prefer_h264(self.pc)
        answer = await self.pc.createAnswer()
        await self.pc.setLocalDescription(answer)
        await self.send({"t": "rtc-answer", "sdp": self.pc.localDescription.sdp})

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
