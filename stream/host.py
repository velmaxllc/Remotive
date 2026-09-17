#!/usr/bin/env python3
"""Remotive Stream host — runs on the desktop you want to play on.

Captures the screen (DXGI/GPU), encodes H.264 with the GPU's hardware encoder, splits each frame into
FEC shards and sends them over UDP to the client. Receives the client's mouse/keyboard over UDP and
injects it. No relay, no TCP: a direct connection over your LAN or a Tailscale IP.

    python host.py                       # asks for the password, listens on 0.0.0.0:47990
    python host.py --port 47990 --fps 60 --bitrate 15000 --width 1280 --height 720
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import socket
import struct
import sys
import threading
import time

# Reuse the capture / encode / input-injection code that already works in the WebSocket host.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "host"))
import remotive_host as rh  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P  # noqa: E402

log = logging.getLogger("stream-host")


class StreamHost:
    def __init__(self, key: bytes, port: int, monitor: int, width: int, height: int, fps: int,
                 bitrate: int, adapt: bool, dry_run: bool):
        self.sealer = P.Sealer(key, P.AAD_H2C, P.AAD_C2H)
        self.port = port
        self.monitor = monitor
        self.out_w = width
        self.out_h = height
        self.fps = fps
        self.bitrate = bitrate            # kbit/s (current target)
        self.bitrate_max = bitrate
        self.bitrate_min = 1500
        self.adapt = adapt
        self.injector = rh.InputInjector(dry_run=dry_run)
        self.monitors = rh.probe_monitors()
        self.client_addr: tuple[str, int] | None = None
        self.client_seen = 0.0
        self.frame_seq = 0
        self.force_key = True
        self.seen_events: set[int] = set()
        self.event_order: list[int] = []
        self.sock: socket.socket | None = None
        self.stop = threading.Event()
        self.stats = {"frames": 0, "bytes": 0}

    # ---- networking ---------------------------------------------------------

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.settimeout(0.5)
        log.info("listening on UDP 0.0.0.0:%d  (%dx%d @ %d fps, up to %d kbit/s)",
                 self.port, self.out_w, self.out_h, self.fps, self.bitrate_max)
        log.info("waiting for the client to connect (run client.py on the laptop with the same password)")
        recv = threading.Thread(target=self._recv_loop, name="recv", daemon=True)
        recv.start()
        stats = threading.Thread(target=self._stats_loop, name="stats", daemon=True)
        stats.start()
        try:
            self._capture_loop()
        finally:
            self.stop.set()
            self.injector.release_all()

    def _recv_loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            body = self.sealer.open(data)
            if body is None:
                continue  # wrong password / replay / corrupt — ignore silently
            t = body[0]
            if t == P.T_HELLO:
                info = P.parse_hello(body)
                if info and addr != self.client_addr:
                    log.info("client connected from %s:%d (wants %d fps, %d kbit/s)",
                             addr[0], addr[1], info["fps"], info["kbps"])
                    self.client_addr = addr
                    self.force_key = True
                    if info["fps"]:
                        self.fps = max(15, min(rh.MAX_FPS, info["fps"]))
                    if info["kbps"]:
                        self.bitrate = self.bitrate_max = max(self.bitrate_min, min(80000, info["kbps"]))
                    self._send(P.build_meta(self.out_w, self.out_h, self.fps, "h264"))
                elif info:
                    self.client_seen = time.monotonic()
                self.client_seen = time.monotonic()
            elif t == P.T_INPUT:
                self.client_seen = time.monotonic()
                self._handle_input(body)
            elif t == P.T_FEEDBACK:
                self.client_seen = time.monotonic()
                self._handle_feedback(P.parse_feedback(body))
            elif t == P.T_BYE:
                if addr == self.client_addr:
                    log.info("client disconnected")
                    self.client_addr = None
                    self.injector.release_all()

    def _send(self, body: bytes):
        if self.client_addr:
            try:
                self.sock.sendto(self.sealer.seal(body), self.client_addr)
            except OSError:
                pass

    # ---- input injection ----------------------------------------------------

    def _dedup(self, event_id: int) -> bool:
        """True the first time we see an event_id (discrete events are sent several times)."""
        if event_id in self.seen_events:
            return False
        self.seen_events.add(event_id)
        self.event_order.append(event_id)
        if len(self.event_order) > 4096:
            for old in self.event_order[:2048]:
                self.seen_events.discard(old)
            self.event_order = self.event_order[2048:]
        return True

    def _handle_input(self, body: bytes):
        ev = P.parse_input(body)
        if ev is None:
            return
        kind = ev[0]
        if kind == "move":
            self.injector.move_rel(ev[1], ev[2])
        elif kind == "button":
            if self._dedup(ev[1]):
                self.injector.button(ev[2], ev[3])
        elif kind == "wheel":
            self.injector.scroll(ev[1] / 120.0, ev[2] / 120.0)
        elif kind == "key":
            if self._dedup(ev[1]):
                self.injector.key(ev[4], ev[3], ev[2])  # key(key, code, down)

    def _handle_feedback(self, fb):
        if not fb:
            return
        if fb["request_key"]:
            self.force_key = True
        if not self.adapt:
            return
        # UDP congestion control: back off fast on loss, creep up when it's clean.
        loss = fb["loss"] / 1000.0
        if loss > 0.05:
            self.bitrate = max(self.bitrate_min, int(self.bitrate * 0.8))
        elif loss < 0.01 and fb["fps"] >= 0.9 * self.fps:
            self.bitrate = min(self.bitrate_max, int(self.bitrate * 1.05) + 100)

    # ---- capture + encode + send -------------------------------------------

    def _capture_loop(self):
        source = rh.ScreenSource(self.monitors)
        encoder = rh.VideoEncoder()
        try:
            next_at = time.perf_counter()
            while not self.stop.is_set():
                if not self.client_addr or time.monotonic() - self.client_seen > 5:
                    if self.client_addr and time.monotonic() - self.client_seen > 5:
                        log.info("client went quiet; pausing")
                        self.client_addr = None
                        self.injector.release_all()
                    time.sleep(0.1)
                    next_at = time.perf_counter()
                    continue
                now = time.perf_counter()
                if now < next_at:
                    time.sleep(min(0.004, next_at - now))
                    continue
                interval = 1.0 / max(1, self.fps)
                next_at = max(next_at + interval, now - interval)

                mon_idx = self.monitor if 0 <= self.monitor < len(self.monitors) else 1
                try:
                    arr = source.grab(mon_idx, self.monitors[mon_idx])
                except Exception as exc:
                    log.warning("capture failed: %s", exc)
                    time.sleep(0.3)
                    continue
                if arr is None:
                    # Nothing changed on screen. Re-send the last frame only occasionally (so a freshly
                    # joined client or a keyframe request is still served) instead of every tick.
                    last = getattr(self, "_last", None)
                    if last is None:
                        continue
                    if not self.force_key and (now - getattr(self, "_last_send", 0.0)) < 0.2:
                        continue
                    arr = last
                else:
                    self._last = arr

                reopened = encoder.ensure(self.out_w, self.out_h, self.fps, self.bitrate)
                if reopened:
                    self.force_key = True
                elif encoder.ctx is not None and encoder.ctx.bit_rate != self.bitrate * 1000:
                    encoder.ctx.bit_rate = self.bitrate * 1000  # live bitrate nudge (nvenc honours it)
                    encoder.params = (self.out_w, self.out_h, self.fps, self.bitrate)
                # Capture never includes the cursor; blend the real one in (no-op when it's hidden in a game).
                arr = arr.copy()
                rh.composite_cursor(arr, self.monitors[mon_idx])
                pix_fmt = "yuv420p" if encoder.name == "libx264" else "bgra"
                frame = rh.VideoEncoder.prepare(arr, self.out_w, self.out_h, pix_fmt)
                want_key, self.force_key = self.force_key, False
                for data, is_key in encoder.encode(frame, want_key):
                    self.frame_seq = (self.frame_seq + 1) & 0xFFFFFFFF
                    if encoder.name and encoder.name != getattr(self, "_enc_logged", None):
                        self._enc_logged = encoder.name
                        log.info("encoding with %s", encoder.name)
                    for pkt in P.build_video_packets(self.sealer, self.frame_seq, self.out_w, self.out_h, is_key, data):
                        try:
                            self.sock.sendto(pkt, self.client_addr)
                        except OSError:
                            break
                        self.stats["bytes"] += len(pkt)
                    self.stats["frames"] += 1
                    self._last_send = now
        finally:
            source.close()

    def _stats_loop(self):
        while not self.stop.is_set():
            time.sleep(2.0)
            if self.client_addr:
                fps = self.stats["frames"] / 2.0
                mbit = self.stats["bytes"] * 8 / 1e6 / 2.0
                log.info("streaming %.0f fps, %.1f Mbit/s, %d kbit/s target", fps, mbit, self.bitrate)
            self.stats["frames"] = 0
            self.stats["bytes"] = 0


def main():
    ap = argparse.ArgumentParser(description="Remotive Stream host (game streaming, UDP + FEC)")
    ap.add_argument("--port", type=int, default=47990)
    ap.add_argument("--monitor", type=int, default=1, help="1 = primary (0 = all monitors)")
    ap.add_argument("--width", type=int, default=1280, help="stream width (default 1280)")
    ap.add_argument("--height", type=int, default=720, help="stream height (default 720)")
    ap.add_argument("--fps", type=int, default=60)
    ap.add_argument("--bitrate", type=int, default=15000, help="max kbit/s (default 15000)")
    ap.add_argument("--no-adapt", action="store_true", help="don't auto-adjust bitrate on packet loss")
    ap.add_argument("--dry-run", action="store_true", help="log input instead of injecting it")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("comtypes").setLevel(logging.WARNING)

    password = os.environ.get("REMOTIVE_PASSWORD") or getpass.getpass("Stream password: ")
    if len(password) < 8:
        log.error("password must be at least 8 characters")
        sys.exit(2)
    answer = os.environ.get("REMOTIVE_ANSWER", "")
    key = P.derive_key(password, answer)
    del password

    rh.make_dpi_aware()
    if rh.bettercam is None:
        log.warning("bettercam not installed — capture will use slower GDI. pip install bettercam")
    if rh.av is None:
        log.error("PyAV not installed — needed for H.264. pip install av")
        sys.exit(2)

    host = StreamHost(key, args.port, args.monitor, args.width & ~1, args.height & ~1,
                      max(15, min(rh.MAX_FPS, args.fps)), args.bitrate, not args.no_adapt, args.dry_run)
    try:
        host.run()
    except KeyboardInterrupt:
        pass
    finally:
        host.injector.release_all()


if __name__ == "__main__":
    main()
