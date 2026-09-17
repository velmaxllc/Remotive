#!/usr/bin/env python3
"""Remoto Stream client — runs on the laptop you play from.

Receives FEC video shards over UDP, rebuilds and hardware-decodes each frame, and shows it in a
low-latency window. Captures your mouse (raw/relative, so games can look around) and keyboard and
sends them back over UDP. Point it at the host's LAN IP, or its Tailscale IP for playing over the internet.

    python client.py 192.168.1.50            # connect to the host at that IP
    python client.py 100.x.y.z --fps 60 --bitrate 15000 --fullscreen
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import queue as queue_mod
import socket
import sys
import threading
import time

import av
import numpy as np
import pygame

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol as P  # noqa: E402

log = logging.getLogger("stream-client")


def build_scancode_map():
    """pygame SDL scancode -> (key, JS-style code) so the host injects the right *physical* key."""
    m = {}
    for c in "abcdefghijklmnopqrstuvwxyz":
        sc = getattr(pygame, f"KSCAN_{c.upper()}", None)
        if sc is not None:
            m[sc] = (c, f"Key{c.upper()}")
    for d in "1234567890":
        sc = getattr(pygame, f"KSCAN_{d}", None)
        if sc is not None:
            m[sc] = (d, f"Digit{d}")
    for i in range(1, 13):
        sc = getattr(pygame, f"KSCAN_F{i}", None)
        if sc is not None:
            m[sc] = (f"F{i}", f"F{i}")
    named = {
        "SPACE": (" ", "Space"), "RETURN": ("Enter", "Enter"), "ESCAPE": ("Escape", "Escape"),
        "BACKSPACE": ("Backspace", "Backspace"), "TAB": ("Tab", "Tab"), "DELETE": ("Delete", "Delete"),
        "INSERT": ("Insert", "Insert"), "HOME": ("Home", "Home"), "END": ("End", "End"),
        "PAGEUP": ("PageUp", "PageUp"), "PAGEDOWN": ("PageDown", "PageDown"),
        "UP": ("ArrowUp", "ArrowUp"), "DOWN": ("ArrowDown", "ArrowDown"),
        "LEFT": ("ArrowLeft", "ArrowLeft"), "RIGHT": ("ArrowRight", "ArrowRight"),
        "LSHIFT": ("Shift", "ShiftLeft"), "RSHIFT": ("Shift", "ShiftRight"),
        "LCTRL": ("Control", "ControlLeft"), "RCTRL": ("Control", "ControlRight"),
        "LALT": ("Alt", "AltLeft"), "RALT": ("Alt", "AltRight"),
        "LGUI": ("Meta", "MetaLeft"), "RGUI": ("Meta", "MetaRight"),
        "MINUS": ("-", "Minus"), "EQUALS": ("=", "Equal"),
        "LEFTBRACKET": ("[", "BracketLeft"), "RIGHTBRACKET": ("]", "BracketRight"),
        "BACKSLASH": ("\\", "Backslash"), "SEMICOLON": (";", "Semicolon"),
        "APOSTROPHE": ("'", "Quote"), "GRAVE": ("`", "Backquote"),
        "COMMA": (",", "Comma"), "PERIOD": (".", "Period"), "SLASH": ("/", "Slash"),
        "CAPSLOCK": ("CapsLock", "CapsLock"),
    }
    for name, val in named.items():
        sc = getattr(pygame, f"KSCAN_{name}", None)
        if sc is not None:
            m[sc] = val
    return m


class StreamClient:
    def __init__(self, key: bytes, host_addr, fps: int, bitrate: int, win_w: int, win_h: int, fullscreen: bool):
        self.sealer = P.Sealer(key, P.AAD_C2H, P.AAD_H2C)
        self.host_addr = host_addr
        self.fps = fps
        self.bitrate = bitrate
        self.win_size = (win_w, win_h)
        self.fullscreen = fullscreen
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        self.reasm = P.FrameReassembler()
        self.decoder = av.CodecContext.create("h264", "r")
        self.decoder.open()
        self.decode_q: queue_mod.Queue = queue_mod.Queue(maxsize=3)
        self.synced = False
        self.request_key = True
        self.latest = None          # (rgb ndarray, w, h)
        self.latest_lock = threading.Lock()
        self.meta = None
        self.stop = threading.Event()
        # stats
        self.recv_frames = 0        # decoded frames in the last second (for the on-screen fps)
        self.reasm_total = 0        # frames successfully reassembled (monotonic)
        self.seq_hi = -1            # highest frame_seq for which any shard arrived
        self.last_gap_seq = -1

    # ---- network + decode thread -------------------------------------------

    def _net_loop(self):
        self.sock.settimeout(0.5)
        while not self.stop.is_set():
            try:
                data, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            body = self.sealer.open(data)
            if body is None:
                continue
            t = body[0]
            if t == P.T_VIDEO:
                self._on_video(body)
            elif t == P.T_META:
                self.meta = P.parse_meta(body)

    def _on_video(self, body: bytes):
        shard = P.parse_video(body)
        if shard is None:
            return
        self.seq_hi = max(self.seq_hi, shard.frame_seq)
        done = self.reasm.add(shard)
        if done is None:
            return
        self.reasm_total += 1
        frame_bytes, is_key = done
        # If we skipped past frames we never completed, the stream is out of sync -> ask for a keyframe.
        if self.last_gap_seq != -1 and shard.frame_seq > self.last_gap_seq + 1 and not is_key:
            self.request_key = True
        self.last_gap_seq = shard.frame_seq
        if not self.synced:
            if not is_key:
                self.request_key = True
                return
            self.synced = True
        # Hand off to the decode thread; if it is behind, drop the oldest so latency never piles up.
        try:
            self.decode_q.put_nowait((frame_bytes, is_key))
        except queue_mod.Full:
            try:
                self.decode_q.get_nowait()
            except queue_mod.Empty:
                pass
            try:
                self.decode_q.put_nowait((frame_bytes, is_key))
            except queue_mod.Full:
                pass

    def _decode_loop(self):
        while not self.stop.is_set():
            try:
                frame_bytes, is_key = self.decode_q.get(timeout=0.5)
            except queue_mod.Empty:
                continue
            try:
                for frame in self.decoder.decode(av.packet.Packet(frame_bytes)):
                    rgb = frame.to_ndarray(format="rgb24")
                    with self.latest_lock:
                        self.latest = (rgb, frame.width, frame.height)
                    self.recv_frames += 1
            except Exception as exc:
                log.debug("decode error: %s", exc)
                self.synced = False
                self.request_key = True

    def _send(self, body: bytes):
        try:
            self.sock.sendto(self.sealer.seal(body), self.host_addr)
        except OSError:
            pass

    # ---- main (pygame) loop -------------------------------------------------

    def run(self):
        pygame.init()
        pygame.display.set_caption("Remoto Stream")
        flags = pygame.FULLSCREEN | pygame.SCALED if self.fullscreen else pygame.RESIZABLE
        screen = pygame.display.set_mode(self.win_size, flags)
        scancodes = build_scancode_map()

        net = threading.Thread(target=self._net_loop, name="net", daemon=True)
        net.start()
        threading.Thread(target=self._decode_loop, name="decode", daemon=True).start()

        self._send(P.build_hello(self.fps, self.bitrate, *self.win_size))
        last_hello = last_feedback = last_fpscalc = time.monotonic()
        fb_prev_hi = fb_prev_reasm = 0
        event_id = 1
        move_dx = move_dy = 0
        wheel_x = wheel_y = 0
        grabbed = False
        recv_fps = 0
        font = pygame.font.SysFont("consolas", 16)
        show_stats = True
        clock = pygame.time.Clock()

        def win_center():
            w, h = pygame.display.get_surface().get_size()
            return w // 2, h // 2

        def set_grab(on):
            nonlocal grabbed
            grabbed = on
            pygame.event.set_grab(on)
            pygame.mouse.set_visible(not on)
            if on:
                pygame.mouse.set_pos(win_center())  # start centered so the first deltas are sane

        _shot = os.environ.get("REMOTO_TEST_SHOT")
        _deadline = time.monotonic() + float(os.environ.get("REMOTO_TEST_SECONDS", "0")) if _shot else None
        if not _shot:
            set_grab(True)

        def send_event(body):
            # discrete events (buttons/keys) are sent 3x for loss tolerance; the host dedups by id
            for _ in range(3):
                self._send(body)

        running = True
        while running and not self.stop.is_set():
            for e in pygame.event.get():
                if e.type == pygame.QUIT:
                    running = False
                elif e.type == pygame.MOUSEMOTION and grabbed:
                    cx, cy = win_center()
                    dx, dy = e.pos[0] - cx, e.pos[1] - cy
                    if dx or dy:
                        move_dx += dx
                        move_dy += dy
                        pygame.mouse.set_pos(cx, cy)
                elif e.type == pygame.MOUSEBUTTONDOWN and e.button in (1, 2, 3, 6, 7):
                    if not grabbed:
                        set_grab(True)
                    else:
                        send_event(P.in_button(event_id, {1: 0, 2: 1, 3: 2, 6: 3, 7: 4}[e.button], True)); event_id += 1
                elif e.type == pygame.MOUSEBUTTONUP and e.button in (1, 2, 3, 6, 7) and grabbed:
                    send_event(P.in_button(event_id, {1: 0, 2: 1, 3: 2, 6: 3, 7: 4}[e.button], False)); event_id += 1
                elif e.type == pygame.MOUSEWHEEL and grabbed:
                    wheel_x += e.x
                    wheel_y += e.y
                elif e.type == pygame.KEYDOWN:
                    if e.key == pygame.K_ESCAPE and grabbed:
                        set_grab(False)  # release the mouse to reach the desktop / close
                        continue
                    if e.scancode in scancodes:
                        key, code = scancodes[e.scancode]
                        send_event(P.in_key(event_id, True, code, key)); event_id += 1
                    if e.key == pygame.K_F11:
                        self._toggle_fullscreen()
                    elif e.key == pygame.K_F9:
                        show_stats = not show_stats
                elif e.type == pygame.KEYUP and e.scancode in scancodes:
                    key, code = scancodes[e.scancode]
                    send_event(P.in_key(event_id, False, code, key)); event_id += 1

            now = time.monotonic()
            if move_dx or move_dy:
                self._send(P.in_move(move_dx, move_dy)); move_dx = move_dy = 0
            if wheel_x or wheel_y:
                self._send(P.in_wheel(wheel_x * 120, wheel_y * 120)); wheel_x = wheel_y = 0
            if now - last_hello > 1.0:
                last_hello = now
                self._send(P.build_hello(self.fps, self.bitrate, *pygame.display.get_surface().get_size()))
            if now - last_feedback > 0.25:
                expected = self.seq_hi - fb_prev_hi
                got = self.reasm_total - fb_prev_reasm
                loss = max(0, min(1000, int((1 - got / expected) * 1000))) if expected >= 4 else 0
                fb_prev_hi, fb_prev_reasm, last_feedback = self.seq_hi, self.reasm_total, now
                self._send(P.build_feedback(recv_fps, loss, self.request_key, self.bitrate, self.fps))
                self.request_key = False
            if now - last_fpscalc >= 1.0:
                recv_fps = self.recv_frames
                self.recv_frames = 0
                last_fpscalc = now

            self._blit(screen, font if show_stats else None, recv_fps)
            clock.tick(self.fps + 5)
            if _deadline and time.monotonic() >= _deadline:
                pygame.image.save(screen, _shot)
                running = False

        self._send(bytes([P.T_BYE]))
        self.stop.set()
        pygame.quit()

    def _blit(self, screen, font, recv_fps):
        with self.latest_lock:
            latest = self.latest
        screen.fill((0, 0, 0))
        if latest is not None:
            rgb, w, h = latest
            surf = pygame.image.frombuffer(np.ascontiguousarray(rgb).tobytes(), (w, h), "RGB")
            sw, sh = screen.get_size()
            scale = min(sw / w, sh / h)
            dw, dh = int(w * scale), int(h * scale)
            surf = pygame.transform.smoothscale(surf, (dw, dh))
            screen.blit(surf, ((sw - dw) // 2, (sh - dh) // 2))
        elif font:
            screen.blit(font.render("waiting for the host video...", True, (200, 200, 200)), (20, 20))
        if font:
            enc = self.meta.get("enc", "?") if self.meta else "?"
            txt = f"{recv_fps} fps  {self.bitrate} kbit/s  {enc}   [Esc release mouse  F11 fullscreen  F9 stats]"
            label = font.render(txt, True, (120, 255, 160))
            screen.blit(label, (10, screen.get_size()[1] - 24))
        pygame.display.flip()

    def _toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        size = pygame.display.get_desktop_sizes()[0] if self.fullscreen else self.win_size
        flags = (pygame.FULLSCREEN | pygame.SCALED) if self.fullscreen else pygame.RESIZABLE
        pygame.display.set_mode(size, flags)


def main():
    ap = argparse.ArgumentParser(description="Remoto Stream client (game streaming, UDP + FEC)")
    ap.add_argument("host", help="host IP (LAN address, or Tailscale 100.x.y.z)")
    ap.add_argument("--port", type=int, default=47990)
    ap.add_argument("--fps", type=int, default=60)
    ap.add_argument("--bitrate", type=int, default=15000, help="requested max kbit/s")
    ap.add_argument("--width", type=int, default=1280, help="window width")
    ap.add_argument("--height", type=int, default=720, help="window height")
    ap.add_argument("--fullscreen", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")

    password = os.environ.get("REMOTO_PASSWORD") or getpass.getpass("Stream password: ")
    answer = os.environ.get("REMOTO_ANSWER", "")
    key = P.derive_key(password, answer)
    del password

    client = StreamClient(key, (args.host, args.port), max(15, args.fps), args.bitrate,
                          args.width, args.height, args.fullscreen)
    log.info("connecting to %s:%d — Esc releases the mouse, F11 fullscreen, close the window to quit", args.host, args.port)
    try:
        client.run()
    except KeyboardInterrupt:
        client.stop.set()


if __name__ == "__main__":
    main()
