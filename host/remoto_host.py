#!/usr/bin/env python3
"""Remoto host agent.

Runs on the desktop you want to control. Captures the screen (only the regions
that changed), encrypts every message end-to-end with a key derived from your
password, and pushes it to the Remoto relay on Cloudflare Workers. Input events
coming back from the viewer are decrypted, validated and injected with pynput.

Usage:
    python remoto_host.py --url https://remoto.<you>.workers.dev
    python remoto_host.py --print-hash          # AUTH_HASH for the relay secrets
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import getpass
import hashlib
import io
import json
import logging
import os
import re
import secrets
import socket
import struct
import sys
import queue as queue_mod
import threading
import time
from collections import deque

import mss
import numpy as np
import websockets
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image
from pynput import keyboard, mouse
from pynput.keyboard import Key, KeyCode
from pynput.mouse import Button

if sys.platform == "win32":
    # Games read raw mouse deltas; SetCursorPos (what pynput uses) never produces them, SendInput does.
    from pynput._util.win32 import INPUT, INPUT_union, MOUSEINPUT, SendInput
    from ctypes import wintypes

    class CURSORINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD),
                    ("hCursor", wintypes.HANDLE), ("ptScreenPos", wintypes.POINT)]

    def cursor_state() -> tuple[int, int, bool]:
        """(x, y, hidden). hidden = a game/app has hidden the cursor, i.e. it wants raw mouse motion."""
        info = CURSORINFO()
        info.cbSize = ctypes.sizeof(CURSORINFO)
        if not ctypes.windll.user32.GetCursorInfo(ctypes.byref(info)):
            raise OSError("GetCursorInfo failed")
        return info.ptScreenPos.x, info.ptScreenPos.y, (info.flags & 1) == 0  # CURSOR_SHOWING == 1

    # --- Cursor compositing: DXGI/GDI capture never includes the mouse, so we draw the real cursor
    #     bitmap onto each frame ourselves (same as Sunshine/Moonlight). --------------------------
    _user32 = ctypes.windll.user32
    _gdi32 = ctypes.windll.gdi32

    # Declare handle-returning/handle-taking prototypes so 64-bit handles are not truncated.
    _H = ctypes.c_void_p
    _user32.GetDC.restype = _H
    _user32.GetDC.argtypes = [_H]
    _user32.ReleaseDC.argtypes = [_H, _H]
    _user32.GetIconInfo.restype = wintypes.BOOL
    _user32.GetIconInfo.argtypes = [_H, ctypes.c_void_p]
    _user32.DrawIconEx.restype = wintypes.BOOL
    _user32.DrawIconEx.argtypes = [_H, ctypes.c_int, ctypes.c_int, _H, ctypes.c_int, ctypes.c_int,
                                   wintypes.UINT, _H, wintypes.UINT]
    _gdi32.CreateCompatibleDC.restype = _H
    _gdi32.CreateCompatibleDC.argtypes = [_H]
    _gdi32.CreateDIBSection.restype = _H
    _gdi32.CreateDIBSection.argtypes = [_H, ctypes.c_void_p, wintypes.UINT, ctypes.POINTER(ctypes.c_void_p), _H, wintypes.DWORD]
    _gdi32.SelectObject.restype = _H
    _gdi32.SelectObject.argtypes = [_H, _H]
    _gdi32.DeleteObject.argtypes = [_H]
    _gdi32.DeleteDC.argtypes = [_H]
    _gdi32.PatBlt.argtypes = [_H, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.DWORD]

    class _ICONINFO(ctypes.Structure):
        _fields_ = [("fIcon", wintypes.BOOL), ("xHotspot", wintypes.DWORD), ("yHotspot", wintypes.DWORD),
                    ("hbmMask", ctypes.c_void_p), ("hbmColor", ctypes.c_void_p)]

    class _BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]

    _cursor_cache: dict = {}   # hCursor handle -> (sprite_bgra HxWx4 with alpha, xhot, yhot)

    def _cursor_sprite(hcursor):
        """Return (BGRA sprite with straight alpha, xhot, yhot) for a cursor handle, cached."""
        cached = _cursor_cache.get(hcursor)
        if cached is not None:
            return cached
        import numpy as _np
        info = _ICONINFO()
        if not _user32.GetIconInfo(hcursor, ctypes.byref(info)):
            _cursor_cache[hcursor] = None
            return None
        for hbm in (info.hbmMask, info.hbmColor):
            pass
        size = 32
        screen_dc = _user32.GetDC(0)
        mem_dc = _gdi32.CreateCompatibleDC(screen_dc)
        bmi = _BITMAPINFOHEADER()
        bmi.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
        bmi.biWidth = size
        bmi.biHeight = -size   # top-down
        bmi.biPlanes = 1
        bmi.biBitCount = 32
        bmi.biCompression = 0  # BI_RGB
        bits = ctypes.c_void_p()
        dib = _gdi32.CreateDIBSection(screen_dc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
        old = _gdi32.SelectObject(mem_dc, dib)
        # Draw twice to detect the alpha: on black and on white, so we can recover coverage for
        # legacy cursors that don't carry an alpha channel.
        sprite = None
        try:
            _gdi32.PatBlt(mem_dc, 0, 0, size, size, 0x000042)  # BLACKNESS
            _user32.DrawIconEx(mem_dc, 0, 0, hcursor, size, size, 0, None, 0x0003)  # DI_NORMAL
            buf_black = (ctypes.c_ubyte * (size * size * 4)).from_address(bits.value)
            on_black = _np.frombuffer(bytes(buf_black), _np.uint8).reshape(size, size, 4).copy()
            _gdi32.PatBlt(mem_dc, 0, 0, size, size, 0xFF0062)  # WHITENESS
            _user32.DrawIconEx(mem_dc, 0, 0, hcursor, size, size, 0, None, 0x0003)
            buf_white = (ctypes.c_ubyte * (size * size * 4)).from_address(bits.value)
            on_white = _np.frombuffer(bytes(buf_white), _np.uint8).reshape(size, size, 4).copy()
            # alpha = 255 - (white_result - black_result)  (per channel, they agree where opaque)
            diff = on_white[:, :, :3].astype(_np.int16) - on_black[:, :, :3].astype(_np.int16)
            alpha = 255 - diff.mean(axis=2).clip(0, 255).astype(_np.uint8)
            # color = the value drawn on black (that IS colour*alpha for straight compositing)
            sprite = _np.dstack([on_black[:, :, :3], alpha]).astype(_np.uint8)
            # crop to the used bounding box to keep compositing cheap
            ys, xs = _np.where(alpha > 8)
            if len(ys):
                sprite = sprite[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
            else:
                sprite = None
        except Exception:
            sprite = None
        finally:
            _gdi32.SelectObject(mem_dc, old)
            _gdi32.DeleteObject(dib)
            _gdi32.DeleteDC(mem_dc)
            _user32.ReleaseDC(0, screen_dc)
            if info.hbmMask:
                _gdi32.DeleteObject(info.hbmMask)
            if info.hbmColor:
                _gdi32.DeleteObject(info.hbmColor)
        result = None if sprite is None else (sprite, int(info.xHotspot), int(info.yHotspot))
        if len(_cursor_cache) > 64:
            _cursor_cache.clear()
        _cursor_cache[hcursor] = result
        return result

    def composite_cursor(frame_bgra, mon: dict) -> None:
        """Blend the current mouse cursor onto a BGRA frame in place (no-op when the cursor is hidden)."""
        info = CURSORINFO()
        info.cbSize = ctypes.sizeof(CURSORINFO)
        if not _user32.GetCursorInfo(ctypes.byref(info)) or not (info.flags & 1) or not info.hCursor:
            return
        sp = _cursor_sprite(info.hCursor)
        if not sp:
            return
        sprite, xhot, yhot = sp
        x = info.ptScreenPos.x - mon["left"] - xhot
        y = info.ptScreenPos.y - mon["top"] - yhot
        h, w = sprite.shape[:2]
        fh, fw = frame_bgra.shape[:2]
        x0, y0 = max(0, x), max(0, y)
        x1, y1 = min(fw, x + w), min(fh, y + h)
        if x0 >= x1 or y0 >= y1:
            return
        sx0, sy0 = x0 - x, y0 - y
        spr = sprite[sy0:sy0 + (y1 - y0), sx0:sx0 + (x1 - x0)]
        alpha = spr[:, :, 3:4].astype(np.float32) / 255.0
        region = frame_bgra[y0:y1, x0:x1, :3].astype(np.float32)
        frame_bgra[y0:y1, x0:x1, :3] = (region * (1 - alpha) + spr[:, :, :3].astype(np.float32) * alpha).astype(np.uint8)
else:
    def composite_cursor(frame_bgra, mon: dict) -> None:
        return

log = logging.getLogger("remoto")
MSS = getattr(mss, "MSS", None) or mss.mss  # mss 10 renamed the class

try:
    import av  # PyAV: ffmpeg encoders (h264_nvenc / amf / qsv / libx264) for the video stream
    from fractions import Fraction
except Exception:
    av = None

bettercam = None
if sys.platform == "win32":
    try:
        import bettercam  # DXGI desktop duplication: GPU capture, returns only changed frames
    except Exception:  # not installed / unsupported GPU driver -> GDI capture via mss
        bettercam = None

PBKDF2_ITERATIONS = 200_000
AAD_H2V = b"remoto-v1:h2v"  # host -> viewer
AAD_V2H = b"remoto-v1:v2h"  # viewer -> host
MSG_FRAME = 0x01           # JPEG regions
MSG_JSON = 0x02
MSG_VIDEO = 0x03           # one H.264 access unit (Annex B), flags bit0 = keyframe

TILE = 32                  # diff granularity in pixels
# Adaptive quality ladder (scale multiplier, JPEG quality), best first. The host steps down when the link
# can't carry the target frame rate at the current size and back up when there's headroom.
LADDER = [(1.0, 75), (1.0, 60), (1.0, 45), (0.75, 50), (0.75, 40), (0.5, 45), (0.5, 35), (0.5, 28), (0.4, 28), (0.3, 25)]
# Video (H.264) bitrate ladder in kbit/s, best first. Used instead of LADDER when the viewer can decode video.
VIDEO_LADDER = [80000, 50000, 35000, 25000, 18000, 12000, 8000, 5000, 3000, 2000, 1200]
VIDEO_START_LEVEL = 4
VIDEO_SCALES = [1.0, 0.75, 0.5, 0.375]   # resolution steps for video, chosen by capture/encode cost
# No point sending 1440p into a thin uplink: cap the resolution by the bitrate the link sustains.
VIDEO_SCALE_FOR_KBPS = [(18000, 1.0), (10000, 0.85), (5000, 0.66), (2500, 0.5), (0, 0.375)]
VIDEO_ENCODERS = ["h264_nvenc", "h264_amf", "h264_qsv", "libx264"]  # hardware first, software last
TARGET_EXCESS_S = 0.10     # acceptable queueing delay above the baseline round trip
STEP_DOWN_EXCESS_S = 0.25  # step to a cheaper level immediately above this
MAX_MESSAGE = 900_000      # stay under the 1 MiB Workers WebSocket limit
# Flow control: frames in flight are limited by a bytes window that adapts to the link (AIMD), so a long
# round trip through the relay doesn't cap the frame rate the way a fixed 2-frame limit did.
MIN_IN_FLIGHT_FRAMES = 2
MAX_IN_FLIGHT_FRAMES = 16
WINDOW_START = 1_500_000
WINDOW_MIN, WINDOW_MAX = 400_000, 16_000_000
AUTO_MAX_WIDTH = 1600      # "auto" resolution: downscale wider screens to this
DEFAULT_FPS = 30
MAX_FPS = 60
REPLAY_WINDOW_S = 30       # reject viewer messages older/newer than this
CLOCK_SKEW_LOG_EVERY_S = 10


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def normalize_answer(answer: str) -> str:
    """Same normalization as the viewer: trim, lowercase, collapse whitespace."""
    return " ".join(answer.strip().lower().split())


def derive_keys(password: str, answer: str) -> tuple[str, bytes]:
    """Return (auth_key_hex, enc_key). Same derivation as the browser viewer:
    the password and the security answer together are the secret."""
    pw = f"{password}\n{normalize_answer(answer)}".encode("utf-8")
    auth = hashlib.pbkdf2_hmac("sha256", pw, b"remoto:auth:v1", PBKDF2_ITERATIONS, 32)
    enc = hashlib.pbkdf2_hmac("sha256", pw, b"remoto:enc:v1", PBKDF2_ITERATIONS, 32)
    return auth.hex(), enc


def auth_hash(auth_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(auth_key_hex)).hexdigest()


# ---------------------------------------------------------------------------
# Screen capture (dedicated thread)
# ---------------------------------------------------------------------------

class Settings:
    """Capture settings and link state shared between the asyncio loop and the capture thread."""

    def __init__(self, monitor: int, quality: int, fps: int, scale, max_fps: int = MAX_FPS):
        self.lock = threading.Lock()
        self.monitor = monitor
        self.quality = quality
        self.max_fps = max(1, min(MAX_FPS, max_fps))
        self.fps = max(1, min(fps, self.max_fps))   # target frame rate (viewer can change it)
        self.scale = scale          # float or "auto"
        self.auto_quality = True    # adapt scale/quality to the link (viewer "Auto" quality)
        self.level = 1              # index into the active ladder (LADDER for jpeg, VIDEO_LADDER for h264)
        self.codec = "jpeg"         # "jpeg" or "h264" (what the viewer can decode, if an encoder exists)
        self.vscale = 0             # index into VIDEO_SCALES (video resolution step, driven by pipeline cost)
        self.last_vscale = 0.0
        self.cheap_since = None
        self.encoder_name = None    # e.g. "h264_nvenc" once the video encoder is opened
        self.keyframe = True
        self.active = False         # at least one viewer connected
        # flow control (goodput-based, BBR-style)
        self.in_flight_frames = 0
        self.in_flight_bytes = 0
        self.window = WINDOW_START  # bytes allowed in flight
        self.sent_at: dict[int, tuple[float, int]] = {}   # seq -> (send time, bytes)
        self.sent_times: deque = deque()                  # send timestamps in the last second
        self.acked_total = 0                              # cumulative acknowledged bytes
        self.delivered: deque = deque()                   # (time, acked_total) samples
        self.bw_samples: deque = deque()                  # (time, bytes/s) delivery-rate samples
        self.bw_bps = 250_000.0     # estimated deliverable throughput, bytes/s (start ~2 Mbit)
        self.srtt = None            # smoothed round trip
        self.rtt_samples: deque = deque()                 # (time, rtt) for the min over a window
        self.last_ack = time.monotonic()
        self.blocked_at = 0.0
        # quality controller
        self.last_step = 0.0
        self.last_step_up = 0.0
        self.good_since = None
        self.ceiling = 0            # lowest LADDER index allowed for a while after a failed step up
        self.ceiling_until = 0.0
        self.frame_cost = 0.0       # median seconds per frame: max(capture-side, encode-side) since they overlap
        self.cost_hist: deque = deque(maxlen=9)
        self.cost_samples = 0
        self.vscale_floor = 0       # lowest video scale index allowed while a reverted step-up is remembered
        self.vscale_floor_until = 0.0
        self.last_vscale_up = 0.0

    def ladder(self):
        return VIDEO_LADDER if self.codec == "h264" else LADDER

    def set_codec(self, codec: str):
        if codec != self.codec:
            self.codec = codec
            self.level = VIDEO_START_LEVEL if codec == "h264" else 1
            self.vscale = 0
            self.ceiling = 0
            with self.lock:
                self.keyframe = True

    def effective(self, screen_w: int):
        """jpeg: (scale factor, quality). h264: (scale factor, kbit/s).
        Video defaults to native resolution — a hardware encoder handles it and the bitrate does the adapting."""
        if self.codec == "h264":
            hw = self.encoder_name not in (None, "libx264")
            base = (1.0 if hw else min(1.0, AUTO_MAX_WIDTH / screen_w)) if self.scale == "auto" else float(self.scale)
            if self.auto_quality:
                kbps = VIDEO_LADDER[self.level]
            else:
                # Pinned: the slider sets a ceiling, but the link still caps it so it can't flood/stall.
                pinned = max(1500, min(50000, self.quality * 300))
                link_kbps = self.bw_bps * 8 / 1000 * 0.85
                kbps = int(max(1500, min(pinned, max(link_kbps, 1500))))
            link_cap = next(sc for floor, sc in VIDEO_SCALE_FOR_KBPS if kbps >= floor)
            vs = VIDEO_SCALES[self.vscale] if self.auto_quality else 1.0
            return base * min(vs, link_cap), kbps
        base = min(1.0, AUTO_MAX_WIDTH / screen_w) if self.scale == "auto" else float(self.scale)
        if self.auto_quality:
            mult, q = LADDER[self.level]
            return base * mult, q
        return base, self.quality

    def snapshot(self):
        with self.lock:
            kf, self.keyframe = self.keyframe, False
            return self.monitor, self.fps, kf, self.active

    # -- flow control ------------------------------------------------------------

    def can_send(self) -> bool:
        now = time.monotonic()
        if self.in_flight_frames and now - self.last_ack > 3:
            self.reset_flow()  # acks stopped (viewer vanished mid-stream); never stall forever
        if self.in_flight_frames < MIN_IN_FLIGHT_FRAMES:
            return True
        if self.in_flight_frames >= MAX_IN_FLIGHT_FRAMES or self.in_flight_bytes >= self.window:
            self.blocked_at = now
            return False
        return True

    def reset_flow(self):
        self.in_flight_frames = 0
        self.in_flight_bytes = 0
        self.sent_at.clear()
        self.delivered.clear()
        self.srtt = None
        self.frame_cost = 0.0
        self.cost_hist.clear()
        self.cost_samples = 0

    @property
    def bw_mbit(self) -> float:
        return self.bw_bps * 8 / 1e6

    def sent(self, seq: int, nbytes: int):
        now = time.monotonic()
        self.sent_at[seq] = (now, nbytes)
        self.in_flight_frames += 1
        self.in_flight_bytes += nbytes
        self.sent_times.append(now)
        while self.sent_times and now - self.sent_times[0] > 1.0:
            self.sent_times.popleft()
        if len(self.sent_at) > 4 * MAX_IN_FLIGHT_FRAMES:
            self.reset_flow()

    def on_ack(self, seq: int):
        """BBR-style estimator. Acks are cumulative (the viewer coalesces them), so seq N also
        acknowledges everything sent before it. We estimate the deliverable bandwidth from how fast bytes
        are acknowledged and the round-trip inflation, then size the window and pick the bitrate to match."""
        now = time.monotonic()
        self.last_ack = now
        acked = 0
        sent = self.sent_at.pop(seq, None)
        if sent is not None:
            acked += sent[1]
            self.in_flight_frames = max(0, self.in_flight_frames - 1)
            self.in_flight_bytes = max(0, self.in_flight_bytes - sent[1])
        for k in [k for k in self.sent_at if (seq - k) & 0xFFFFFFFF < 0x7FFFFFFF]:
            older = self.sent_at.pop(k)
            acked += older[1]
            self.in_flight_frames = max(0, self.in_flight_frames - 1)
            self.in_flight_bytes = max(0, self.in_flight_bytes - older[1])
        if sent is None:
            return

        rtt = now - sent[0]
        self.srtt = rtt if self.srtt is None else 0.9 * self.srtt + 0.1 * rtt
        self.rtt_samples.append((now, rtt))
        while self.rtt_samples and now - self.rtt_samples[0][0] > 10:
            self.rtt_samples.popleft()
        min_rtt = min(r for _, r in self.rtt_samples) if self.rtt_samples else rtt

        # Delivery rate: acked bytes over the span they arrived in (a lower-bound on link bandwidth).
        self.acked_total += acked
        self.delivered.append((now, self.acked_total))
        while self.delivered and now - self.delivered[0][0] > 0.5:
            self.delivered.popleft()
        if len(self.delivered) >= 2:
            span = now - self.delivered[0][0]
            if span > 0.05:
                rate = (self.acked_total - self.delivered[0][1]) / span
                # Trust the sample whenever there was a real backlog to drain (so it can ratchet up).
                if self.in_flight_bytes > 0.25 * self.window or now - self.blocked_at < 0.5:
                    self.bw_samples.append((now, rate))
        while self.bw_samples and now - self.bw_samples[0][0] > 4.0:
            self.bw_samples.popleft()
        if self.bw_samples:
            peak = max(r for _, r in self.bw_samples)
            # Rise fast toward a new peak, fall slowly (BBR-like): favours using all the headroom there is.
            self.bw_bps = max(peak, 0.9 * self.bw_bps + 0.1 * peak)

        queue = self.srtt - min_rtt          # standing queue delay = congestion signal
        # Throughput-first: keep ~2 bandwidth-delay products in flight so the pipe stays full; only pull
        # back when the queue gets genuinely large (a relay always adds some baseline buffering).
        bdp = self.bw_bps * max(min_rtt, 0.03) * 2.0
        self.window = int(min(WINDOW_MAX, max(WINDOW_MIN, bdp)))
        if queue > 0.5:                       # severe backlog only: ease off a little
            self.window = int(max(WINDOW_MIN, self.window * 0.8))

        if not self.auto_quality:
            return
        self._pick_bitrate(now, queue)

    def _pick_bitrate(self, now: float, queue: float):
        """Bandwidth-first: aim the bitrate straight at ~90% of the measured throughput so the link is
        actually used. A large standing queue only trims it a little (this path always buffers some)."""
        if now > self.ceiling_until:
            self.ceiling = 0
        headroom = 0.75 if queue > 0.6 else 0.9   # only ease off when the backlog is really large
        target_kbps = self.bw_bps * 8 / 1000 * headroom
        ladder = self.ladder()
        if self.codec == "h264":
            want = next((i for i, kb in enumerate(ladder) if kb <= target_kbps), len(ladder) - 1)
        else:
            want = self.level + (1 if queue > STEP_DOWN_EXCESS_S else -1 if queue < TARGET_EXCESS_S else 0)
        want = max(self.ceiling, min(len(ladder) - 1, want))
        # Move toward the bandwidth target promptly in either direction (the user wants the link used).
        if want > self.level and now - self.last_step > 0.4:
            self.level += 1
            self.last_step = now
            self.good_since = None
            if now - self.last_step_up < 3:
                self.ceiling, self.ceiling_until = min(len(ladder) - 1, self.level), now + 15
            log.debug("bandwidth ~%.1f Mbit/s -> lower quality, level %d (%s)", self.bw_mbit, self.level, ladder[self.level])
        elif want < self.level and now - self.last_step > 0.6:
            self.level -= 1
            self.last_step = self.last_step_up = now
            self.good_since = None
            log.debug("bandwidth ~%.1f Mbit/s -> higher quality, level %d (%s)", self.bw_mbit, self.level, ladder[self.level])
            self.last_step = self.last_step_up = now
            self.good_since = None
            log.debug("headroom (~%.1f Mbit/s) -> level %d (%s)", self.bw_mbit, self.level, ladder[self.level])

    def note_frame_cost(self, seconds: float):
        """Steps quality down when the capture/encode pipeline itself can't reach the target fps."""
        self.cost_samples += 1
        if self.cost_samples <= 2:  # cold start (first grab, allocations) is not representative
            return
        self.cost_hist.append(seconds)
        self.frame_cost = sorted(self.cost_hist)[len(self.cost_hist) // 2]  # median: immune to single spikes
        now = time.monotonic()
        if self.cost_samples < 6 or not self.auto_quality:
            return
        budget = 1.0 / max(1, self.fps)
        if self.codec == "h264":
            # Bitrate doesn't change how long a frame takes to produce; resolution does.
            if now > self.vscale_floor_until:
                self.vscale_floor = 0
            if self.frame_cost > 0.9 * budget and now - self.last_vscale > 2.0 and self.vscale < len(VIDEO_SCALES) - 1:
                self.vscale += 1
                if now - self.last_vscale_up < 6.0:   # the step up didn't hold: stay here for a while
                    self.vscale_floor, self.vscale_floor_until = self.vscale, now + 30.0
                self.last_vscale = now
                self.cheap_since = None
                self.cost_hist.clear()
                log.info("capture+encode %.0f ms > budget for %d fps -> video scale %.0f%%", self.frame_cost * 1000, self.fps, VIDEO_SCALES[self.vscale] * 100)
            elif self.frame_cost < 0.45 * budget:
                self.cheap_since = self.cheap_since or now
                if now - self.cheap_since > 5.0 and now - self.last_vscale > 5.0 and self.vscale > self.vscale_floor:
                    self.vscale -= 1
                    self.last_vscale = self.last_vscale_up = now
                    self.cheap_since = None
                    self.cost_hist.clear()
                    log.info("pipeline has headroom -> video scale %.0f%%", VIDEO_SCALES[self.vscale] * 100)
            else:
                self.cheap_since = None
        elif self.frame_cost > 0.9 * budget and now - self.last_step > 1.0:
            self._step_down(now, "capture+encode takes %.0f ms, too slow for %d fps" % (self.frame_cost * 1000, self.fps))

    def _step_down(self, now: float, why: str):
        if self.level >= len(self.ladder()) - 1:
            return
        if now - self.last_step_up < 4:  # a recent step up clearly didn't hold: pin a floor for a while
            self.ceiling, self.ceiling_until = min(len(self.ladder()) - 1, self.level + 1), now + 20
        self.last_step = now
        self.good_since = None
        log.debug("%s", why)


class ScreenSource:
    """Grabs a monitor as a BGRA (H, W, 4) numpy array — the screen's native layout, which the video
    encoder takes as-is. Windows: DXGI desktop duplication (GPU; returns None when nothing changed).
    Fallback and "all monitors": GDI via mss."""

    def __init__(self, monitors: list[dict]):
        self.monitors = monitors
        self.sct = None
        self.cams: dict[int, object] = {}
        self.dxgi_ok = bettercam is not None
        self.dxgi_failures = 0

    def grab(self, mon_idx: int, mon: dict):
        if self.dxgi_ok and mon_idx >= 1:
            try:
                cam = self.cams.get(mon_idx) or self._open_cam(mon_idx, mon)
                frame = cam.grab()
                if frame is None:
                    return None
                return frame if frame.flags.c_contiguous else np.ascontiguousarray(frame)
            except Exception as exc:
                self.dxgi_failures += 1
                self.cams.pop(mon_idx, None)
                if self.dxgi_failures > 3:
                    self.dxgi_ok = False
                    log.warning("DXGI capture keeps failing (%s); using GDI capture", exc)
                else:
                    log.debug("DXGI capture hiccup: %s", exc)
        if self.sct is None:
            self.sct = MSS()
        shot = self.sct.grab(mon)
        return np.frombuffer(shot.bgra, dtype=np.uint8).reshape(shot.height, shot.width, 4)

    def _open_cam(self, mon_idx: int, mon: dict):
        outputs = []
        for m in re.finditer(r"Device\[(\d+)\] Output\[(\d+)\]: Res:\((\d+), (\d+)\) Rot:(\d+) Primary:(True|False)", bettercam.output_info()):
            outputs.append({"device": int(m[1]), "output": int(m[2]), "w": int(m[3]), "h": int(m[4]), "primary": m[6] == "True"})
        same_size = [o for o in outputs if (o["w"], o["h"]) == (mon["width"], mon["height"])]
        if mon_idx == 1:
            pick = next((o for o in same_size if o["primary"]), None) or next((o for o in outputs if o["primary"]), None)
        else:
            used = {(c.device_idx, c.output_idx) for c in self.cams.values() if hasattr(c, "device_idx")}
            pick = next((o for o in same_size if not o["primary"] and (o["device"], o["output"]) not in used), None)
        if pick is None:
            raise RuntimeError("no matching DXGI output for monitor %d" % mon_idx)
        cam = bettercam.create(device_idx=pick["device"], output_idx=pick["output"], output_color="BGRA")
        cam.device_idx, cam.output_idx = pick["device"], pick["output"]
        self.cams[mon_idx] = cam
        log.info("capturing monitor %d via DXGI (%dx%d)", mon_idx, pick["w"], pick["h"])
        return cam

    def close(self):
        for cam in self.cams.values():
            try:
                cam.release()
            except Exception:
                pass
        self.cams.clear()
        if self.sct is not None:
            self.sct.close()


class VideoEncoder:
    """H.264 encoder (hardware when available) producing one Annex B access unit per frame."""

    def __init__(self):
        self.ctx = None
        self.name = None
        self.params = None       # (w, h, fps, kbps)
        self.pts = 0
        self.sw_only = False

    @staticmethod
    def available() -> bool:
        return av is not None

    def _open(self, name: str, w: int, h: int, fps: int, kbps: int):
        ctx = av.CodecContext.create(name, "w")
        ctx.width, ctx.height = w, h
        ctx.pix_fmt = "yuv420p" if name == "libx264" else "bgra"
        ctx.time_base = Fraction(1, fps)
        ctx.framerate = Fraction(fps, 1)
        ctx.bit_rate = kbps * 1000
        ctx.gop_size = fps * 10        # keyframes mostly on demand (viewer join / recovery)
        ctx.max_b_frames = 0
        # VBV of ~2 frames: no frame (keyframes included) can spike far above bitrate/fps, so a keyframe
        # never stalls a thin uplink and frame sizes stay even (same idea as Sunshine's single-frame VBV).
        vbv = {"maxrate": f"{kbps}k", "bufsize": f"{max(64, kbps * 2 // fps)}k"}
        if name == "h264_nvenc":
            ctx.options = {"preset": "p1", "tune": "ull", "rc": "cbr", "zerolatency": "1", "delay": "0",
                           "profile": "high", "forced-idr": "1", "repeat_headers": "1", **vbv}
        elif name == "h264_amf":
            ctx.options = {"usage": "ultralowlatency", "rc": "cbr", "profile": "high", "header_insertion_mode": "idr", **vbv}
        elif name == "h264_qsv":
            ctx.options = {"preset": "veryfast", "profile": "high", "look_ahead": "0", **vbv}
        else:
            ctx.options = {"preset": "ultrafast", "tune": "zerolatency", "profile": "baseline", **vbv}
        ctx.open()
        return ctx

    def ensure(self, w: int, h: int, fps: int, kbps: int) -> bool:
        """(Re)open the encoder if size/fps/bitrate changed. Hardware encoders force a keyframe on a bitrate
        change anyway; reopening also resizes the VBV so that keyframe stays tiny.
        Returns True when a new stream started (the next frame is a keyframe)."""
        params = (w, h, fps, kbps)
        if self.ctx is not None and params == self.params:
            return False
        self.close()
        candidates = ["libx264"] if self.sw_only else VIDEO_ENCODERS
        for name in candidates:
            try:
                self.ctx = self._open(name, w, h, fps, kbps)
                self.name = name
                self.params = params
                self.pts = 0
                return True
            except Exception as exc:
                log.debug("encoder %s unavailable: %s", name, exc)
        raise RuntimeError("no H.264 encoder could be opened")

    @staticmethod
    def prepare(arr_bgra: np.ndarray, w: int, h: int, pix_fmt: str = "bgra"):
        """Wrap a BGRA screen grab as a frame (zero-copy), scaling/converting only when needed.
        Runs on the capture thread so it overlaps with encoding."""
        frame = av.VideoFrame.from_numpy_buffer(arr_bgra, format="bgra")
        if arr_bgra.shape[1] != w or arr_bgra.shape[0] != h or pix_fmt != "bgra":
            frame = frame.reformat(width=w, height=h, format=pix_fmt, interpolation="FAST_BILINEAR")
        return frame

    def encode(self, frame, force_key: bool) -> list[tuple[bytes, bool]]:
        if frame.format.name != self.ctx.pix_fmt or frame.width != self.params[0] or frame.height != self.params[1]:
            frame = frame.reformat(width=self.params[0], height=self.params[1], format=self.ctx.pix_fmt, interpolation="FAST_BILINEAR")
        frame.pts = self.pts
        self.pts += 1
        if force_key:
            frame.pict_type = av.video.frame.PictureType.I
        out = []
        for pkt in self.ctx.encode(frame):
            out.append((bytes(pkt), bool(pkt.is_keyframe)))
        return out

    def close(self):
        self.ctx = None  # PyAV frees the encoder when the context is dropped
        self.params = None


def pack_video(seq: int, w: int, h: int, key: bool, data: bytes) -> bytes:
    return struct.pack("<BIHHB", MSG_VIDEO, seq, w, h, 1 if key else 0) + data


def motion_fraction(prev: np.ndarray, cur: np.ndarray) -> float:
    """Cheap estimate of how much of the frame changed (samples every 16th row)."""
    return float(np.any(cur[::16] != prev[::16], axis=2).mean())


class Encoder(threading.Thread):
    """JPEG-encodes frames handed over by the capture thread. PIL releases the GIL, so grabbing the
    next frame and encoding the previous one overlap on different cores."""

    def __init__(self, settings: Settings, loop: asyncio.AbstractEventLoop, out: asyncio.Queue):
        super().__init__(name="encode", daemon=True)
        self.settings = settings
        self.loop = loop
        self.out = out
        self.jobs: queue_mod.Queue = queue_mod.Queue(maxsize=1)
        self.seq = 0
        self.video_ok = VideoEncoder.available()

    def next_seq(self) -> int:
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        return self.seq

    def run(self):
        video = VideoEncoder() if VideoEncoder.available() else None
        failures = 0
        last_size = None
        reopened = False
        try:
            while True:
                job = self.jobs.get()
                if job is None:
                    return
                t0 = time.perf_counter()
                try:
                    if job[0] == "video":
                        _, frame, _arr, w, h, fps, kbps, keyframe, capture_cost = job
                        reopened = video.ensure(w, h, fps, kbps)
                        if reopened:
                            keyframe = True
                            new_name = self.settings.encoder_name != video.name
                            self.settings.encoder_name = video.name
                            (log.info if new_name or (w, h) != last_size else log.debug)(
                                "video encoder: %s (%dx%d @ %d fps, %d kbit/s)", video.name, w, h, fps, kbps)
                            last_size = (w, h)
                        for data, key in video.encode(frame, keyframe):
                            message = pack_video(self.next_seq(), w, h, key, data)
                            self.settings.sent(struct.unpack_from("<I", message, 1)[0], len(message))
                            self.loop.call_soon_threadsafe(self.out.put_nowait, message)
                    else:
                        _, img, regions, quality, capture_cost = job
                        for message in encode_messages(img, regions, quality, self.next_seq):
                            self.settings.sent(struct.unpack_from("<I", message, 1)[0], len(message))
                            self.loop.call_soon_threadsafe(self.out.put_nowait, message)
                except Exception as exc:
                    failures += 1
                    log.warning("encode failed (%d): %s", failures, exc)
                    if job[0] == "video" and video is not None:
                        if video.name != "libx264" and not video.sw_only:
                            video.sw_only = True   # hardware encoder broke: fall back to software
                            log.warning("switching to the software H.264 encoder")
                        elif failures >= 5:
                            self.video_ok = False  # give up on video; the capture loop falls back to JPEG
                            log.warning("video encoding keeps failing; streaming JPEG instead")
                        video.close()
                else:
                    failures = 0
                    if not reopened:  # encoder start-up cost isn't a steady-state sample
                        self.settings.note_frame_cost(max(capture_cost, time.perf_counter() - t0))
                reopened = False
        finally:
            if video is not None:
                video.close()


class Capturer(threading.Thread):
    def __init__(self, settings: Settings, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
        super().__init__(name="capture", daemon=True)
        self.settings = settings
        self.loop = loop
        self.queue = queue
        self.stop_event = threading.Event()
        self.encoder = Encoder(settings, loop, queue)
        self.monitors: list[dict] = probe_monitors()

    def run(self):
        source = ScreenSource(self.monitors)
        self.encoder.start()
        try:
            self.capture_loop(source)
        finally:
            self.encoder.jobs.put(None)
            source.close()

    def capture_loop(self, source: ScreenSource):
        prev = None
        prev_key = None
        last_raw = None          # last full-resolution frame, for keyframes when nothing changed
        motion_streak = 0
        frame_no = 0
        next_at = time.perf_counter()
        while not self.stop_event.is_set():
            mon_idx, fps, keyframe, active = self.settings.snapshot()
            if not active:
                prev = None
                time.sleep(0.2)
                next_at = time.perf_counter()
                continue
            if not self.settings.can_send():
                if keyframe:
                    with self.settings.lock:
                        self.settings.keyframe = True
                time.sleep(0.002)
                continue
            now = time.perf_counter()
            if now < next_at:
                time.sleep(next_at - now)
                now = time.perf_counter()
            interval = 1.0 / max(1, fps)
            next_at = max(next_at + interval, now - interval)  # pace at the target fps without accumulating debt

            started = time.perf_counter()
            if not 0 <= mon_idx < len(self.monitors):
                mon_idx = 1
            mon = self.monitors[mon_idx]
            try:
                arr = source.grab(mon_idx, mon)
            except Exception as exc:  # display change, locked session, etc.
                log.warning("capture failed: %s", exc)
                time.sleep(0.5)
                prev = None
                continue
            if arr is None:  # nothing changed on screen
                if keyframe and last_raw is not None:
                    arr = last_raw
                else:
                    if keyframe:
                        with self.settings.lock:
                            self.settings.keyframe = True
                    continue
            else:
                last_raw = arr

            factor, quality = self.settings.effective(arr.shape[1])
            if self.settings.codec == "h264" and self.encoder.video_ok:
                w = max(2, int(arr.shape[1] * factor)) & ~1
                h = max(2, int(arr.shape[0] * factor)) & ~1
                prev = None
                pix_fmt = "yuv420p" if self.settings.encoder_name == "libx264" else "bgra"
                frame = VideoEncoder.prepare(arr, w, h, pix_fmt)
                self.encoder.jobs.put(("video", frame, arr, w, h, fps, quality, keyframe, time.perf_counter() - started))
                continue
            img = Image.frombuffer("RGB", (arr.shape[1], arr.shape[0]), arr, "raw", "BGRX", 0, 1)
            if factor < 0.999:
                w, h = arr.shape[1], arr.shape[0]
                if abs(factor - 0.5) < 0.01:
                    img = img.reduce(2)
                else:
                    img = img.resize((max(2, int(w * factor)) & ~1, max(2, int(h * factor)) & ~1), Image.BILINEAR, reducing_gap=2.0)
            cur = np.asarray(img)
            key = (mon_idx, cur.shape)
            frame_no += 1
            full = [(0, 0, cur.shape[1], cur.shape[0])]
            if keyframe or prev is None or key != prev_key:
                regions = full
            elif motion_streak >= 2 and frame_no % 8:
                # Sustained motion (game/video): skip the exact diff most of the time.
                regions = full if motion_fraction(prev, cur) > 0.25 else diff_regions(prev, cur)
            else:
                regions = diff_regions(prev, cur)
            prev, prev_key = cur, key
            motion_streak = motion_streak + 1 if regions == full else 0

            if regions:
                capture_cost = time.perf_counter() - started
                self.encoder.jobs.put(("jpeg", img, regions, quality, capture_cost))  # blocks while the encoder is busy


def probe_monitors() -> list[dict]:
    """Monitor geometry from a throwaway mss instance (mss objects are thread-bound)."""
    try:
        with MSS() as sct:
            return list(sct.monitors)
    except Exception as exc:
        log.warning("could not enumerate monitors: %s", exc)
        return []


def diff_regions(prev: np.ndarray, cur: np.ndarray) -> list[tuple[int, int, int, int]]:
    """Bounding boxes (x, y, w, h) of changed areas, grouped by tile rows."""
    changed = np.any(cur != prev, axis=2)
    h, w = changed.shape
    hh = -(-h // TILE) * TILE
    ww = -(-w // TILE) * TILE
    if (hh, ww) != (h, w):
        padded = np.zeros((hh, ww), dtype=bool)
        padded[:h, :w] = changed
        changed = padded
    tiles = changed.reshape(hh // TILE, TILE, ww // TILE, TILE).any(axis=(1, 3))
    rows = np.flatnonzero(tiles.any(axis=1))
    if rows.size == 0:
        return []
    if tiles.mean() > 0.5:
        return [(0, 0, w, h)]

    bands: list[tuple[int, int]] = []
    start = last = int(rows[0])
    for r in rows[1:]:
        r = int(r)
        if r == last + 1:
            last = r
        else:
            bands.append((start, last))
            start = last = r
    bands.append((start, last))

    if len(bands) > 8:  # too fragmented: one box around everything
        cols = np.flatnonzero(tiles.any(axis=0))
        bands = [(int(rows[0]), int(rows[-1]))]
        x0, x1 = int(cols[0]) * TILE, min(int(cols[-1] + 1) * TILE, w)
        y0, y1 = bands[0][0] * TILE, min((bands[0][1] + 1) * TILE, h)
        return [(x0, y0, x1 - x0, y1 - y0)]

    regions = []
    for r0, r1 in bands:
        cols = np.flatnonzero(tiles[r0:r1 + 1].any(axis=0))
        x0, x1 = int(cols[0]) * TILE, min(int(cols[-1] + 1) * TILE, w)
        y0, y1 = r0 * TILE, min((r1 + 1) * TILE, h)
        regions.append((x0, y0, x1 - x0, y1 - y0))
    return regions


def encode_jpeg(img: Image.Image, region, quality: int) -> bytes:
    x, y, w, h = region
    buf = io.BytesIO()
    img.crop((x, y, x + w, y + h)).save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def encode_messages(img: Image.Image, regions, quality: int, next_seq) -> list[bytes]:
    """Encode regions as JPEG and pack them into one or more frame messages under MAX_MESSAGE."""
    encoded: list[tuple[tuple[int, int, int, int], bytes]] = []
    pending = list(regions)
    while pending:
        region = pending.pop()
        data = encode_jpeg(img, region, quality)
        if len(data) > MAX_MESSAGE - 64:
            x, y, w, h = region
            if h >= 2:  # split tall regions in half and retry
                half = h // 2
                pending.extend([(x, y, w, half), (x, y + half, w, h - half)])
                continue
            data = encode_jpeg(img, region, 25)
        encoded.append((region, data))

    messages = []
    batch: list[tuple[tuple[int, int, int, int], bytes]] = []
    size = 0
    for item in encoded:
        if batch and size + len(item[1]) + 12 > MAX_MESSAGE - 64:
            messages.append(pack_frame(img.size, batch, next_seq()))
            batch, size = [], 0
        batch.append(item)
        size += len(item[1]) + 12
    if batch:
        messages.append(pack_frame(img.size, batch, next_seq()))
    return messages


def pack_frame(size, batch, seq: int) -> bytes:
    w, h = size
    parts = [struct.pack("<BIHHB", MSG_FRAME, seq, w, h, len(batch))]
    for (x, y, rw, rh), data in batch:
        parts.append(struct.pack("<HHHHI", x, y, rw, rh, len(data)))
        parts.append(data)
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Input injection
# ---------------------------------------------------------------------------

SPECIAL_KEYS = {
    "Enter": Key.enter, "Backspace": Key.backspace, "Tab": Key.tab, "Escape": Key.esc,
    "Delete": Key.delete, "Insert": Key.insert, "Home": Key.home, "End": Key.end,
    "PageUp": Key.page_up, "PageDown": Key.page_down,
    "ArrowUp": Key.up, "ArrowDown": Key.down, "ArrowLeft": Key.left, "ArrowRight": Key.right,
    "CapsLock": Key.caps_lock, "NumLock": Key.num_lock, "ScrollLock": Key.scroll_lock,
    "PrintScreen": Key.print_screen, "Pause": Key.pause, "ContextMenu": Key.menu,
    " ": Key.space, "AltGraph": Key.alt_gr,
    "AudioVolumeMute": Key.media_volume_mute, "AudioVolumeDown": Key.media_volume_down,
    "AudioVolumeUp": Key.media_volume_up, "MediaPlayPause": Key.media_play_pause,
    "MediaTrackNext": Key.media_next, "MediaTrackPrevious": Key.media_previous,
}
MODIFIERS = {
    "ShiftLeft": Key.shift_l, "ShiftRight": Key.shift_r, "Shift": Key.shift,
    "ControlLeft": Key.ctrl_l, "ControlRight": Key.ctrl_r, "Control": Key.ctrl,
    "AltLeft": Key.alt_l, "AltRight": Key.alt_r, "Alt": Key.alt,
    "MetaLeft": Key.cmd_l, "MetaRight": Key.cmd_r, "Meta": Key.cmd, "OS": Key.cmd,
}
# Physical key codes -> Windows virtual-key codes, so shortcuts work regardless of
# what character the viewer's keyboard layout produced.
WIN_VK = {
    "Minus": 0xBD, "Equal": 0xBB, "BracketLeft": 0xDB, "BracketRight": 0xDD, "Backslash": 0xDC,
    "Semicolon": 0xBA, "Quote": 0xDE, "Backquote": 0xC0, "Comma": 0xBC, "Period": 0xBE, "Slash": 0xBF,
    "NumpadMultiply": 0x6A, "NumpadAdd": 0x6B, "NumpadSubtract": 0x6D, "NumpadDecimal": 0x6E, "NumpadDivide": 0x6F,
}
for _i in range(26):
    WIN_VK[f"Key{chr(65 + _i)}"] = 0x41 + _i
for _i in range(10):
    WIN_VK[f"Digit{_i}"] = 0x30 + _i
    WIN_VK[f"Numpad{_i}"] = 0x60 + _i
BUTTONS = {0: Button.left, 1: Button.middle, 2: Button.right}
if hasattr(Button, "x1"):
    BUTTONS[3] = Button.x1
    BUTTONS[4] = Button.x2


def map_key(key, code):
    if not isinstance(key, str):
        return None
    if key in ("Shift", "Control", "Alt", "Meta", "OS"):
        return MODIFIERS.get(code) or MODIFIERS.get(key)
    if key in SPECIAL_KEYS:
        return SPECIAL_KEYS[key]
    if key.startswith("F") and key[1:].isdigit() and 1 <= int(key[1:]) <= 20:
        return getattr(Key, f"f{key[1:]}", None)
    if code == "NumpadEnter":
        return Key.enter
    if sys.platform == "win32" and isinstance(code, str) and code in WIN_VK:
        return KeyCode.from_vk(WIN_VK[code])
    if len(key) == 1:
        return KeyCode.from_char(key)
    return None  # Dead, Unidentified, Process, ...


class InputInjector:
    def __init__(self, dry_run: bool):
        self.dry_run = dry_run
        self.mouse = mouse.Controller()
        self.keyboard = keyboard.Controller()
        self.held_keys: dict[str, object] = {}
        self.held_buttons: set = set()
        self.scroll_acc = [0.0, 0.0]

    def move(self, mon: dict, nx: float, ny: float):
        x = mon["left"] + int(round(nx * (mon["width"] - 1)))
        y = mon["top"] + int(round(ny * (mon["height"] - 1)))
        if self.dry_run:
            log.info("[dry-run] move -> (%d, %d)", x, y)
            return
        self.mouse.position = (x, y)

    def move_rel(self, dx: int, dy: int):
        """Relative motion that games see (raw input on Windows)."""
        if self.dry_run:
            log.info("[dry-run] move-rel (%+d, %+d)", dx, dy)
            return
        if sys.platform == "win32":
            SendInput(1, ctypes.byref(INPUT(type=INPUT.MOUSE, value=INPUT_union(
                mi=MOUSEINPUT(dx=dx, dy=dy, dwFlags=MOUSEINPUT.MOVE)))), ctypes.sizeof(INPUT))
        else:
            self.mouse.move(dx, dy)

    def button(self, b: int, down: bool):
        btn = BUTTONS.get(b)
        if btn is None:
            return
        if self.dry_run:
            log.info("[dry-run] button %s %s", btn, "down" if down else "up")
            return
        if down:
            self.mouse.press(btn)
            self.held_buttons.add(btn)
        else:
            self.mouse.release(btn)
            self.held_buttons.discard(btn)

    def scroll(self, dx: float, dy: float):
        # Browser: positive dy = scroll down. pynput: positive dy = scroll up.
        self.scroll_acc[0] += dx
        self.scroll_acc[1] -= dy
        ix, iy = int(self.scroll_acc[0]), int(self.scroll_acc[1])
        if ix or iy:
            self.scroll_acc[0] -= ix
            self.scroll_acc[1] -= iy
            if self.dry_run:
                log.info("[dry-run] scroll (%d, %d)", ix, iy)
            else:
                self.mouse.scroll(ix, iy)

    def key(self, key, code, down: bool):
        ident = code if isinstance(code, str) and code else str(key)
        if down:
            k = map_key(key, code)
            if k is None:
                return
            self.held_keys[ident] = k
        else:
            k = self.held_keys.pop(ident, None) or map_key(key, code)
            if k is None:
                return
        if self.dry_run:
            log.info("[dry-run] key %s %s", k, "down" if down else "up")
            return
        try:
            (self.keyboard.press if down else self.keyboard.release)(k)
        except Exception as exc:
            log.debug("key %s failed: %s", k, exc)

    def type_text(self, text: str):
        if self.dry_run:
            log.info("[dry-run] type %r", text[:80])
            return
        self.keyboard.type(text)

    def tap(self, names: list):
        keys = [map_key(n, n) for n in names[:4] if isinstance(n, str)]
        keys = [k for k in keys if k is not None]
        if self.dry_run:
            log.info("[dry-run] tap %s", keys)
            return
        for k in keys:
            self.keyboard.press(k)
        for k in reversed(keys):
            self.keyboard.release(k)

    def release_all(self):
        if self.dry_run:
            self.held_keys.clear()
            self.held_buttons.clear()
            return
        for k in list(self.held_keys.values()):
            try:
                self.keyboard.release(k)
            except Exception:
                pass
        for b in list(self.held_buttons):
            try:
                self.mouse.release(b)
            except Exception:
                pass
        self.held_keys.clear()
        self.held_buttons.clear()


# ---------------------------------------------------------------------------
# Host session
# ---------------------------------------------------------------------------

class Host:
    def __init__(self, url: str, auth_key_hex: str, enc_key: bytes, settings: Settings, injector: InputInjector):
        self.ws_url = url.rstrip("/").replace("https://", "wss://", 1).replace("http://", "ws://", 1) + "/ws/host"
        self.auth_key_hex = auth_key_hex
        self.aead = AESGCM(enc_key)
        self.settings = settings
        self.injector = injector
        self.run_id = secrets.token_hex(8)
        self.hostname = socket.gethostname()
        self.seen_nonces: deque = deque()
        self.seen_set: set = set()
        self.last_skew_log = 0.0
        self.capturer: Capturer | None = None
        self.queue: asyncio.Queue | None = None

    # -- crypto --------------------------------------------------------------

    def seal(self, plain: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, plain, AAD_H2V)

    def open(self, data: bytes) -> bytes | None:
        if len(data) < 12 + 16 + 1 or len(data) > 65536:
            return None
        nonce, ct = data[:12], data[12:]
        now = time.monotonic()
        while self.seen_nonces and now - self.seen_nonces[0][0] > 2 * REPLAY_WINDOW_S:
            self.seen_set.discard(self.seen_nonces.popleft()[1])
        if nonce in self.seen_set:
            log.warning("replayed message dropped")
            return None
        try:
            plain = self.aead.decrypt(nonce, ct, AAD_V2H)
        except InvalidTag:
            log.warning("message failed authentication (wrong password on the viewer?)")
            return None
        self.seen_nonces.append((now, nonce))
        self.seen_set.add(nonce)
        return plain

    # -- lifecycle -----------------------------------------------------------

    async def run_forever(self):
        backoff = 1.0
        while True:
            try:
                log.info("connecting to %s", self.ws_url)
                async with websockets.connect(
                    self.ws_url,
                    additional_headers={"Authorization": f"Bearer {self.auth_key_hex}"},
                    max_size=1024 * 1024,
                    ping_interval=None,      # the relay answers app-level "ping" without waking up
                    open_timeout=15,
                    close_timeout=5,
                ) as ws:
                    backoff = 1.0
                    log.info("connected; waiting for viewers")
                    await self.session(ws)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                status = getattr(getattr(exc, "response", None), "status_code", None)
                if status == 401:
                    log.error("relay rejected the password (401). Did you run `npm run setup` with the same password?")
                elif status == 429:
                    log.error("relay is rate limiting logins (429); waiting")
                    backoff = max(backoff, 60)
                elif status == 503:
                    log.error("relay is not configured yet (503). Run `npm run setup` in the worker folder.")
                else:
                    log.warning("connection lost: %s", exc)
            self.settings.active = False
            self.injector.release_all()
            log.info("reconnecting in %.0fs", backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    async def session(self, ws):
        loop = asyncio.get_running_loop()
        self.queue = asyncio.Queue()
        self.capturer = Capturer(self.settings, loop, self.queue)
        self.capturer.start()
        sender = asyncio.create_task(self.sender(ws))
        keepalive = asyncio.create_task(self.keepalive(ws))
        cursor = asyncio.create_task(self.cursor_reporter())
        try:
            async for message in ws:
                if isinstance(message, str):
                    self.on_control(message)
                else:
                    await self.on_cipher(message)
        finally:
            self.capturer.stop_event.set()
            sender.cancel()
            keepalive.cancel()
            cursor.cancel()
            self.settings.active = False
            self.settings.in_flight = 0

    async def sender(self, ws):
        while True:
            message = await self.queue.get()
            await ws.send(self.seal(message))

    async def keepalive(self, ws):
        while True:
            await asyncio.sleep(20)
            await ws.send("ping")

    async def cursor_reporter(self):
        """Screen captures never include the cursor; tell the viewer where it is (used in game mode)."""
        last = None
        while True:
            await asyncio.sleep(1 / 30)
            if not self.settings.active:
                continue
            mon = self.current_monitor()
            if not mon:
                continue
            try:
                if sys.platform == "win32":
                    x, y, hidden = cursor_state()
                else:
                    (x, y), hidden = self.injector.mouse.position, False
            except Exception:
                continue
            state = (round((x - mon["left"]) / max(1, mon["width"]), 4), round((y - mon["top"]) / max(1, mon["height"]), 4), hidden)
            if state != last:
                if last is None or hidden != last[2]:
                    log.info("cursor %s by the foreground app", "hidden (game mode)" if hidden else "visible")
                last = state
                self.send_json({"t": "cur", "x": state[0], "y": state[1], "hidden": hidden})

    def on_control(self, text: str):
        if text == "pong":
            return
        try:
            msg = json.loads(text)
        except ValueError:
            return
        if msg.get("type") != "relay":
            return
        viewers = int(msg.get("viewers") or 0)
        was_active = self.settings.active
        self.settings.active = viewers > 0
        self.settings.reset_flow()
        if viewers > 0:
            with self.settings.lock:
                self.settings.keyframe = True
            self.send_meta()
            if not was_active:
                log.info("viewer connected (%d online)", viewers)
        elif was_active:
            log.info("no viewers; capture paused")
            self.injector.release_all()

    def send_json(self, obj: dict):
        if self.queue is not None:
            self.queue.put_nowait(bytes([MSG_JSON]) + json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    def send_meta(self):
        mons = self.capturer.monitors if self.capturer else []
        self.send_json({
            "t": "meta",
            "host": self.hostname,
            "run": self.run_id,
            "monitor": self.settings.monitor,
            "monitors": [
                {"i": i, "w": m["width"], "h": m["height"], "primary": i == 1}
                for i, m in enumerate(mons)
            ],
        })

    # -- viewer messages -----------------------------------------------------

    async def on_cipher(self, data: bytes):
        plain = self.open(data)
        if plain is None or plain[0] != MSG_JSON:
            return
        try:
            msg = json.loads(plain[1:].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(msg, dict):
            return
        ts = msg.get("ts")
        if not isinstance(ts, (int, float)) or abs(time.time() * 1000 - ts) > REPLAY_WINDOW_S * 1000:
            now = time.monotonic()
            if now - self.last_skew_log > CLOCK_SKEW_LOG_EVERY_S:
                self.last_skew_log = now
                log.warning("dropping message with stale timestamp (clock skew > %ds between laptop and desktop?)", REPLAY_WINDOW_S)
            return
        self.handle(msg)

    def handle(self, msg: dict):
        t = msg.get("t")
        s = self.settings
        if t == "ack":
            seq = msg.get("seq")
            s.on_ack(seq if isinstance(seq, int) else -1)
        elif t == "mr":
            dx, dy = msg.get("dx"), msg.get("dy")
            if isinstance(dx, (int, float)) and isinstance(dy, (int, float)):
                self.injector.move_rel(int(max(-2000, min(2000, dx))), int(max(-2000, min(2000, dy))))
        elif t == "mm":
            x, y = msg.get("x"), msg.get("y")
            if isinstance(x, (int, float)) and isinstance(y, (int, float)):
                mon = self.current_monitor()
                if mon:
                    self.injector.move(mon, min(1.0, max(0.0, float(x))), min(1.0, max(0.0, float(y))))
        elif t in ("md", "mu"):
            b = msg.get("b")
            if isinstance(b, int):
                self.injector.button(b, t == "md")
        elif t == "wh":
            dx, dy = msg.get("dx", 0), msg.get("dy", 0)
            if isinstance(dx, (int, float)) and isinstance(dy, (int, float)):
                self.injector.scroll(max(-50.0, min(50.0, float(dx))), max(-50.0, min(50.0, float(dy))))
        elif t in ("kd", "ku"):
            self.injector.key(msg.get("key"), msg.get("code"), t == "kd")
        elif t == "type":
            text = msg.get("text")
            if isinstance(text, str) and text:
                self.injector.type_text(text[:5000])
        elif t == "tap":
            keys = msg.get("keys")
            if isinstance(keys, list):
                self.injector.tap(keys)
        elif t == "cfg":
            codec = msg.get("codec")
            if codec in ("jpeg", "h264"):
                s.set_codec(codec if (codec == "jpeg" or VideoEncoder.available()) else "jpeg")
            q = msg.get("quality")
            if q == "auto":
                s.auto_quality = True
            elif isinstance(q, (int, float)):
                s.auto_quality = False
                s.quality = int(max(10, min(95, q)))
            sc = msg.get("scale")
            if sc == "auto":
                s.scale = "auto"
            elif isinstance(sc, (int, float)) and 0.25 <= sc <= 1.0:
                s.scale = float(sc)
            fps = msg.get("fps")
            if isinstance(fps, (int, float)):
                s.fps = int(max(1, min(s.max_fps, fps)))
            with s.lock:
                s.keyframe = True
        elif t == "mon":
            i = msg.get("i")
            if isinstance(i, int) and self.capturer and 0 <= i < len(self.capturer.monitors):
                s.monitor = i
                with s.lock:
                    s.keyframe = True
                self.send_meta()
        elif t == "kf":
            with s.lock:
                s.keyframe = True
        elif t == "ping":
            mon = self.current_monitor()
            factor, quality = s.effective(mon["width"] if mon else 1920)
            self.send_json({"t": "pong", "p": msg.get("p"), "q": quality, "s": round(factor, 2), "auto": s.auto_quality,
                            "fps": s.fps, "win": s.window, "inflight": s.in_flight_frames,
                            "codec": s.codec, "enc": s.encoder_name, "bw": round(s.bw_mbit, 1)})

    def current_monitor(self) -> dict | None:
        if not self.capturer or not self.capturer.monitors:
            return None
        idx = self.settings.monitor
        if not 0 <= idx < len(self.capturer.monitors):
            idx = 1
        return self.capturer.monitors[idx]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def make_dpi_aware():
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def main():
    parser = argparse.ArgumentParser(description="Remoto host agent")
    parser.add_argument("--url", help="Relay URL, e.g. https://remoto.<you>.workers.dev (or REMOTO_URL)")
    parser.add_argument("--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"),
                        help="JSON file with url/password/answer/monitor/quality/fps (default: config.json next to this script)")
    parser.add_argument("--monitor", type=int, help="Monitor index: 1 = primary, 0 = all monitors")
    parser.add_argument("--quality", type=int, help="Initial JPEG quality 10-95 (viewer can change)")
    parser.add_argument("--fps", type=int, help="Frame rate cap (default 60; the viewer picks 15/30/60 below it)")
    parser.add_argument("--dry-run", action="store_true", help="Log input events instead of injecting them")
    parser.add_argument("--print-hash", action="store_true", help="Print AUTH_HASH for the relay and exit")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("comtypes").setLevel(logging.WARNING)

    cfg = load_config(args.config)
    password = os.environ.get("REMOTO_PASSWORD") or cfg.get("password") or getpass.getpass("Remoto password: ")
    if len(password) < 10:
        log.error("password must be at least 10 characters")
        sys.exit(2)
    # Optional second factor: only if the relay was set up with a security question. Blank = password only.
    answer = os.environ.get("REMOTO_ANSWER")
    if answer is None:
        answer = cfg.get("answer")
    if answer is None:
        answer = getpass.getpass("Security answer (press Enter if you didn't set a question): ")
    auth_key_hex, enc_key = derive_keys(password, answer)
    del password, answer

    if args.print_hash:
        print(auth_hash(auth_key_hex))
        return

    url = args.url or os.environ.get("REMOTO_URL") or cfg.get("url")
    if not url:
        parser.error("--url is required (or set REMOTO_URL / config.json)")
    if not url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
        parser.error("--url must be https:// (http is only allowed for localhost testing)")

    make_dpi_aware()
    settings = Settings(
        monitor=args.monitor if args.monitor is not None else int(cfg.get("monitor", 1)),
        quality=args.quality or int(cfg.get("quality", 65)),
        fps=DEFAULT_FPS,
        scale="auto",
        max_fps=args.fps or int(cfg.get("fps", MAX_FPS)),
    )
    log.info("capture: %s", "DXGI (GPU)" if bettercam is not None else "GDI via mss (pip install bettercam for faster capture)")
    log.info("video: %s", "H.264 available (encoder chosen when a viewer connects)" if av is not None else "unavailable (pip install av) - JPEG only")
    host = Host(url, auth_key_hex, enc_key, settings, InputInjector(dry_run=args.dry_run))
    if args.dry_run:
        log.info("dry run: input events will be logged, not injected")
    try:
        asyncio.run(host.run_forever())
    except KeyboardInterrupt:
        pass
    finally:
        host.injector.release_all()


if __name__ == "__main__":
    main()
