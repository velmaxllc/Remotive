"""Remotive Stream — shared wire protocol for the low-latency game streamer.

Same idea as NVIDIA GameStream / Sunshine+Moonlight, but our own code:

  * raw UDP (no TCP, no relay) so a late frame is dropped, never queued behind a retransmit
  * each H.264 frame is split into MTU-sized shards + Reed-Solomon (zfec) parity, so a few
    lost packets are rebuilt on the client without asking for anything back (Forward Error Correction)
  * every packet is AES-256-GCM sealed with a key derived from the password (end-to-end encrypted);
    the host and client never send the password, and pairing is implicit: a wrong key just won't decrypt

Two peers: the HOST (desktop, captures+encodes+injects input) and the CLIENT (laptop, decodes+displays
+sends input). They find each other by IP:port — on a LAN directly, or over the internet via a Tailscale IP.
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import time
from dataclasses import dataclass

import zfec
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---- key derivation (matches the Remotive scheme so a password behaves the same) ----------
PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, answer: str = "") -> bytes:
    secret = f"{password}\n{' '.join(answer.strip().lower().split())}".encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret, b"remoto:stream:v1", PBKDF2_ITERATIONS, 32)


# ---- packet framing ---------------------------------------------------------------------
# Wire packet = [12-byte nonce][ GCM ciphertext of (1-byte type + body) ][16-byte tag].
# Direction is bound into the GCM associated data so a packet can't be reflected back.
# NOTE: these salt/AAD strings keep their original spelling on purpose. They are protocol
# constants baked into every derived key — renaming them would invalidate existing deployments.
AAD_H2C = b"remoto-stream:h2c"   # host -> client
AAD_C2H = b"remoto-stream:c2h"   # client -> host

T_HELLO = 0x01      # client -> host: I'm here, please stream (also carries desired settings)
T_VIDEO = 0x02      # host -> client: one FEC shard of a video frame
T_INPUT = 0x03      # client -> host: an input event
T_FEEDBACK = 0x04   # client -> host: periodic stats + requests (keyframe, bitrate)
T_META = 0x05       # host -> client: stream info (resolution, encoder, fps)
T_BYE = 0x06        # either way: closing

MTU_PAYLOAD = 1150            # bytes of shard per UDP packet (keeps us under a 1280 MTU after crypto)
MAX_SHARDS = 200             # zfec k+n ceiling we allow per frame
FEC_RATIO = 0.25             # parity overhead added on top of the data shards
REPLAY_WINDOW_S = 5.0        # reject packets whose timestamp is older/newer than this

# VIDEO body header (after decrypt, after the 1-byte type):
#   frame_seq u32 | k u8 | n u8 | shard_index u8 | flags u8 | width u16 | height u16 | frame_len u32
_VIDEO_HDR = struct.Struct("<IBBBBHHI")
VIDEO_FLAG_KEY = 0x01


class Sealer:
    """AES-256-GCM sealing/opening plus a small replay guard, one per direction pair."""

    def __init__(self, key: bytes, send_aad: bytes, recv_aad: bytes):
        self.aead = AESGCM(key)
        self.send_aad = send_aad
        self.recv_aad = recv_aad
        self._seen: dict[bytes, float] = {}
        self._last_gc = 0.0

    def seal(self, plain: bytes) -> bytes:
        nonce = os.urandom(12)
        # prepend an 8-byte send timestamp (ms) so the peer can drop stale/replayed packets
        stamped = struct.pack("<Q", int(time.time() * 1000)) + plain
        return nonce + self.aead.encrypt(nonce, stamped, self.send_aad)

    def open(self, data: bytes, check_replay: bool = True) -> bytes | None:
        if len(data) < 12 + 16 + 8:
            return None
        nonce = data[:12]
        try:
            stamped = self.aead.decrypt(nonce, data[12:], self.recv_aad)
        except InvalidTag:
            return None
        ts = struct.unpack_from("<Q", stamped, 0)[0]
        if abs(time.time() * 1000 - ts) > REPLAY_WINDOW_S * 1000:
            return None
        if check_replay:
            now = time.monotonic()
            if nonce in self._seen:
                return None
            self._seen[nonce] = now
            if now - self._last_gc > 1.0:
                self._last_gc = now
                cutoff = now - 2 * REPLAY_WINDOW_S
                for k in [k for k, t in self._seen.items() if t < cutoff]:
                    del self._seen[k]
        return stamped[8:]


# ---- video frame <-> FEC shards ---------------------------------------------------------

def shard_frame(frame: bytes) -> tuple[int, int, int, list[bytes]]:
    """Split an encoded frame into k data shards + parity shards (systematic FEC).
    Returns (k, n, block_size, shards) where shards[:k] are the data and shards[k:] the parity."""
    k = max(1, min(MAX_SHARDS - 1, math.ceil(len(frame) / MTU_PAYLOAD)))
    block = math.ceil(len(frame) / k)
    padded = frame.ljust(k * block, b"\x00")
    data_blocks = [padded[i * block:(i + 1) * block] for i in range(k)]
    parity = min(MAX_SHARDS - k, max(1, round(k * FEC_RATIO)))
    n = k + parity
    shards = zfec.Encoder(k, n).encode(data_blocks, list(range(n)))
    return k, n, block, shards


def build_video_packets(sealer: Sealer, frame_seq: int, w: int, h: int, key: bool, frame: bytes) -> list[bytes]:
    k, n, _block, shards = shard_frame(frame)
    flags = VIDEO_FLAG_KEY if key else 0
    out = []
    for idx, shard in enumerate(shards):
        body = bytes([T_VIDEO]) + _VIDEO_HDR.pack(frame_seq, k, n, idx, flags, w, h, len(frame)) + shard
        out.append(sealer.seal(body))
    return out


@dataclass
class VideoShard:
    frame_seq: int
    k: int
    n: int
    index: int
    key: bool
    w: int
    h: int
    frame_len: int
    data: bytes


def parse_video(body: bytes) -> VideoShard | None:
    if len(body) < 1 + _VIDEO_HDR.size or body[0] != T_VIDEO:
        return None
    frame_seq, k, n, idx, flags, w, h, flen = _VIDEO_HDR.unpack_from(body, 1)
    return VideoShard(frame_seq, k, n, idx, bool(flags & VIDEO_FLAG_KEY), w, h, flen, body[1 + _VIDEO_HDR.size:])


class FrameReassembler:
    """Collects shards per frame and rebuilds the frame once k of them (any mix of data/parity) arrive.
    Late/incomplete older frames are dropped the moment a newer frame completes — latency over completeness."""

    def __init__(self):
        self.frames: dict[int, dict[int, bytes]] = {}
        self.done: set[int] = set()          # frame_seqs already delivered or abandoned
        self.newest_done = -1

    def add(self, s: VideoShard) -> tuple[bytes, bool] | None:
        if s.frame_seq <= self.newest_done or s.frame_seq in self.done:
            return None
        slot = self.frames.setdefault(s.frame_seq, {})
        slot[s.index] = s.data
        if len(slot) < s.k:
            return None
        # We have enough shards: reconstruct.
        idxs = sorted(slot.keys())[: s.k]
        blocks = [slot[i] for i in idxs]
        try:
            recovered = zfec.Decoder(s.k, s.n).decode(blocks, idxs)
        except Exception:
            return None
        frame = b"".join(recovered)[: s.frame_len]
        self._finish(s.frame_seq)
        return frame, s.key

    def _finish(self, frame_seq: int):
        self.done.add(frame_seq)
        self.newest_done = max(self.newest_done, frame_seq)
        # Drop everything older; it can't help us anymore.
        for fs in [fs for fs in self.frames if fs <= frame_seq]:
            del self.frames[fs]
        if len(self.done) > 512:
            for fs in sorted(self.done)[:256]:
                self.done.discard(fs)


# ---- input / control bodies -------------------------------------------------------------
# Input body = [T_INPUT][subtype][fields].  Discrete events (buttons, keys) carry an event_id and
# are sent a few times; the host dedups by id so a lost packet doesn't drop or stick a key.
IN_MOVE = 0x01     # relative mouse motion:  i16 dx, i16 dy
IN_BUTTON = 0x02   # mouse button:           u32 id, u8 button, u8 down
IN_WHEEL = 0x03    # scroll wheel:           i16 dx, i16 dy   (units of 120 = one notch)
IN_KEY = 0x04      # keyboard:               u32 id, u8 down, len-prefixed code, len-prefixed key

_MOVE = struct.Struct("<hh")
_BUTTON = struct.Struct("<IBB")
_WHEEL = struct.Struct("<hh")


def in_move(dx: int, dy: int) -> bytes:
    dx = max(-32000, min(32000, int(dx)))
    dy = max(-32000, min(32000, int(dy)))
    return bytes([T_INPUT, IN_MOVE]) + _MOVE.pack(dx, dy)


def in_button(event_id: int, button: int, down: bool) -> bytes:
    return bytes([T_INPUT, IN_BUTTON]) + _BUTTON.pack(event_id & 0xFFFFFFFF, button & 0xFF, 1 if down else 0)


def in_wheel(dx120: int, dy120: int) -> bytes:
    return bytes([T_INPUT, IN_WHEEL]) + _WHEEL.pack(max(-32000, min(32000, dx120)), max(-32000, min(32000, dy120)))


def in_key(event_id: int, down: bool, code: str, key: str) -> bytes:
    cb = code.encode("utf-8")[:24]
    kb = key.encode("utf-8")[:24]
    return bytes([T_INPUT, IN_KEY]) + struct.pack("<IB", event_id & 0xFFFFFFFF, 1 if down else 0) + \
        bytes([len(cb)]) + cb + bytes([len(kb)]) + kb


def parse_input(body: bytes):
    """Returns a tuple describing the event, or None. Shapes:
       ('move', dx, dy) | ('button', id, button, down) | ('wheel', dx, dy) | ('key', id, down, code, key)"""
    if len(body) < 2 or body[0] != T_INPUT:
        return None
    sub = body[1]
    p = body[2:]
    try:
        if sub == IN_MOVE:
            dx, dy = _MOVE.unpack_from(p, 0)
            return ("move", dx, dy)
        if sub == IN_BUTTON:
            eid, b, d = _BUTTON.unpack_from(p, 0)
            return ("button", eid, b, bool(d))
        if sub == IN_WHEEL:
            dx, dy = _WHEEL.unpack_from(p, 0)
            return ("wheel", dx, dy)
        if sub == IN_KEY:
            eid, down = struct.unpack_from("<IB", p, 0)
            o = 5
            clen = p[o]; o += 1
            code = p[o:o + clen].decode("utf-8", "replace"); o += clen
            klen = p[o]; o += 1
            key = p[o:o + klen].decode("utf-8", "replace")
            return ("key", eid, bool(down), code, key)
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    return None


_HELLO = struct.Struct("<BBIHH")     # version, desired_fps, desired_kbps, screen_w, screen_h
_FEEDBACK = struct.Struct("<HHBIB")  # fps_recv, loss_permille, request_flags, desired_kbps, desired_fps
FB_REQUEST_KEY = 0x01


def build_hello(desired_fps: int, desired_kbps: int, screen_w: int, screen_h: int) -> bytes:
    return bytes([T_HELLO]) + _HELLO.pack(1, desired_fps & 0xFF, desired_kbps & 0xFFFFFFFF, screen_w & 0xFFFF, screen_h & 0xFFFF)


def parse_hello(body: bytes):
    if len(body) < 1 + _HELLO.size or body[0] != T_HELLO:
        return None
    _v, fps, kbps, w, h = _HELLO.unpack_from(body, 1)
    return {"fps": fps, "kbps": kbps, "w": w, "h": h}


def build_feedback(fps_recv: int, loss_permille: int, request_key: bool, desired_kbps: int, desired_fps: int) -> bytes:
    flags = FB_REQUEST_KEY if request_key else 0
    return bytes([T_FEEDBACK]) + _FEEDBACK.pack(min(65535, fps_recv), min(65535, loss_permille), flags,
                                                desired_kbps & 0xFFFFFFFF, desired_fps & 0xFF)


def parse_feedback(body: bytes):
    if len(body) < 1 + _FEEDBACK.size or body[0] != T_FEEDBACK:
        return None
    fps, loss, flags, kbps, dfps = _FEEDBACK.unpack_from(body, 1)
    return {"fps": fps, "loss": loss, "request_key": bool(flags & FB_REQUEST_KEY), "kbps": kbps, "desired_fps": dfps}


def build_meta(w: int, h: int, fps: int, enc: str) -> bytes:
    eb = enc.encode("utf-8")[:32]
    return bytes([T_META]) + struct.pack("<HHB", w, h, fps) + bytes([len(eb)]) + eb


def parse_meta(body: bytes):
    if len(body) < 1 + 5 or body[0] != T_META:
        return None
    w, h, fps = struct.unpack_from("<HHB", body, 1)
    ln = body[6]
    return {"w": w, "h": h, "fps": fps, "enc": body[7:7 + ln].decode("utf-8", "replace")}
