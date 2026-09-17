# Remoto Stream

Your own Sunshine/Moonlight — a low-latency **game** streamer, entirely your code. Same technique the
real thing uses: **raw UDP** (no relay, no TCP), **Reed-Solomon FEC** so lost packets are rebuilt instead
of retransmitted, **hardware H.264** on both ends, and a **direct connection** (your LAN, or a Tailscale IP
over the internet). Every packet is AES-256-GCM encrypted from a password.

This is separate from the browser-based Remoto in the parent folder. Remoto (browser link) is for controlling
your desktop from anywhere; **Remoto Stream (this) is for playing games** with the lowest latency this design allows.

```
desktop (host.py)                              laptop (client.py)
  DXGI capture ─▶ NVENC H.264 ─▶ FEC shards ─▶ UDP ─▶ FEC rebuild ─▶ H.264 decode ─▶ window
  inject mouse/kbd ◀───────────────── UDP ◀──────────── raw mouse + keyboard
```

## Why it's faster than the browser version
- **UDP, not TCP.** A late packet is dropped and the stream keeps going; TCP would stall everything behind it
  waiting for a retransmit (that was the ~300 ms lag in the browser version).
- **FEC.** ~25% parity packets per frame, so a few losses are repaired on the client with zero round trips.
- **Direct.** No Cloudflare hop — desktop straight to laptop.

## Install (both machines)
Python 3.10+. On the **desktop** you also need the parent `host/` deps (capture + input) and a GPU with a
hardware H.264 encoder (NVIDIA/AMD/Intel — you have an RTX, so NVENC).

```powershell
cd Remoto\stream
pip install -r requirements.txt
```

## Run

**1. Desktop (host):**
```powershell
cd Remoto\stream
python host.py --fps 60 --bitrate 20000
```
It asks for a password (any 8+ chars; the laptop must use the same one) and listens on UDP **47990**.
First run, Windows will ask to allow Python through the firewall — say yes for **Private** networks (and
Public too if you'll play over the internet).

**2. Laptop (client):** point it at the desktop's IP.
```powershell
cd Remoto\stream
python client.py <DESKTOP-IP> --fps 60 --bitrate 20000
```
- **Same Wi-Fi/LAN:** use the desktop's local IP (`ipconfig` on the desktop → IPv4, e.g. `192.168.1.50`).
- **Over the internet:** use Tailscale (below) and pass the desktop's `100.x.y.z` address.

Type the same password. A window opens showing your desktop; click it to capture the mouse and play.

| Key | Action |
| --- | --- |
| **Esc** | Release the mouse (to reach your laptop's desktop or close the window) |
| Click | Re-capture the mouse |
| **F11** | Toggle fullscreen |
| **F9** | Toggle the stats overlay |

The overlay shows `fps · bitrate · encoder`.

## Playing over the internet (Tailscale)
Tailscale puts both machines on one private network and makes a **direct, encrypted UDP** link between them —
exactly what keeps the latency low across the internet.

1. Install [Tailscale](https://tailscale.com/download) on **both** machines, sign in to the same account.
2. On each, run it (`tailscale up`). The desktop gets a stable `100.x.y.z` address — see it with `tailscale ip -4`.
3. Start `host.py` on the desktop, then on the laptop: `python client.py 100.x.y.z`.

No port-forwarding, no relay. If Tailscale can't punch a direct path (rare, strict NATs) it falls back to its
own relay — still works, just a little more latency.

## Tuning
| Flag | Meaning | Notes |
| --- | --- | --- |
| `--fps 60` | Frame rate | 60 for shooters; 30 uses less upload |
| `--bitrate 20000` | Max kbit/s | LAN: 20000–50000. Internet: match your **upload** — check speed.cloudflare.com. |
| `--width 1280 --height 720` | Stream resolution (host) | 720p60 is the Siege sweet spot; 1920×1080 if your link is fat |
| `--monitor 1` | Which monitor (host) | 1 = primary |
| `--fullscreen` | Start fullscreen (client) | |
| `--no-adapt` | Host: hold the bitrate fixed | otherwise it drops on packet loss and recovers |

The host auto-lowers the bitrate when the client reports packet loss and raises it back when the link is clean.

## Requirements & limits
- Host needs a hardware H.264 encoder; without one it falls back to CPU `libx264` (higher latency, more CPU).
- One client at a time.
- Locked screen / UAC prompts can't be captured (Windows secure desktop) — same as any user-mode capture.
- The picture is H.264 4:2:0; text is a touch softer than the desktop but games look great.

## Files
```
protocol.py   packet format, AES-GCM sealing, FEC shard/rebuild, input/control messages
host.py       desktop: capture + NVENC + UDP send + input injection (reuses ../host/remoto_host.py)
client.py     laptop: UDP recv + FEC + decode + pygame window + raw input capture
```
