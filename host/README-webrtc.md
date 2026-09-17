# Remotive WebRTC (low-latency streaming to the browser)

Streams your desktop to the **browser** with game-grade latency, using **WebRTC** — the same UDP/hardware-H.264
transport Parsec/Stadia use for in-browser play. The Cloudflare Worker only carries the tiny connection
handshake (SDP/ICE, end-to-end encrypted); the video then flows **directly** desktop ⇄ browser, peer-to-peer.

## Use it
1. Deploy the relay (see the main README) — same one the plain viewer uses.
2. On the **desktop**:
   ```powershell
   cd host
   pip install -r requirements.txt          # includes aiortc
   python webrtc_host.py --url https://remotive.<you>.workers.dev --fps 60 --bitrate 20000
   ```
   Enter the same password + security answer as the relay.
3. On the **laptop**, open **`https://remotive.<you>.workers.dev/stream`**, log in, and click **🎮 Play**
   (fullscreen + captured mouse for games; press **Esc** to release).

## How it differs from the other two modes
| Mode | Transport | Client | Latency |
| --- | --- | --- | --- |
| Plain viewer (`/`) | JPEG/H.264 over TCP WebSocket through the relay | browser | highest |
| **WebRTC (`/stream`)** | **H.264 over WebRTC (UDP), P2P** | **browser** | low |
| Native (`stream/`) | H.264 over raw UDP + FEC, P2P | Python app | lowest |

## Notes
- Needs a browser with WebRTC H.264 (Chrome, Edge, Safari, Firefox) — all modern ones.
- On a LAN it connects directly and instantly. Over the internet it uses STUN to punch a direct path; on strict
  NATs where that fails you'd need a TURN server (or use Tailscale so both machines are directly reachable).
- aiortc encodes in software H.264 (fast at 720p). The bitrate adapts automatically via WebRTC congestion control,
  up to the `--bitrate` ceiling.
