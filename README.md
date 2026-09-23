# Remotive

Self-hosted remote desktop and game streaming that runs on **your own Cloudflare account**. Open a link in
any browser to control your PC, or stream it at 60 fps with game-grade latency. End-to-end encrypted — the
relay only ever sees ciphertext.

No accounts, no subscriptions, no third-party service. Cloudflare's free tier is enough.

```
laptop browser  ──▶  your Cloudflare Worker  ◀──  your desktop (Python host)
                     (encrypted relay / signalling only)
```

## Three ways to connect

| Mode | Open | Latency | Best for |
| --- | --- | --- | --- |
| **Desktop control** | `/` in any browser | moderate | files, browsing, admin — works anywhere |
| **Game stream (browser)** | `/stream` | low | gaming with nothing to install on the client |
| **Game stream (native)** | `stream/client.py` | lowest | the smoothest possible play |

- **Desktop control** sends JPEG/H.264 tiles over the relay. Simple and universal.
- **`/stream`** uses **WebRTC**: hardware H.264 over UDP, peer-to-peer. The Worker only carries the
  connection handshake — video flows straight from your PC to the browser.
- **Native client** is a small Sunshine/Moonlight-style app: raw UDP + Reed-Solomon FEC, lowest latency.

---

## Setup (about 5 minutes)

### 1. Get the code
```bash
git clone https://github.com/velmaxllc/Remotive.git
cd Remotive
```

### 2. Deploy your relay
Needs [Node.js](https://nodejs.org) 20+ and a free [Cloudflare](https://dash.cloudflare.com/sign-up) account.

```bash
cd worker
npm install
npx wrangler login      # opens your browser once
npx wrangler deploy     # prints your link: https://remotive.<you>.workers.dev
npm run setup           # choose your password (+ optional security question)
```

`npm run setup` asks for:
- **A password** (10+ characters). This is the key to your desktop — make it long.
- **A security question** *(optional)* — your own wording, e.g. *"What street did I grow up on?"*. Press
  Enter to skip and use just a password. The answer becomes part of the encryption key, so it's a real
  second factor, not a cosmetic check.
- **An SMTP password** *(optional)* — press Enter to skip. See [Email alerts](#email-alerts-optional).

Only a *hash* is uploaded to Cloudflare. Your password never leaves your machine.

> Prefer clicking to typing? [DEPLOY.md](DEPLOY.md) covers deploying from the Cloudflare dashboard or from
> a GitHub repo instead of the CLI.

### 3. Run the host on the PC you want to control
Needs Python 3.10+ on that machine (Windows is the primary target; macOS/Linux work for desktop control).

```bash
cd host
pip install -r requirements.txt
python remotive_host.py --url https://remotive.<you>.workers.dev
```

Enter the same password (and answer, if you set a question). Leave it running.

### 4. Connect
Open **`https://remotive.<you>.workers.dev`** on any device, log in, and you're controlling your desktop.

---

## Gaming

For low-latency gaming, run the WebRTC host instead and open `/stream`:

```bash
cd host
python webrtc_host.py --url https://remotive.<you>.workers.dev --fps 60 --bitrate 20000
```

Then open **`https://remotive.<you>.workers.dev/stream`**, log in, and click **🎮 Play** (captures your
mouse for aiming; **Esc** releases it). Details: [host/README-webrtc.md](host/README-webrtc.md).

For the absolute lowest latency, use the native client instead — see [stream/README.md](stream/README.md).

**Reality check:** latency is bounded by your home connection's **upload** speed (not download — check the
*upload* number at [speed.cloudflare.com](https://speed.cloudflare.com) on the host PC). On a LAN it feels
instant. Over the internet, 5+ Mbit/s upload gives a good 720p60 experience.

---

## Configuration

### Security question (optional)
Set during `npm run setup`, or later:
```bash
npx wrangler secret put SECURITY_QUESTION    # then paste your question
```
The login page shows it automatically. Leave it unset for password-only login. Changing the *wording* is
safe; changing the *answer* means re-running `npm run setup`.

### Streaming away from home (TURN)
Game streaming connects your desktop and browser **directly**, peer to peer. On your own network that
always works. On other networks — mobile hotspots, hotel/office/campus Wi-Fi, or an ISP that uses
[CGNAT](https://en.wikipedia.org/wiki/Carrier-grade_NAT) — the direct path is often blocked, and `/stream`
stops at *"Could not reach the desktop"*. Desktop control (`/`) is unaffected: it goes through the relay.

The fix is a **TURN** server, which forwards the video when no direct path exists. Cloudflare has one,
and 1,000 GB/month is [included free](https://developers.cloudflare.com/realtime/pricing/) ($0.05/GB after
that). At the default `--bitrate 20000` that is about 9 GB per hour, so roughly **110 hours of streaming a
month** before you pay anything — and TURN is only used when a direct connection is impossible:

1. Cloudflare dashboard → **Realtime** → **TURN** → *Create* → copy the **Turn Token ID** and **API Token**.
2. Add them to your Worker:
   ```bash
   cd worker
   npx wrangler secret put TURN_KEY_ID          # paste the Turn Token ID
   npx wrangler secret put TURN_KEY_API_TOKEN   # paste the API token
   ```
3. Restart the host. It logs `using a TURN relay` when it picks them up.

Both ends fetch these automatically from the relay, so there is nothing to configure on the client.
Without them everything still works — just only on your own network.

### Email alerts (optional)
**Off by default** — most people don't need them and don't have an SMTP server. When enabled, you get an
email on every successful login and whenever an IP is locked out after repeated failures.

To turn them on, add your mail details to `worker/wrangler.jsonc`:
```jsonc
"vars": {
  "ALERT_TO": "you@example.com",
  "ALERT_FROM": "Remotive <you@example.com>",
  "SMTP_HOST": "smtp.gmail.com", "SMTP_PORT": "465", "SMTP_SECURE": "tls",
  "SMTP_USER": "you@example.com"
}
```
then `npx wrangler secret put SMTP_PASS` (for Gmail/Workspace, an [app password](https://support.google.com/accounts/answer/185833)),
and redeploy. Without `ALERT_TO`, no email is ever attempted — alerts just go to the Worker log.

### Host options
| Flag | Meaning |
| --- | --- |
| `--monitor 1` | which monitor (1 = primary, 0 = all) |
| `--fps 60` | frame rate cap |
| `--bitrate 20000` | max kbit/s (WebRTC / native hosts) |
| `--width` / `--height` | stream resolution |
| `--dry-run` | log input instead of injecting it (safe for testing) |

Run the host at logon with a scheduled task — see [DEPLOY.md](DEPLOY.md).

---

## Security

Your password (plus the security answer, if set) is stretched with PBKDF2 into **two** keys: one proves who
you are to the relay, the other encrypts the video and input. Cloudflare only ever stores a hash of the
first and never sees the second — so the relay cannot decrypt your screen or your keystrokes.

Also included: one viewer at a time, login rate limiting, signed `__Host-` session cookies, strict CSP,
replay protection, and input validation on the host. Full threat model: [SECURITY.md](SECURITY.md).

**Understand the risk:** anyone with your password can control that PC. Use a long, unique one.

---

## Project layout
```
worker/     Cloudflare Worker: relay, auth, and the browser pages
  src/        index.ts (routes/auth), relay.ts (Durable Object), smtp.ts, alerts.ts
  public/     the viewer (/) and the WebRTC stream page (/stream)
  scripts/    setup-secrets.mjs, build helpers
host/       Python host agents
  remotive_host.py    desktop control (tiles over the relay)
  webrtc_host.py    low-latency browser streaming (WebRTC)
stream/     native UDP + FEC streamer (host.py + client.py)
tools/      setup.html — offline generator for the secrets, if you prefer the dashboard
```

## Requirements
- **Relay:** a free Cloudflare account. (Heavy 60 fps use can exceed free-tier request limits; the $5/month
  Workers Paid plan removes that ceiling.)
- **Host PC:** Python 3.10+. A GPU with a hardware H.264 encoder (NVIDIA/AMD/Intel) makes streaming much better.
- **Client:** any modern browser. The native client needs Python.
- **Streaming from other networks:** a TURN server — see [Streaming away from home](#streaming-away-from-home-turn).

## Known limits
- Windows lock screen and UAC prompts can't be captured — the OS blocks it for any user-mode program.
- No audio or file transfer yet.
- Game streaming needs a direct peer-to-peer path, or a [TURN server](#streaming-away-from-home-turn) on
  networks that block one.
- One viewer at a time (by design).

## License
MIT — see [LICENSE](LICENSE).
