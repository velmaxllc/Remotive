# Security

Remotive gives a browser full control of a desktop, so the design assumes the network,
the relay and even Cloudflare itself may be hostile. This document says what protects you
and what does not.

## One secret (password + optional security answer), two keys

```
secret = password + "\n" + answer        answer normalized: trimmed, lower-cased, single spaces
                                         (answer is "" when no security question is configured)
secret ──PBKDF2-SHA256 (200k, salt "remoto:auth:v1")──▶ auth key   ──SHA-256──▶ AUTH_HASH (stored on Cloudflare)
       ──PBKDF2-SHA256 (200k, salt "remoto:enc:v1") ──▶ encryption key             (never leaves host/viewer)
```

The security question is optional and you choose its wording at setup (`SECURITY_QUESTION`). It is not a separate
check bolted onto the login form: its answer is folded into the secret itself. With one configured, knowing the
password alone gets an attacker nothing — not a relay login, not a host connection, not a decryptable byte. The
login error is the same whichever part is wrong. Skip it and the password alone is the key.

- The **viewer** derives both keys in the browser (Web Crypto). It sends only the *auth key* to log in.
- The **host** derives both keys locally and presents the *auth key* as a bearer token.
- The **relay** stores only `SHA-256(auth key)` and compares in constant time. It cannot derive the
  encryption key from anything it holds, and cannot recover the password without brute-forcing PBKDF2.

## End-to-end encryption

Every screen frame (H.264 access unit or JPEG tile set) and every input event is AES-256-GCM encrypted with a
fresh random 96-bit nonce.
The direction is bound into the authenticated data (`remoto-v1:h2v` / `remoto-v1:v2h`), so a message
can't be reflected back as if it came from the other side. The relay only ever forwards opaque bytes.

Consequences:

- A **stolen session cookie** lets an attacker open a WebSocket to the relay — and receive ciphertext they
  can't read, and send bytes the host rejects (GCM tag check). They cannot see the screen or move the mouse.
- A **compromised relay / Cloudflare account** sees connection metadata (IPs, timing, message sizes), not content.
- The **host validates every message**: types, ranges, coordinates clamped to the screen, relative mouse
  deltas clamped to ±2000, text length capped.

## Replay protection

The host drops any viewer message whose nonce it has already seen, and any message whose timestamp
is more than 30 s from its own clock. (If your laptop and desktop clocks drift by more than that, input
is ignored and the host logs a warning — sync the clocks.)

## Login hardening (relay)

- Login and host authentication are **rate limited**: 5 failures per IP per 15 minutes, 50 failures globally
  per 10 minutes. Counters live in Durable Object storage, so they survive restarts.
- Constant-time comparison (`crypto.subtle.timingSafeEqual`).
- Password minimum 10 characters at setup. PBKDF2 with 200 000 iterations makes offline guessing slow;
  use a long passphrase anyway — password and answer are the only secrets in the system.
- Session cookie: `__Host-` prefix, `HttpOnly`, `Secure`, `SameSite=Strict`, HMAC-SHA256 signed, 8 h expiry.
- `Origin` must match on login and on the viewer WebSocket (CSRF / cross-site WebSocket hijacking).
  The host endpoint refuses any request that carries an `Origin` header at all (browsers can't be hosts).

## Transport & page hardening

- HTTPS/WSS only in production (`workers.dev` is TLS-terminated by Cloudflare; the host refuses plain `http://`
  except for localhost).
- `Content-Security-Policy: default-src 'none'; script-src 'self'; …` — no inline scripts, no third-party code,
  no eval. Plus `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP, HSTS.
- The viewer page never persists the password or keys — they live in page memory and die on reload.
- Messages larger than 1 MiB are refused by the relay; the host splits frames to stay under it.
- At most one host (a reconnect replaces the old socket) and **one viewer**: a second viewer is refused with a
  visible message, so nobody can silently watch alongside you.

## Alerts

Every successful login and every lockout sends an email to `ALERT_TO` with time, IP, approximate location and
browser. The Worker delivers it itself over SMTP with TLS (Google Workspace app password stored as the
`SMTP_PASS` secret — a scoped credential you can revoke without touching the account password). Alerts run
after the response is sent and never block or weaken the login path; if the mail server is down, the login
still works and the failure is logged.

## What is *not* protected

- **Whoever knows the password and the answer owns the desktop.** Both are things you *know*; there is no device-bound factor. Treat them like an SSH key.
- **The desktop is a normal logged-in session.** The host agent runs as your user; anyone controlling it can do
  anything you can. Don't run it on a machine you'd be uncomfortable leaving unlocked in a shared space.
- **Traffic analysis.** The relay (and your ISP) can see when you're connected and roughly how much changes on screen.
- **Locked screen / UAC.** Windows' secure desktop can't be captured or controlled — this is a limitation *and* a
  protection: a remote attacker with your password still cannot get past a UAC prompt unless the host runs elevated.
- **Denial of service.** An attacker who knows your relay URL can burn your login rate limit and lock you out for
  15 minutes per IP (the global limit is deliberately generous to keep that from being trivial from one address).
- **A compromised laptop or desktop.** Keyloggers, malicious extensions, etc. are out of scope.

## Operational advice

1. Use a long, unique passphrase (20+ characters) and a non-guessable answer. Change them with `npm run setup`
   if you ever suspect exposure — and act on any login alert you didn't cause.
2. Keep `host/config.json` (if you use autostart) readable only by your user; it holds the password.
3. Leave `observability` on in `wrangler.jsonc` and glance at the Workers dashboard for 401/429 spikes.
4. Update dependencies occasionally: `npm update` in `worker/`, `pip install -U -r requirements.txt` in `host/`.
