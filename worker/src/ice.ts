// ICE servers for the WebRTC stream (/stream).
//
// STUN alone only tells each end its own public address — the two then have to punch a UDP hole
// straight to each other. On a LAN that always works, which is why streaming is flawless at home.
// Away from home it often fails: mobile hotspots, hotel/office/campus Wi-Fi and ISP CGNAT all use
// NATs that hole punching cannot cross, and the stream then hangs at "Negotiating…" forever.
//
// Most home routers are fine: if yours hands out a stable public address (a "cone" NAT, which the
// host checks and logs at startup), STUN alone connects from anywhere. TURN is only needed when a
// network blocks peer-to-peer UDP outright. It is entirely optional and off unless TURN_KEY_ID and
// TURN_KEY_API_TOKEN are set — leave them unset and this returns plain STUN, which costs nothing.

import type { Env } from './index';

// Order matters: some WebRTC stacks (aiortc, which the host uses) take only the *first* STUN server,
// so the most dependable one goes first. The host additionally probes these before use.
const STUN_ONLY = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
const TTL_SECONDS = 12 * 60 * 60;

export interface IceConfig {
  iceServers: unknown[];
  /** false = STUN only, so the viewer can say *why* a connection failed instead of just hanging. */
  turn: boolean;
}

// Credentials are valid for TTL_SECONDS, so one fetch serves every stream this isolate starts.
let cached: { value: IceConfig; expires: number } | null = null;

export async function iceServers(env: Env): Promise<IceConfig> {
  if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) return { iceServers: STUN_ONLY, turn: false };
  if (cached && Date.now() < cached.expires) return cached.value;

  const endpoint = `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(env.TURN_KEY_ID)}/credentials/generate-ice-servers`;
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ ttl: TTL_SECONDS }),
    });
    if (!res.ok) {
      console.log(`[ice] Cloudflare TURN said ${res.status}; check TURN_KEY_ID / TURN_KEY_API_TOKEN. Using STUN only.`);
      return { iceServers: STUN_ONLY, turn: false };
    }
    const body = (await res.json()) as { iceServers?: unknown };
    // The API returns either a single object or a list, depending on the key; accept both.
    const list = Array.isArray(body.iceServers) ? body.iceServers : body.iceServers ? [body.iceServers] : [];
    if (!list.length) return { iceServers: STUN_ONLY, turn: false };

    const value: IceConfig = { iceServers: list, turn: true };
    // Expire our copy well before the credentials themselves do.
    cached = { value, expires: Date.now() + (TTL_SECONDS / 2) * 1000 };
    return value;
  } catch (err) {
    console.log(`[ice] could not reach Cloudflare TURN (${err}); using STUN only.`);
    return { iceServers: STUN_ONLY, turn: false };
  }
}
