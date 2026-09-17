// The relay Durable Object. One instance ("main") holds the host's WebSocket and
// up to MAX_VIEWERS viewer WebSockets and forwards opaque binary messages between
// them. Everything peers send is end-to-end encrypted, so this object only ever
// sees ciphertext. It also keeps the login rate-limit counters.

import { DurableObject } from 'cloudflare:workers';
import type { Env } from './index';

const MAX_VIEWERS = 1; // one person controls the desktop at a time; a second viewer is refused
const MAX_MESSAGE = 1024 * 1024; // Workers WebSocket message limit
const IP_LIMIT = 5; // failed logins per IP per window
const IP_WINDOW_MS = 15 * 60_000;
const GLOBAL_LIMIT = 50; // failed logins across all IPs per window
const GLOBAL_WINDOW_MS = 10 * 60_000;

type Role = 'host' | 'viewer';
interface Bucket {
  count: number;
  start: number;
}

export class Relay extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Answer keepalive pings without waking the object from hibernation.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  // ---- WebSocket relay -------------------------------------------------

  async fetch(req: Request): Promise<Response> {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('Expected WebSocket', { status: 426 });
    // The Worker authenticated the caller and tells us the role; nothing else can reach this object.
    const role = req.headers.get('X-Remoto-Role') as Role | null;
    if (role !== 'host' && role !== 'viewer') return new Response('Bad role', { status: 400 });

    if (role === 'host') {
      // A reconnecting host replaces any stale host socket.
      for (const old of this.sockets('host')) old.close(4000, 'Replaced by a new host connection');
    } else if (this.sockets('viewer').length >= MAX_VIEWERS) {
      // Complete the handshake, then close with a reason the browser can show.
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      server.close(4002, 'Another viewer is already connected. Disconnect there first.');
      return new Response(null, { status: 101, webSocket: client });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [role]);
    this.broadcastState(); // includes the newcomer
    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): void {
    // Peers only speak binary (ciphertext). Text is reserved for relay control messages.
    if (typeof message === 'string') return;
    if (message.byteLength > MAX_MESSAGE) {
      ws.close(1009, 'Message too large');
      return;
    }
    const role = this.ctx.getTags(ws)[0] as Role;
    const targets = role === 'host' ? this.sockets('viewer') : this.sockets('host');
    for (const t of targets) {
      try {
        t.send(message);
      } catch {
        /* peer went away; close handler will tidy up */
      }
    }
  }

  webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): void {
    this.dropped(ws, code, reason);
  }

  webSocketError(ws: WebSocket, _err: unknown): void {
    this.dropped(ws, 1011, 'Socket error');
  }

  private dropped(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch {
      /* already closed */
    }
    this.broadcastState(ws);
  }

  private sockets(role: Role, except?: WebSocket): WebSocket[] {
    return this.ctx.getWebSockets(role).filter((s) => s !== except);
  }

  private stateMessage(except?: WebSocket): string {
    return JSON.stringify({
      type: 'relay',
      hostOnline: this.sockets('host', except).length > 0,
      viewers: this.sockets('viewer', except).length,
    });
  }

  private broadcastState(except?: WebSocket): void {
    const msg = this.stateMessage(except);
    for (const s of this.ctx.getWebSockets()) {
      if (s === except) continue;
      try {
        s.send(msg);
      } catch {
        /* ignore */
      }
    }
  }

  // ---- Login rate limiting (RPC methods called by the Worker) ------------

  async loginAllowed(ip: string): Promise<boolean> {
    const now = Date.now();
    const [ipBucket, globalBucket] = await Promise.all([
      this.ctx.storage.get<Bucket>(`rl:ip:${ip}`),
      this.ctx.storage.get<Bucket>('rl:global'),
    ]);
    return !exceeded(ipBucket, IP_LIMIT, IP_WINDOW_MS, now) && !exceeded(globalBucket, GLOBAL_LIMIT, GLOBAL_WINDOW_MS, now);
  }

  /** Record a failed login. Returns true when this failure locks the IP out. */
  async loginFailed(ip: string): Promise<boolean> {
    const now = Date.now();
    const [ipBucket, globalBucket] = await Promise.all([
      this.ctx.storage.get<Bucket>(`rl:ip:${ip}`),
      this.ctx.storage.get<Bucket>('rl:global'),
    ]);
    const nextIp = bump(ipBucket, IP_WINDOW_MS, now);
    await this.ctx.storage.put({
      [`rl:ip:${ip}`]: nextIp,
      'rl:global': bump(globalBucket, GLOBAL_WINDOW_MS, now),
    });
    if ((await this.ctx.storage.getAlarm()) === null) await this.ctx.storage.setAlarm(now + 60 * 60_000);
    return nextIp.count === IP_LIMIT;
  }

  /** Periodic cleanup of expired rate-limit buckets. */
  async alarm(): Promise<void> {
    const now = Date.now();
    const all = await this.ctx.storage.list<Bucket>({ prefix: 'rl:' });
    const stale: string[] = [];
    for (const [key, bucket] of all) {
      const window = key === 'rl:global' ? GLOBAL_WINDOW_MS : IP_WINDOW_MS;
      if (now - bucket.start > window) stale.push(key);
    }
    if (stale.length) await this.ctx.storage.delete(stale);
  }
}

function exceeded(bucket: Bucket | undefined, limit: number, windowMs: number, now: number): boolean {
  if (!bucket || now - bucket.start > windowMs) return false;
  return bucket.count >= limit;
}

function bump(bucket: Bucket | undefined, windowMs: number, now: number): Bucket {
  if (!bucket || now - bucket.start > windowMs) return { count: 1, start: now };
  return { count: bucket.count + 1, start: bucket.start };
}
