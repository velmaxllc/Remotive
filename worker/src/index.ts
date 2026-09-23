// Remotive relay Worker: serves the viewer page, authenticates viewers (cookie) and
// the host (bearer auth key), and hands authenticated WebSockets to the Relay
// Durable Object. All screen/input traffic through here is end-to-end encrypted.

import { Relay } from './relay';
import { isHex64, readCookie, signSession, verifyAuthKey, verifySession } from './auth';
import { INLINE_ASSETS } from './assets.generated';
import { lockoutAlert, loginAlert, requestFacts, sendAlert } from './alerts';
import { iceServers } from './ice';

export { Relay };

export interface Env {
  ASSETS?: Fetcher; // absent on single-file (dashboard) deploys; the viewer is then served from INLINE_ASSETS
  RELAY: DurableObjectNamespace<Relay>;
  AUTH_HASH?: string;
  SESSION_SECRET?: string;
  SECURITY_QUESTION?: string; // optional second-factor question shown on the login page; blank = password only
  // Email alerts over SMTP (see alerts.ts / smtp.ts)
  SMTP_HOST?: string;
  SMTP_PORT?: string;
  SMTP_SECURE?: string;
  SMTP_USER?: string;
  SMTP_PASS?: string;
  ALERT_TO?: string;
  ALERT_FROM?: string;
  // Cloudflare Realtime TURN (see ice.ts). Without these, /stream is STUN-only and only
  // reliably connects on a LAN. Set both to stream from other networks.
  TURN_KEY_ID?: string;
  TURN_KEY_API_TOKEN?: string;
}

const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_LOGIN_BODY = 1024;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    let res: Response;
    try {
      res = await route(request, env, url, ctx);
    } catch (err) {
      console.error('Unhandled error', err);
      res = text('Internal error', 500);
    }
    // 101 responses are immutable; every other response gets the hardening headers.
    return res.status === 101 ? res : withSecurityHeaders(res, url);
  },
} satisfies ExportedHandler<Env>;

async function route(req: Request, env: Env, url: URL, ctx: ExecutionContext): Promise<Response> {
  const path = url.pathname;

  // Public: the login page reads the (optional) security-question text from here before login.
  if (path === '/api/config') {
    return json({
      securityQuestion: (env.SECURITY_QUESTION ?? '').slice(0, 200),
      configured: isHex64(env.AUTH_HASH) && !!env.SESSION_SECRET && env.SESSION_SECRET.length >= 32,
    });
  }

  if (path.startsWith('/api/') || path.startsWith('/ws/')) {
    if (!isHex64(env.AUTH_HASH) || !env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
      return text('Relay is not configured yet. Run `npm run setup` in the worker folder.', 503);
    }
    switch (path) {
      case '/api/login':
        return req.method === 'POST' ? login(req, env, url, ctx) : text('Method not allowed', 405);
      case '/api/logout':
        return req.method === 'POST' ? logout(req, url) : text('Method not allowed', 405);
      case '/api/session':
        return req.method === 'GET' ? sessionCheck(req, env, url) : text('Method not allowed', 405);
      case '/api/ice':
        return req.method === 'GET' ? iceEndpoint(req, env, url) : text('Method not allowed', 405);
      case '/ws/viewer':
        return viewerSocket(req, env, url);
      case '/ws/host':
        return hostSocket(req, env, url, ctx);
      default:
        return text('Not found', 404);
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') return text('Method not allowed', 405);
  return env.ASSETS ? env.ASSETS.fetch(req) : serveInline(req, path);
}

/** Static viewer files bundled into the script (used when there is no ASSETS binding). */
function serveInline(req: Request, path: string): Response {
  const asset = INLINE_ASSETS[path === '/' ? '/index.html' : path];
  if (!asset) return text('Not found', 404);
  const headers = { 'Content-Type': asset.type, ETag: asset.etag, 'Cache-Control': 'no-cache' };
  if (req.headers.get('If-None-Match') === asset.etag) return new Response(null, { status: 304, headers });
  return new Response(req.method === 'HEAD' ? null : asset.body, { status: 200, headers });
}

// ---- Auth endpoints -----------------------------------------------------

async function login(req: Request, env: Env, url: URL, ctx: ExecutionContext): Promise<Response> {
  if (!sameOrigin(req, url)) return json({ error: 'Forbidden' }, 403);
  const length = Number(req.headers.get('Content-Length') ?? '0');
  if (!(length > 0 && length <= MAX_LOGIN_BODY)) return json({ error: 'Bad request' }, 400);

  let body: { authKey?: unknown };
  try {
    body = await req.json();
  } catch {
    return json({ error: 'Bad request' }, 400);
  }
  const authKey = typeof body?.authKey === 'string' ? body.authKey.toLowerCase() : '';
  if (!isHex64(authKey)) return json({ error: 'Bad request' }, 400);

  const ip = clientIp(req);
  const relay = relayStub(env);
  if (!(await relay.loginAllowed(ip))) return json({ error: 'Too many attempts. Try again in a few minutes.' }, 429);
  if (!(await verifyAuthKey(authKey, env.AUTH_HASH!))) {
    if (await relay.loginFailed(ip)) {
      const alert = lockoutAlert(requestFacts(req));
      ctx.waitUntil(sendAlert(env, alert.subject, alert.lines));
    }
    return json({ error: 'Wrong password or answer.' }, 401);
  }

  // Someone is in. Tell the owner (never blocks the response).
  const alert = loginAlert(requestFacts(req));
  ctx.waitUntil(sendAlert(env, alert.subject, alert.lines));

  const token = await signSession(env.SESSION_SECRET!, SESSION_TTL_SECONDS);
  return new Response(null, {
    status: 204,
    headers: { 'Set-Cookie': sessionCookie(token, SESSION_TTL_SECONDS, url), 'Cache-Control': 'no-store' },
  });
}

function logout(req: Request, url: URL): Response {
  if (!sameOrigin(req, url)) return json({ error: 'Forbidden' }, 403);
  return new Response(null, { status: 204, headers: { 'Set-Cookie': sessionCookie('', 0, url), 'Cache-Control': 'no-store' } });
}

async function sessionCheck(req: Request, env: Env, url: URL): Promise<Response> {
  const claims = await verifySession(env.SESSION_SECRET!, readCookie(req, cookieName(url)));
  return claims ? json({ ok: true, expiresAt: claims.exp }) : json({ error: 'Unauthorized' }, 401);
}

// ---- WebSocket entry points ---------------------------------------------

async function viewerSocket(req: Request, env: Env, url: URL): Promise<Response> {
  if (req.headers.get('Upgrade') !== 'websocket') return text('Expected WebSocket', 426);
  if (!sameOrigin(req, url)) return text('Forbidden', 403);
  const claims = await verifySession(env.SESSION_SECRET!, readCookie(req, cookieName(url)));
  if (!claims) return text('Unauthorized', 401);
  return connectRelay(env, 'viewer');
}

/**
 * ICE servers for the WebRTC stream. Both ends need them, so this accepts either a viewer
 * session cookie or the host's bearer auth key. Returns no secrets of its own — just
 * short-lived TURN credentials (or public STUN when TURN is not configured).
 */
async function iceEndpoint(req: Request, env: Env, url: URL): Promise<Response> {
  const auth = req.headers.get('Authorization') ?? '';
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim().toLowerCase() : '';

  if (isHex64(bearer)) {
    // Host path: rate-limited like every other place the auth key is accepted.
    const relay = relayStub(env);
    const ip = clientIp(req);
    if (!(await relay.loginAllowed(ip))) return json({ error: 'Too many attempts' }, 429);
    if (!(await verifyAuthKey(bearer, env.AUTH_HASH!))) {
      await relay.loginFailed(ip);
      return json({ error: 'Unauthorized' }, 401);
    }
  } else if (!(await verifySession(env.SESSION_SECRET!, readCookie(req, cookieName(url))))) {
    return json({ error: 'Unauthorized' }, 401);
  }

  return json(await iceServers(env));
}

async function hostSocket(req: Request, env: Env, url: URL, ctx: ExecutionContext): Promise<Response> {
  if (req.headers.get('Upgrade') !== 'websocket') return text('Expected WebSocket', 426);
  // The host is a native agent: it must not be a browser page (no Origin) and must present the auth key.
  if (req.headers.get('Origin') !== null) return text('Forbidden', 403);
  const auth = req.headers.get('Authorization') ?? '';
  const authKey = auth.startsWith('Bearer ') ? auth.slice(7).trim().toLowerCase() : '';
  if (!isHex64(authKey)) return text('Unauthorized', 401);

  const ip = clientIp(req);
  const relay = relayStub(env);
  if (!(await relay.loginAllowed(ip))) return text('Too many attempts', 429);
  if (!(await verifyAuthKey(authKey, env.AUTH_HASH!))) {
    if (await relay.loginFailed(ip)) {
      const alert = lockoutAlert(requestFacts(req));
      ctx.waitUntil(sendAlert(env, alert.subject, alert.lines));
    }
    return text('Unauthorized', 401);
  }
  void url;
  return connectRelay(env, 'host');
}

function connectRelay(env: Env, role: 'host' | 'viewer'): Promise<Response> {
  // Only this Worker can reach the Durable Object, so the role header is trusted there.
  return relayStub(env).fetch('https://relay.internal/connect', {
    headers: { Upgrade: 'websocket', 'X-Remotive-Role': role },
  });
}

function relayStub(env: Env) {
  return env.RELAY.get(env.RELAY.idFromName('main'));
}

// ---- Helpers --------------------------------------------------------------

function sameOrigin(req: Request, url: URL): boolean {
  return req.headers.get('Origin') === url.origin;
}

function clientIp(req: Request): string {
  return req.headers.get('CF-Connecting-IP') ?? 'local';
}

function isHttps(url: URL): boolean {
  return url.protocol === 'https:';
}

function cookieName(url: URL): string {
  // __Host- prefix binds the cookie to this origin; browsers only accept it over HTTPS.
  return isHttps(url) ? '__Host-remotive_session' : 'remotive_session';
}

function sessionCookie(value: string, maxAge: number, url: URL): string {
  const parts = [`${cookieName(url)}=${value}`, 'Path=/', `Max-Age=${maxAge}`, 'HttpOnly', 'SameSite=Strict'];
  if (isHttps(url)) parts.push('Secure');
  return parts.join('; ');
}

function text(body: string, status: number): Response {
  return new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function withSecurityHeaders(res: Response, url: URL): Response {
  const out = new Response(res.body, res);
  const wsOrigin = `${isHttps(url) ? 'wss' : 'ws'}://${url.host}`;
  out.headers.set(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' blob:",
      "media-src 'self' blob:",
      `connect-src 'self' ${wsOrigin}`,
      "font-src 'self'",
      "base-uri 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
    ].join('; '),
  );
  out.headers.set('X-Content-Type-Options', 'nosniff');
  out.headers.set('X-Frame-Options', 'DENY');
  out.headers.set('Referrer-Policy', 'no-referrer');
  out.headers.set('Cross-Origin-Opener-Policy', 'same-origin');
  out.headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  out.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  if (isHttps(url)) out.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  return out;
}
