// Crypto helpers for the relay: auth-key verification and signed session cookies.
// The relay never sees the user's password — only a PBKDF2-derived "auth key",
// and it stores only the SHA-256 of that key.

const enc = new TextEncoder();
const HEX64 = /^[0-9a-f]{64}$/;

export function isHex64(s: unknown): s is string {
  return typeof s === 'string' && HEX64.test(s);
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (const b of u) s += b.toString(16).padStart(2, '0');
  return s;
}

function b64url(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return null;
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function randomHex(bytes: number): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Constant-time comparison (Workers runtime extension). */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  return (crypto.subtle as unknown as { timingSafeEqual(x: Uint8Array, y: Uint8Array): boolean }).timingSafeEqual(a, b);
}

/** True when SHA-256(authKey) matches the configured AUTH_HASH. */
export async function verifyAuthKey(authKeyHex: string, authHashHex: string): Promise<boolean> {
  if (!isHex64(authKeyHex) || !isHex64(authHashHex)) return false;
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', hexToBytes(authKeyHex)));
  return timingSafeEqual(digest, hexToBytes(authHashHex));
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

interface SessionClaims {
  exp: number; // unix seconds
  jti: string;
}

/** Create a signed, stateless session token: base64url(claims).base64url(hmac). */
export async function signSession(secret: string, ttlSeconds: number): Promise<string> {
  const claims: SessionClaims = { exp: Math.floor(Date.now() / 1000) + ttlSeconds, jti: randomHex(16) };
  const payload = b64url(enc.encode(JSON.stringify(claims)));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(payload)));
  return `${payload}.${b64url(sig)}`;
}

/** Verify signature and expiry. Returns the claims, or null if invalid. */
export async function verifySession(secret: string, token: string | null): Promise<SessionClaims | null> {
  if (!token || token.length > 512) return null;
  const dot = token.indexOf('.');
  if (dot <= 0) return null;
  const payload = token.slice(0, dot);
  const sig = unb64url(token.slice(dot + 1));
  const payloadBytes = unb64url(payload);
  if (!sig || !payloadBytes) return null;
  const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), sig, enc.encode(payload));
  if (!ok) return null;
  let claims: SessionClaims;
  try {
    claims = JSON.parse(new TextDecoder().decode(payloadBytes));
  } catch {
    return null;
  }
  if (typeof claims?.exp !== 'number' || claims.exp <= Date.now() / 1000) return null;
  return claims;
}

export function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get('Cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}
