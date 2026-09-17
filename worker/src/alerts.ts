// Email alerts, delivered by SMTP straight from the Worker (see smtp.ts) —
// for Google Workspace: smtp.gmail.com:465 with an app password.
//
//   vars    SMTP_HOST, SMTP_PORT, SMTP_SECURE (tls|starttls|none), SMTP_USER, ALERT_TO, ALERT_FROM
//   secret  SMTP_PASS  -> app password (alerts are only logged if missing)

import type { Env } from './index';
import { sendMail } from './smtp';

export interface RequestFacts {
  ip: string;
  userAgent: string;
  location: string;
}

export function requestFacts(req: Request): RequestFacts {
  const cf = (req as Request & { cf?: Record<string, unknown> }).cf ?? {};
  const place = [cf.city, cf.region, cf.country].filter((v): v is string => typeof v === 'string' && v.length > 0);
  return {
    ip: req.headers.get('CF-Connecting-IP') ?? 'unknown',
    userAgent: (req.headers.get('User-Agent') ?? 'unknown').slice(0, 300),
    location: place.length ? place.join(', ') : 'unknown',
  };
}

export async function sendAlert(env: Env, subject: string, lines: string[]): Promise<void> {
  const to = env.ALERT_TO;
  if (!to) return;
  const text = lines.join('\n');
  if (!env.SMTP_PASS || !env.SMTP_USER || !env.SMTP_HOST) {
    console.log(`[alert not sent: SMTP_HOST/SMTP_USER/SMTP_PASS not configured] ${subject}\n${text}`);
    return;
  }
  const secure = env.SMTP_SECURE === 'starttls' || env.SMTP_SECURE === 'none' ? env.SMTP_SECURE : 'tls';
  try {
    await sendMail({
      host: env.SMTP_HOST,
      port: Number(env.SMTP_PORT) || (secure === 'starttls' ? 587 : 465),
      secure,
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
      from: env.ALERT_FROM || env.SMTP_USER,
      to,
      subject,
      text,
    });
  } catch (err) {
    console.error('alert email failed:', err instanceof Error ? err.message : err);
  }
}

function stamp(): string {
  return new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

export function loginAlert(facts: RequestFacts): { subject: string; lines: string[] } {
  return {
    subject: 'Remoto: someone just logged in to your desktop',
    lines: [
      'A viewer logged in to Remoto with the correct password and security answer.',
      '',
      `Time:      ${stamp()}`,
      `IP:        ${facts.ip}`,
      `Location:  ${facts.location}`,
      `Browser:   ${facts.userAgent}`,
      '',
      "If this wasn't you: run `npm run setup` in worker/ to change the password and answer,",
      'then restart the host agent. The old session stops working immediately.',
    ],
  };
}

export function lockoutAlert(facts: RequestFacts): { subject: string; lines: string[] } {
  return {
    subject: 'Remoto: repeated failed logins (IP locked out)',
    lines: [
      'An IP address hit the failed-login limit and is blocked for 15 minutes.',
      '',
      `Time:      ${stamp()}`,
      `IP:        ${facts.ip}`,
      `Location:  ${facts.location}`,
      `Browser:   ${facts.userAgent}`,
      '',
      'No action is needed unless this keeps happening; consider a longer password.',
    ],
  };
}
