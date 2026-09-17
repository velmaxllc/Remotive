#!/usr/bin/env node
// Derives the relay secrets from your Remotive password and stores them.
//
//   npm run setup          -> pushes AUTH_HASH + SESSION_SECRET (+ SMTP_PASS) to Cloudflare (wrangler secret bulk)
//   npm run setup:local    -> writes them to .dev.vars for `npm run dev`
//   npm run setup:print    -> prints them, for pasting into the dashboard (Settings -> Variables and Secrets)
//
// The password itself is never stored anywhere. Only SHA-256(PBKDF2(password))
// reaches Cloudflare, and the encryption key (a different PBKDF2 output) is
// only ever derived on the host and in the viewer's browser.

import { createHash, pbkdf2Sync, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const PBKDF2_ITERATIONS = 200000;
const MIN_PASSWORD_LENGTH = 10;
const workerDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const local = process.argv.includes('--local');
const printOnly = process.argv.includes('--print');
const CTRL_C = String.fromCharCode(3);
const DEL = String.fromCharCode(127);

function askHidden(question) {
  return new Promise((resolve, reject) => {
    const { stdin, stdout } = process;
    stdout.write(question);
    if (!stdin.isTTY) {
      // Piped input (scripts/CI): one answer per line.
      pipedLines().then((lines) => {
        stdout.write('\n');
        resolve(lines.shift() ?? '');
      }, reject);
      return;
    }
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (ch) => {
      if (ch === CTRL_C) {
        stdin.setRawMode(false);
        reject(new Error('cancelled'));
        return;
      }
      if (ch === '\r' || ch === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        stdout.write('\n');
        resolve(value);
        return;
      }
      if (ch === DEL || ch === '\b') value = value.slice(0, -1);
      else value += ch;
    };
    stdin.on('data', onData);
  });
}

let piped;
function pipedLines() {
  if (!piped) {
    piped = new Promise((resolve) => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (c) => (data += c));
      process.stdin.on('end', () => resolve(data.split(/\r?\n/)));
    });
  }
  return piped;
}

// Same normalization as the viewer and the host: trim, lowercase, collapse whitespace.
function normalizeAnswer(answer) {
  return answer.trim().toLowerCase().replace(/\s+/g, ' ');
}

function deriveAuthHash(password, answer) {
  const secret = `${password}\n${normalizeAnswer(answer)}`;
  const authKey = pbkdf2Sync(secret, 'remoto:auth:v1', PBKDF2_ITERATIONS, 32, 'sha256');
  return createHash('sha256').update(authKey).digest('hex');
}

// A plain (visible) prompt, for non-secret input like the security-question text.
function askVisible(question) {
  return new Promise((resolve, reject) => {
    process.stdout.write(question);
    if (!process.stdin.isTTY) {
      pipedLines().then((lines) => resolve((lines.shift() ?? '').trim()), reject);
      return;
    }
    const onData = (buf) => {
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      resolve(buf.toString('utf8').replace(/\r?\n$/, '').trim());
    };
    process.stdin.resume();
    process.stdin.once('data', onData);
  });
}

async function main() {
  console.log(`Remotive relay setup (${local ? 'local .dev.vars' : printOnly ? 'print values' : 'Cloudflare secrets'})\n`);
  const password = await askHidden('Choose a Remotive password (10+ characters): ');
  if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  const again = await askHidden('Repeat it: ');
  if (again !== password) throw new Error('Passwords do not match.');

  // Optional second factor: a security question shown on the login page. Blank = password only.
  const question = await askVisible('Security question (shown on the login page; press Enter for none): ');
  let answer = '';
  if (question) {
    answer = await askHidden(`Answer to "${question}": `);
    if (!normalizeAnswer(answer)) throw new Error('The answer cannot be empty when a question is set.');
    const answerAgain = await askHidden('Repeat the answer: ');
    if (normalizeAnswer(answerAgain) !== normalizeAnswer(answer)) throw new Error('Answers do not match.');
  }

  const secrets = { AUTH_HASH: deriveAuthHash(password, answer), SESSION_SECRET: randomBytes(32).toString('hex') };
  if (question) secrets.SECURITY_QUESTION = question;

  // Optional: email login-alerts. Off unless you enter an SMTP password (and set ALERT_TO in wrangler.jsonc).
  const appPassword = (await askHidden('SMTP password for login-alert emails (press Enter to skip — most people skip): ')).replace(/\s+/g, '');
  if (appPassword) secrets.SMTP_PASS = appPassword;
  else console.log('  (email alerts off — see wrangler.jsonc to enable them later)');

  if (printOnly) {
    console.log('\nAdd these secrets to the Worker (Settings -> Variables and Secrets -> type: Secret):\n');
    for (const [k, v] of Object.entries(secrets)) console.log(`  ${k}\n  ${v}\n`);
    return;
  }

  if (local) {
    const file = join(workerDir, '.dev.vars');
    writeFileSync(file, Object.entries(secrets).map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600 });
    console.log(`\nWrote ${file}. Start the relay locally with: npm run dev`);
    return;
  }

  const dir = mkdtempSync(join(tmpdir(), 'remotive-'));
  const file = join(dir, 'secrets.json');
  try {
    writeFileSync(file, JSON.stringify(secrets), { mode: 0o600 });
    console.log('\nUploading secrets with wrangler…');
    const res = spawnSync('npx', ['wrangler', 'secret', 'bulk', file], { cwd: workerDir, stdio: 'inherit', shell: true });
    if (res.status !== 0) throw new Error('wrangler secret bulk failed (are you logged in? try: npx wrangler login)');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log('\nDone. Deploy with: npm run deploy');
  console.log('Then start the host with the same password and answer: python host/remotive_host.py --url https://<your-worker>.workers.dev');
}

main().catch((err) => {
  console.error(`\n${err.message}`);
  process.exit(1);
});
