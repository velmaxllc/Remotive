#!/usr/bin/env node
// Builds dist/remoto-worker.js: the whole relay (viewer page inlined) as ONE
// ES-module file that can be pasted into the Cloudflare dashboard code editor.
//
//   npm run bundle

import { build } from 'esbuild';
import { execFileSync } from 'node:child_process';
import { mkdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const workerDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const outfile = join(workerDir, 'dist', 'remoto-worker.js');

execFileSync(process.execPath, [join(workerDir, 'scripts', 'inline-assets.mjs')], { stdio: 'inherit' });
mkdirSync(join(workerDir, 'dist'), { recursive: true });

await build({
  entryPoints: [join(workerDir, 'src', 'index.ts')],
  bundle: true,
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  external: ['cloudflare:workers', 'cloudflare:sockets'],
  outfile,
  legalComments: 'none',
  banner: {
    js: [
      '// Remoto relay — single-file build for the Cloudflare dashboard editor.',
      '// Paste this whole file as the Worker code, then in Settings add:',
      '//   Bindings  -> Durable Object: variable RELAY, class Relay (this Worker)',
      '//   Secrets   -> AUTH_HASH and SESSION_SECRET (generate with tools/setup.html), SMTP_PASS (app password)',
      '//   Variables -> ALERT_TO, ALERT_FROM, SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER (see wrangler.jsonc)',
      '// Built from worker/src by scripts/build-bundle.mjs.',
    ].join('\n'),
  },
});

console.log(`bundle: wrote ${outfile} (${(statSync(outfile).size / 1024).toFixed(1)} KiB)`);
