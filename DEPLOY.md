# Deploying Remoto — pick one route

Remoto's link is a **Worker with code** (login API, WebSocket relay, a Durable Object, two secrets).
The dashboard's *"Upload static files"* / drag-a-zip flow only accepts static HTML/CSS/JS, so it can't run
the relay — you'd get the login page with nothing behind it. Use one of these instead.

| Route | Needs | Best when |
| --- | --- | --- |
| **A. Dashboard paste** | a browser | you don't want to install anything |
| **B. GitHub import** | a GitHub account | you want Cloudflare to rebuild on every change |
| **C. Command line** | Node.js | fastest if you're okay running 3 commands |

Whichever route you take, the host side is the same: [README.md → "Run the host"](README.md#2-run-the-host-on-the-desktop).

---

## A. Dashboard paste (no tools needed)

1. **Generate your secrets.** Double-click `tools/setup.html` (it runs offline in your browser).
   Choose your password and, optionally, your own security question + answer → copy the values it shows
   (`AUTH_HASH`, `SESSION_SECRET`, and `SECURITY_QUESTION` if you set one).

2. **Create the Worker.** Cloudflare dashboard → *Workers & Pages* → *Create* → *Start with Hello World!*
   → name it `remoto` → *Deploy*.

3. **Paste the code.** On the new Worker click *Edit code*, select everything in the editor, delete it,
   and paste the entire contents of `dashboard/remoto-worker.js`. Click *Deploy*.

4. **Add the Durable Object.** Worker → *Settings* → *Bindings* → *Add* → *Durable Object*:
   - Variable name: `RELAY`
   - Durable Object class: `Relay` — from *this* Worker (`remoto`)
   - If it asks for a storage backend, choose **SQLite** (required on the free plan).
   Save / Deploy.

5. **Add the secrets.** *Settings* → *Variables and Secrets* → *Add*, type **Secret**:
   - `AUTH_HASH` = value from step 1
   - `SESSION_SECRET` = value from step 1
   - `SECURITY_QUESTION` = your question text (optional; omit for password-only login)
   Email alerts are **off by default** — skip them unless you want them (see the README).
   Save / Deploy.

6. Open `https://remoto.<your-subdomain>.workers.dev`. You should see the Remoto login page.
   Start the host agent on the desktop with the same password, then log in from the laptop.

> If the page says *"Relay is not configured yet"*, step 5 didn't apply — check the two secret names exactly.
> If login returns *Internal error*, step 4 is missing — the code can't find the `RELAY` binding.

To change the password later: run `tools/setup.html` again, replace **both** secrets, restart the host agent.

## B. GitHub import (Cloudflare builds it for you)

1. Create a new GitHub repository and upload everything in this folder **except** `dashboard/`
   (GitHub's *Add file → Upload files* accepts drag-and-dropped folders).
2. Cloudflare dashboard → *Workers & Pages* → *Create* → *Import a repository* → pick the repo.
   - Root directory: `worker`
   - Build command: *(leave empty)* · Deploy command: `npx wrangler deploy`
   Cloudflare reads `worker/wrangler.jsonc` (Durable Object, migration, static assets) and deploys.
3. Add the two secrets exactly as in route A, step 5 (generate them with `tools/setup.html`).
4. Every push to the repo redeploys automatically.

## C. Command line (3 commands)

```powershell
cd worker
npm install
npx wrangler login          # opens the browser once
npx wrangler deploy         # prints https://remoto.<you>.workers.dev
npm run setup               # password (+ optional security question) -> uploads the secrets
```

Rebuild `dashboard/remoto-worker.js` after editing the source with `npm run bundle`.

---

## After deploying (all routes)

```powershell
cd host
pip install -r requirements.txt
python remoto_host.py --url https://remoto.<you>.workers.dev
```

Type the same password (and answer, if you set a question), leave it running, open the link on the laptop. Full details, autostart and
known limits are in [README.md](README.md); the threat model is in [SECURITY.md](SECURITY.md).
