// Remoto Stream viewer — WebRTC. Logs in and opens the relay WebSocket only to trade the WebRTC
// handshake (SDP/ICE) with the desktop host, encrypted end-to-end. Once connected, H.264 video and
// input flow peer-to-peer over WebRTC (UDP) — the relay is out of the media path.
'use strict';

(() => {
  const $ = (s) => document.querySelector(s);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERATIONS = 200000;
  const AAD_H2V = enc.encode('remoto-v1:h2v');
  const AAD_V2H = enc.encode('remoto-v1:v2h');
  const MSG_JSON = 0x02;

  const ui = {
    login: $('#login'), form: $('#login-form'), password: $('#password'), answer: $('#answer'), answerLabel: $('#answer-label'),
    connect: $('#connect'), loginError: $('#login-error'),
    stage: $('#stage'), status: $('#status'), stats: $('#stats'), video: $('#video'),
    viewport: $('#viewport'), overlay: $('#overlay'), overlayTitle: $('#overlay-title'),
    overlayText: $('#overlay-text'), overlayAction: $('#overlay-action'),
    btnPlay: $('#btn-play'), btnFull: $('#btn-full'), btnLeave: $('#btn-leave'),
  };

  const state = {
    ws: null, encKey: null, authKeyHex: null,
    pc: null, dc: null, playing: false, leaving: false,
    held: new Set(), moveDx: 0, moveDy: 0, moveRaf: 0, statsTimer: 0, hostOnline: false,
  };

  // ---- crypto / login ----------------------------------------------------
  async function deriveKeys(password, answer) {
    if (!crypto.subtle) throw new Error('This page needs HTTPS (or localhost).');
    const secret = `${password}\n${answer.trim().toLowerCase().replace(/\s+/g, ' ')}`;
    const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'PBKDF2', false, ['deriveBits']);
    const derive = (salt) => crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: PBKDF2_ITERATIONS }, base, 256);
    const [authBits, encBits] = await Promise.all([derive('remoto:auth:v1'), derive('remoto:enc:v1')]);
    const encKey = await crypto.subtle.importKey('raw', encBits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { authKeyHex: hex(new Uint8Array(authBits)), encKey };
  }
  function hex(b) { let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s; }

  async function seal(obj) {
    obj.ts = Date.now();
    const plain = new Uint8Array([MSG_JSON, ...enc.encode(JSON.stringify(obj))]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD_V2H }, state.encKey, plain));
    const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
  }
  async function open(buf) {
    const u = new Uint8Array(buf);
    if (u.length < 29) return null;
    let plain;
    try { plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.subarray(0, 12), additionalData: AAD_H2V }, state.encKey, u.subarray(12))); }
    catch { return null; }
    if (plain[0] !== MSG_JSON) return null;
    try { return JSON.parse(dec.decode(plain.subarray(1))); } catch { return null; }
  }

  let questionRequired = false;
  (async () => {
    try {
      const cfg = await (await fetch('/api/config', { credentials: 'same-origin' })).json();
      if (cfg.securityQuestion) {
        questionRequired = true;
        ui.answerLabel.textContent = cfg.securityQuestion;
        ui.answerLabel.hidden = false; ui.answer.hidden = false; ui.answer.required = true;
      }
    } catch { /* password only */ }
  })();

  ui.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = ui.password.value, answer = questionRequired ? ui.answer.value : '';
    if (!password || (questionRequired && !answer.trim())) return;
    ui.connect.disabled = true; ui.connect.textContent = 'Deriving keys…'; showLoginError('');
    try {
      const { authKeyHex, encKey } = await deriveKeys(password, answer);
      const res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ authKey: authKeyHex }), credentials: 'same-origin' });
      if (!res.ok) { const b = await res.json().catch(() => ({})); throw new Error(b.error || `Login failed (${res.status})`); }
      state.encKey = encKey; state.authKeyHex = authKeyHex;
      ui.password.value = ''; ui.answer.value = '';
      ui.login.hidden = true; ui.stage.hidden = false;
      connect();
    } catch (err) { showLoginError(err.message || 'Login failed.'); }
    finally { ui.connect.disabled = false; ui.connect.textContent = 'Connect'; }
  });
  function showLoginError(m) { ui.loginError.textContent = m; ui.loginError.hidden = !m; }

  // ---- relay signaling ---------------------------------------------------
  function connect() {
    state.leaving = false;
    setStatus('Connecting…', '');
    showOverlay('Connecting to the relay…', '');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/viewer`);
    ws.binaryType = 'arraybuffer';
    state.ws = ws;
    ws.onopen = () => { setStatus('Waiting for desktop…', 'warn'); startStats(); };
    ws.onmessage = (ev) => { if (typeof ev.data === 'string') onRelay(ev.data); else onSealed(ev.data); };
    ws.onclose = () => {
      if (state.ws !== ws) return;
      state.ws = null; stopStats(); teardownPeer();
      if (!state.leaving) { setStatus('Disconnected', 'bad'); showOverlay('Disconnected', 'Lost the relay connection.', 'Reconnect', reconnect); }
    };
  }
  async function reconnect() {
    try { const r = await fetch('/api/session', { credentials: 'same-origin' }); if (!r.ok) throw 0; connect(); }
    catch { ui.stage.hidden = true; ui.login.hidden = false; }
  }

  function onRelay(text) {
    let m; try { m = JSON.parse(text); } catch { return; }
    if (m.type !== 'relay') return;
    const was = state.hostOnline;
    state.hostOnline = !!m.hostOnline;
    if (state.hostOnline && !was) { hideOverlay(); setStatus('Desktop online', 'ok'); startWebRTC(); }
    else if (!state.hostOnline) { setStatus('Waiting for desktop…', 'warn'); teardownPeer(); showOverlay('Waiting for the desktop…', 'Start webrtc_host.py on your desktop with the same password.'); }
  }

  async function onSealed(buf) {
    const msg = await open(buf);
    if (!msg) return;
    if (msg.t === 'rtc-answer') { if (state.pc) await state.pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp }); }
    else if (msg.t === 'rtc-ice') { if (state.pc && msg.candidate) { try { await state.pc.addIceCandidate(msg.candidate); } catch (e) { /* ignore */ } } }
  }

  // ---- WebRTC ------------------------------------------------------------
  async function startWebRTC() {
    teardownPeer();
    setStatus('Negotiating…', 'warn');
    const pc = new RTCPeerConnection({ iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }] });
    state.pc = pc;
    pc.addTransceiver('video', { direction: 'recvonly' });
    const dc = pc.createDataChannel('input', { ordered: false, maxRetransmits: 0 });
    state.dc = dc;
    dc.onopen = () => setStatus('Connected', 'ok');

    pc.ontrack = (ev) => { ui.video.srcObject = ev.streams[0]; ui.video.play().catch(() => {}); hideOverlay(); };
    pc.onicecandidate = (ev) => { if (ev.candidate && state.ws) send({ t: 'rtc-ice', candidate: ev.candidate.toJSON() }); };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') { setStatus('Connected', 'ok'); hideOverlay(); }
      else if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) { setStatus('Peer lost', 'bad'); }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    send({ t: 'rtc-offer', sdp: pc.localDescription.sdp });
  }

  function teardownPeer() {
    if (state.dc) { try { state.dc.close(); } catch {} state.dc = null; }
    if (state.pc) { try { state.pc.close(); } catch {} state.pc = null; }
    ui.video.srcObject = null;
    if (state.playing) exitPlay();
  }

  async function send(obj) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN || !state.encKey) return;
    try { state.ws.send(await seal(obj)); } catch {}
  }
  function sendInput(obj) {
    if (state.dc && state.dc.readyState === 'open') { try { state.dc.send(JSON.stringify(obj)); } catch {} }
  }

  // ---- input (Play = pointer lock + keyboard capture) --------------------
  function enterPlay() {
    state.playing = true; ui.btnPlay.classList.add('active');
    if (!document.fullscreenElement) ui.stage.requestFullscreen({ navigationUI: 'hide' }).catch(() => {});
    if (navigator.keyboard && navigator.keyboard.lock) navigator.keyboard.lock().catch(() => {});
    ui.video.requestPointerLock();
  }
  function exitPlay() {
    state.playing = false; ui.btnPlay.classList.remove('active');
    releaseAll();
    if (document.pointerLockElement) document.exitPointerLock();
    if (navigator.keyboard && navigator.keyboard.unlock) navigator.keyboard.unlock();
  }
  const locked = () => document.pointerLockElement === ui.video;

  ui.btnPlay.addEventListener('click', () => (state.playing ? exitPlay() : enterPlay()));
  document.addEventListener('pointerlockchange', () => { if (!locked() && state.playing) state.playing = state.playing; });

  ui.video.addEventListener('mousemove', (e) => {
    if (!locked()) return;
    state.moveDx += e.movementX; state.moveDy += e.movementY;
    if (!state.moveRaf) state.moveRaf = requestAnimationFrame(flushMove);
  });
  function flushMove() {
    state.moveRaf = 0;
    const dx = Math.trunc(state.moveDx), dy = Math.trunc(state.moveDy);
    state.moveDx -= dx; state.moveDy -= dy;
    if (dx || dy) sendInput({ t: 'mr', dx, dy });
  }
  ui.video.addEventListener('mousedown', (e) => { e.preventDefault(); if (!locked()) { enterPlay(); return; } sendInput({ t: 'md', b: e.button }); });
  ui.video.addEventListener('mouseup', (e) => { e.preventDefault(); if (locked()) sendInput({ t: 'mu', b: e.button }); });
  ui.video.addEventListener('contextmenu', (e) => e.preventDefault());
  ui.video.addEventListener('wheel', (e) => { if (!locked()) return; e.preventDefault(); sendInput({ t: 'wh', dx: -e.deltaX / 100, dy: -e.deltaY / 100 }); }, { passive: false });

  document.addEventListener('keydown', (e) => {
    if (!state.playing) return;
    if (e.key === 'Escape' && !document.fullscreenElement) { exitPlay(); return; }
    e.preventDefault();
    state.held.add(e.code || e.key);
    sendInput({ t: 'kd', key: e.key, code: e.code });
  });
  document.addEventListener('keyup', (e) => {
    if (!state.held.has(e.code || e.key)) return;
    e.preventDefault();
    state.held.delete(e.code || e.key);
    sendInput({ t: 'ku', key: e.key, code: e.code });
  });
  function releaseAll() { for (const c of state.held) sendInput({ t: 'ku', key: c, code: c }); state.held.clear(); }
  window.addEventListener('blur', releaseAll);

  ui.btnFull.addEventListener('click', () => { if (document.fullscreenElement) document.exitFullscreen(); else ui.stage.requestFullscreen({ navigationUI: 'hide' }).catch(() => {}); });
  ui.btnLeave.addEventListener('click', () => {
    state.leaving = true; send({ t: 'rtc-stop' }); teardownPeer();
    if (state.ws) state.ws.close(1000, 'left');
    fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    ui.stage.hidden = true; ui.login.hidden = false;
  });
  ui.overlayAction.addEventListener('click', () => { const f = ui.overlayAction._fn; if (f) f(); });

  // ---- status / stats ----------------------------------------------------
  function setStatus(t, k) { ui.status.textContent = t; ui.status.className = `pill ${k}`; }
  function showOverlay(title, text, label, fn) {
    ui.overlayTitle.textContent = title; ui.overlayText.textContent = text || ''; ui.overlayText.hidden = !text;
    ui.overlayAction.hidden = !label; ui.overlayAction.textContent = label || ''; ui.overlayAction._fn = fn || null;
    ui.overlay.hidden = false;
  }
  function hideOverlay() { ui.overlay.hidden = true; }

  function startStats() {
    stopStats();
    let lastBytes = 0, lastTs = 0, lastFrames = 0;
    state.statsTimer = setInterval(async () => {
      if (!state.pc) { ui.stats.textContent = '—'; return; }
      const stats = await state.pc.getStats();
      stats.forEach((r) => {
        if (r.type === 'inbound-rtp' && r.kind === 'video') {
          const dt = (r.timestamp - lastTs) / 1000 || 1;
          const mbit = ((r.bytesReceived - lastBytes) * 8 / 1e6 / dt);
          const fps = Math.round((r.framesDecoded - lastFrames) / dt);
          lastBytes = r.bytesReceived; lastTs = r.timestamp; lastFrames = r.framesDecoded;
          const w = ui.video.videoWidth, h = ui.video.videoHeight;
          ui.stats.textContent = `${fps} fps · ${mbit.toFixed(1)} Mbit/s · ${w}×${h}`;
        }
      });
    }, 1000);
  }
  function stopStats() { if (state.statsTimer) clearInterval(state.statsTimer); state.statsTimer = 0; }

  window.addEventListener('beforeunload', () => { if (state.ws) state.ws.close(1000, 'closed'); });
})();
