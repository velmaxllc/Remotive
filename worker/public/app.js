// Remoto viewer. Derives the session keys from the password in the browser,
// logs in to the relay with the auth key, then exchanges AES-GCM encrypted
// frames/input with the host over a WebSocket. The encryption key never leaves
// this page and is never persisted.
'use strict';

(() => {
  const $ = (sel) => document.querySelector(sel);
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const PBKDF2_ITERATIONS = 200000;
  const AAD_H2V = enc.encode('remoto-v1:h2v'); // host -> viewer
  const AAD_V2H = enc.encode('remoto-v1:v2h'); // viewer -> host
  const MSG_FRAME = 0x01; // JPEG regions
  const MSG_JSON = 0x02;
  const MSG_VIDEO = 0x03; // H.264 access unit (Annex B); decoded with WebCodecs

  const ui = {
    login: $('#login'),
    form: $('#login-form'),
    password: $('#password'),
    answer: $('#answer'),
    answerLabel: $('#answer-label'),
    connect: $('#connect'),
    loginError: $('#login-error'),
    stage: $('#stage'),
    bar: $('#bar'),
    hotzone: $('#hotzone'),
    status: $('#status'),
    hostname: $('#hostname'),
    stats: $('#stats'),
    monitor: $('#monitor'),
    quality: $('#quality'),
    scale: $('#scale'),
    fps: $('#fps'),
    viewport: $('#viewport'),
    canvas: $('#screen'),
    overlay: $('#overlay'),
    overlayTitle: $('#overlay-title'),
    overlayText: $('#overlay-text'),
    overlayAction: $('#overlay-action'),
    btnGame: $('#btn-game'),
    btnWin: $('#btn-win'),
    remoteCursor: $('#remote-cursor'),
    toast: $('#toast'),
    btnText: $('#btn-text'),
    btnRefresh: $('#btn-refresh'),
    btnFull: $('#btn-full'),
    btnLeave: $('#btn-leave'),
    textDialog: $('#text-dialog'),
    textInput: $('#text-input'),
  };

  const ctx2d = ui.canvas.getContext('2d', { alpha: false, desynchronized: true });

  const state = {
    ws: null,
    encKey: null,
    authKeyHex: null,
    hostOnline: false,
    remoteW: 0,
    remoteH: 0,
    monitors: [],
    held: new Map(), // code -> {key, code} currently pressed on the remote
    pendingMove: null,
    moveRaf: 0,
    gameMode: false,
    remoteHidden: false, // the desktop's foreground app hid the cursor (a game took the mouse)
    autoLocked: false, // pointer lock we took because of remoteHidden (released when the cursor returns)
    delta: { x: 0, y: 0 }, // accumulated relative motion while the pointer is locked
    deltaRaf: 0,
    link: null, // {q, s, auto, codec, enc} reported by the host
    videoSupported: false,
    decoder: null,
    decoderHasKey: false,
    videoW: 0,
    videoH: 0,
    videoTs: 0,
    lastSeq: -1,
    ackTimer: 0,
    toastTimer: 0,
    sendChain: Promise.resolve(),
    recvChain: Promise.resolve(),
    frames: 0,
    bytes: 0,
    latency: null,
    decryptFailures: 0,
    timers: [],
    leaving: false,
  };

  // ---- Key derivation & crypto -----------------------------------------

  // The security answer is part of the secret: password + normalized answer feed the KDF together.
  function combinedSecret(password, answer) {
    return `${password}\n${answer.trim().toLowerCase().replace(/\s+/g, ' ')}`;
  }

  async function deriveKeys(password, answer) {
    if (!crypto.subtle) throw new Error('This page needs HTTPS (or localhost) for Web Crypto.');
    const base = await crypto.subtle.importKey('raw', enc.encode(combinedSecret(password, answer)), 'PBKDF2', false, ['deriveBits']);
    const derive = (salt) =>
      crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: PBKDF2_ITERATIONS }, base, 256);
    const [authBits, encBits] = await Promise.all([derive('remoto:auth:v1'), derive('remoto:enc:v1')]);
    const encKey = await crypto.subtle.importKey('raw', encBits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { authKeyHex: hex(new Uint8Array(authBits)), encKey };
  }

  function hex(bytes) {
    let s = '';
    for (const b of bytes) s += b.toString(16).padStart(2, '0');
    return s;
  }

  async function seal(plain) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD_V2H }, state.encKey, plain));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv, 0);
    out.set(ct, 12);
    return out;
  }

  async function open(buf) {
    const u = new Uint8Array(buf);
    if (u.length < 12 + 16 + 1) throw new Error('short message');
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: u.subarray(0, 12), additionalData: AAD_H2V },
      state.encKey,
      u.subarray(12),
    );
    return new Uint8Array(plain);
  }

  // ---- Login ---------------------------------------------------------------

  // Show the security-question field only if the relay has one configured (SECURITY_QUESTION).
  let questionRequired = false;
  (async () => {
    try {
      const cfg = await (await fetch('/api/config', { credentials: 'same-origin' })).json();
      if (cfg.securityQuestion) {
        questionRequired = true;
        ui.answerLabel.textContent = cfg.securityQuestion;
        ui.answerLabel.hidden = false;
        ui.answer.hidden = false;
        ui.answer.required = true;
      }
    } catch { /* no config endpoint -> password only */ }
  })();

  ui.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = ui.password.value;
    const answer = questionRequired ? ui.answer.value : '';
    if (!password || (questionRequired && !answer.trim())) return;
    setBusy(true);
    showLoginError('');
    try {
      const { authKeyHex, encKey } = await deriveKeys(password, answer);
      await loginWith(authKeyHex);
      state.videoSupported = await detectVideo();
      state.encKey = encKey;
      state.authKeyHex = authKeyHex;
      ui.password.value = '';
      ui.answer.value = '';
      showStage();
      connect();
    } catch (err) {
      showLoginError(err.message || 'Login failed.');
    } finally {
      setBusy(false);
    }
  });

  // Hardware H.264 decoding in the browser (Chrome, Edge, Safari 16.4+, Firefox 130+). Falls back to JPEG.
  async function detectVideo() {
    if (!('VideoDecoder' in window) || !('EncodedVideoChunk' in window)) return false;
    try {
      const r = await VideoDecoder.isConfigSupported({ codec: 'avc1.64001F', optimizeForLatency: true });
      return !!r.supported;
    } catch {
      return false;
    }
  }

  async function loginWith(authKeyHex) {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authKey: authKeyHex }),
      credentials: 'same-origin',
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `Login failed (${res.status}).`);
    }
  }

  function setBusy(busy) {
    ui.connect.disabled = busy;
    ui.connect.textContent = busy ? 'Deriving keys…' : 'Connect';
  }

  function showLoginError(msg) {
    ui.loginError.textContent = msg;
    ui.loginError.hidden = !msg;
  }

  function showStage() {
    ui.login.hidden = true;
    ui.stage.hidden = false;
    layout();
    ui.canvas.focus();
  }

  function showLogin(message) {
    ui.stage.hidden = true;
    ui.login.hidden = false;
    showLoginError(message || '');
    ui.password.focus();
  }

  // ---- Connection --------------------------------------------------------

  function connect() {
    state.leaving = false;
    state.decryptFailures = 0;
    setStatus('Connecting…', '');
    showOverlay('Connecting to the relay…', '');
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/viewer`);
    ws.binaryType = 'arraybuffer';
    state.ws = ws;

    ws.onopen = () => {
      setStatus('Connected', 'ok');
      startTimers();
      sendConfig();
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') onControl(ev.data);
      else onCipher(ev.data);
    };
    ws.onclose = (ev) => {
      if (state.ws !== ws) return;
      state.ws = null;
      stopTimers();
      resetDecoder();
      state.held.clear();
      setStatus('Disconnected', 'bad');
      if (state.leaving) return;
      showOverlay('Disconnected', ev.reason || 'The connection to the relay was closed.', 'Reconnect', reconnect);
    };
    ws.onerror = () => {
      /* onclose follows */
    };
  }

  async function reconnect() {
    // The cookie may have expired; refresh it with the still-in-memory auth key.
    try {
      const res = await fetch('/api/session', { credentials: 'same-origin' });
      if (!res.ok) await loginWith(state.authKeyHex);
      connect();
    } catch (err) {
      showLogin(err.message || 'Please sign in again.');
    }
  }

  async function leave() {
    state.leaving = true;
    if (state.gameMode) exitGameMode();
    releaseAllRemote();
    await state.sendChain; // let the key-up messages go out first
    if (state.ws) state.ws.close(1000, 'Viewer left');
    fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    state.encKey = null;
    state.authKeyHex = null;
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    showLogin('');
  }

  function onControl(text) {
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }
    if (msg.type !== 'relay') return;
    const wasOnline = state.hostOnline;
    state.hostOnline = !!msg.hostOnline;
    if (state.hostOnline) {
      hideOverlay();
      setStatus(msg.viewers > 1 ? `Connected · ${msg.viewers} viewers` : 'Connected', 'ok');
      if (!wasOnline) sendConfig();
    } else {
      setStatus('Host offline', 'warn');
      showOverlay('Waiting for the desktop…', 'The host agent is not connected to the relay. Start it on your desktop and this page will pick it up automatically.');
    }
  }

  function onCipher(buf) {
    state.bytes += buf.byteLength;
    state.recvChain = state.recvChain
      .then(() => handleCipher(buf))
      .catch((err) => {
        state.decryptFailures++;
        console.warn('Dropped message:', err);
        if (state.decryptFailures >= 5 && state.ws) {
          state.ws.close(4001, 'Could not decrypt host messages');
          showOverlay('Encryption mismatch', 'The host is using a different password than this session. Restart the host agent with the same password.', 'Reconnect', reconnect);
        }
      });
  }

  async function handleCipher(buf) {
    const plain = await open(buf);
    state.decryptFailures = 0;
    if (plain[0] === MSG_FRAME) await drawFrame(plain);
    else if (plain[0] === MSG_VIDEO) handleVideo(plain);
    else if (plain[0] === MSG_JSON) onHostJson(JSON.parse(dec.decode(plain.subarray(1))));
  }

  function onHostJson(msg) {
    switch (msg.t) {
      case 'meta':
        ui.hostname.textContent = msg.host ? `· ${msg.host}` : '';
        state.monitors = Array.isArray(msg.monitors) ? msg.monitors : [];
        renderMonitors(msg.monitor);
        break;
      case 'pong':
        if (typeof msg.p === 'number') state.latency = Math.max(0, performance.now() - msg.p);
        if (typeof msg.q === 'number') state.link = { q: msg.q, s: msg.s, auto: !!msg.auto, codec: msg.codec, enc: msg.enc };
        break;
      case 'cur':
        onRemoteCursor(msg);
        break;
    }
  }

  // ---- Frames --------------------------------------------------------------

  async function drawFrame(u8) {
    const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const seq = view.getUint32(1, true);
    const w = view.getUint16(5, true);
    const h = view.getUint16(7, true);
    const n = view.getUint8(9);
    let off = 10;
    const regions = [];
    for (let i = 0; i < n; i++) {
      const x = view.getUint16(off, true);
      const y = view.getUint16(off + 2, true);
      const rw = view.getUint16(off + 4, true);
      const rh = view.getUint16(off + 6, true);
      const len = view.getUint32(off + 8, true);
      off += 12;
      regions.push({ x, y, rw, rh, blob: new Blob([u8.subarray(off, off + len)], { type: 'image/jpeg' }) });
      off += len;
    }
    if (w !== state.remoteW || h !== state.remoteH) {
      state.remoteW = w;
      state.remoteH = h;
      ui.canvas.width = w;
      ui.canvas.height = h;
      layout();
    }
    const bitmaps = await Promise.all(regions.map((r) => createImageBitmap(r.blob)));
    bitmaps.forEach((bmp, i) => {
      ctx2d.drawImage(bmp, regions[i].x, regions[i].y);
      bmp.close();
    });
    state.frames++;
    send({ t: 'ack', seq });
  }

  // ---- Video (H.264 via WebCodecs) ----------------------------------------

  function spsCodecString(data) {
    // Find the SPS NAL (type 7) in the Annex B stream and build avc1.PPCCLL from its first bytes.
    for (let i = 0; i + 4 < data.length; i++) {
      if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1 && (data[i + 3] & 0x1f) === 7) {
        const hex = (b) => b.toString(16).padStart(2, '0');
        return `avc1.${hex(data[i + 4])}${hex(data[i + 5])}${hex(data[i + 6])}`;
      }
    }
    return 'avc1.64001F';
  }

  function resetDecoder() {
    if (state.decoder) {
      try {
        state.decoder.close();
      } catch {
        /* already closed */
      }
    }
    state.decoder = null;
    state.decoderHasKey = false;
  }

  function configureDecoder(w, h, data) {
    resetDecoder();
    const decoder = new VideoDecoder({
      output: (frame) => {
        try {
          ctx2d.drawImage(frame, 0, 0);
          state.frames++;
        } finally {
          frame.close();
        }
      },
      error: (err) => {
        console.warn('video decoder error', err);
        resetDecoder();
        send({ t: 'kf' });
      },
    });
    decoder.configure({ codec: spsCodecString(data), codedWidth: w, codedHeight: h, optimizeForLatency: true });
    state.decoder = decoder;
    state.videoW = w;
    state.videoH = h;
    if (w !== state.remoteW || h !== state.remoteH) {
      state.remoteW = w;
      state.remoteH = h;
      ui.canvas.width = w;
      ui.canvas.height = h;
      layout();
    }
  }

  function handleVideo(u8) {
    const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const seq = view.getUint32(1, true);
    const w = view.getUint16(5, true);
    const h = view.getUint16(7, true);
    const key = (view.getUint8(9) & 1) === 1;
    const data = u8.subarray(10);
    scheduleAck(seq);
    if (key && (!state.decoder || state.decoder.state !== 'configured' || w !== state.videoW || h !== state.videoH)) {
      try {
        configureDecoder(w, h, data);
      } catch (err) {
        console.warn('cannot configure video decoder', err);
        return;
      }
    }
    if (!state.decoder || state.decoder.state !== 'configured') return; // waiting for a keyframe
    if (!key && !state.decoderHasKey) return;
    if (state.decoder.decodeQueueSize > 12) {
      // Decoder can't keep up: drop until the next keyframe rather than build latency.
      state.decoderHasKey = false;
      send({ t: 'kf' });
      return;
    }
    try {
      state.videoTs += 16667;
      state.decoder.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: state.videoTs, data }));
      state.decoderHasKey = true;
    } catch (err) {
      console.warn('decode failed', err);
      resetDecoder();
      send({ t: 'kf' });
    }
  }

  // Acks are cumulative on the host; coalesce them so the relay sees far fewer messages at 60 fps.
  function scheduleAck(seq) {
    state.lastSeq = seq;
    if (!state.ackTimer) {
      state.ackTimer = setTimeout(() => {
        state.ackTimer = 0;
        send({ t: 'ack', seq: state.lastSeq });
      }, 25);
    }
  }

  function layout() {
    if (!state.remoteW || !state.remoteH) return;
    const vw = ui.viewport.clientWidth;
    const vh = ui.viewport.clientHeight;
    const s = Math.min(vw / state.remoteW, vh / state.remoteH);
    ui.canvas.style.width = `${Math.floor(state.remoteW * s)}px`;
    ui.canvas.style.height = `${Math.floor(state.remoteH * s)}px`;
  }
  window.addEventListener('resize', layout);

  // ---- Sending -------------------------------------------------------------

  function send(obj) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN || !state.encKey) return;
    obj.ts = Date.now();
    const plain = enc.encode(JSON.stringify(obj));
    const framed = new Uint8Array(1 + plain.length);
    framed[0] = MSG_JSON;
    framed.set(plain, 1);
    // Serialize so key-down always arrives before key-up, etc.
    state.sendChain = state.sendChain
      .then(async () => {
        const sealed = await seal(framed);
        if (state.ws && state.ws.readyState === WebSocket.OPEN) state.ws.send(sealed);
      })
      .catch((err) => console.warn('send failed', err));
  }

  function sendConfig() {
    send({
      t: 'cfg',
      codec: state.videoSupported ? 'h264' : 'jpeg',
      quality: ui.quality.value === 'auto' ? 'auto' : Number(ui.quality.value),
      scale: ui.scale.value === 'auto' ? 'auto' : Number(ui.scale.value),
      fps: Number(ui.fps.value),
    });
    send({ t: 'kf' });
  }

  // ---- Pointer input -------------------------------------------------------

  function normalized(e) {
    const r = ui.canvas.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return null;
    const x = Math.min(1, Math.max(0, (e.clientX - r.left) / r.width));
    const y = Math.min(1, Math.max(0, (e.clientY - r.top) / r.height));
    return { x, y };
  }

  function flushMove() {
    state.moveRaf = 0;
    if (state.pendingMove) {
      send({ t: 'mm', x: state.pendingMove.x, y: state.pendingMove.y });
      state.pendingMove = null;
    }
  }

  // Game mode: the browser captures the mouse (Pointer Lock) and we forward raw deltas,
  // which is what games read. Outside game mode we send absolute positions.
  function pointerLocked() {
    return document.pointerLockElement === ui.canvas;
  }

  function flushDelta() {
    state.deltaRaf = 0;
    const dx = Math.trunc(state.delta.x);
    const dy = Math.trunc(state.delta.y);
    state.delta.x -= dx;
    state.delta.y -= dy;
    if (dx || dy) send({ t: 'mr', dx, dy });
  }

  ui.canvas.addEventListener('pointermove', (e) => {
    if (pointerLocked()) {
      const events = e.getCoalescedEvents ? e.getCoalescedEvents() : [];
      for (const ev of events.length ? events : [e]) {
        state.delta.x += ev.movementX;
        state.delta.y += ev.movementY;
      }
      if (!state.deltaRaf) state.deltaRaf = requestAnimationFrame(flushDelta);
      return;
    }
    if (state.remoteHidden) return; // game wants deltas; absolute positions would spin the camera
    const p = normalized(e);
    if (!p) return;
    state.pendingMove = p;
    if (!state.moveRaf) state.moveRaf = requestAnimationFrame(flushMove);
  });

  ui.canvas.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    ui.canvas.focus();
    if ((state.gameMode || state.remoteHidden) && !pointerLocked()) {
      // User gesture: capture now (game mode, or the game hid the cursor and wants raw motion).
      lockPointer().then(() => {
        if (pointerLocked()) state.autoLocked = !state.gameMode;
      });
    }
    if (pointerLocked() || state.remoteHidden) {
      send({ t: 'md', b: e.button });
      return;
    }
    ui.canvas.setPointerCapture(e.pointerId);
    const p = normalized(e);
    if (!p) return;
    state.pendingMove = null;
    send({ t: 'mm', x: p.x, y: p.y });
    send({ t: 'md', b: e.button });
  });

  ui.canvas.addEventListener('pointerup', (e) => {
    e.preventDefault();
    if (!pointerLocked() && !state.remoteHidden) {
      const p = normalized(e);
      if (p) send({ t: 'mm', x: p.x, y: p.y });
    }
    send({ t: 'mu', b: e.button });
  });

  async function lockPointer() {
    try {
      await ui.canvas.requestPointerLock({ unadjustedMovement: true }); // raw, unaccelerated deltas
    } catch {
      try {
        await ui.canvas.requestPointerLock();
      } catch (err) {
        console.warn('pointer lock', err);
      }
    }
  }

  async function enterGameMode() {
    state.gameMode = true;
    ui.btnGame.classList.add('active');
    try {
      if (!document.fullscreenElement) {
        await ui.stage.requestFullscreen({ navigationUI: 'hide' });
        if (navigator.keyboard && navigator.keyboard.lock) await navigator.keyboard.lock().catch(() => {});
      }
    } catch (err) {
      console.warn('fullscreen', err);
    }
    await lockPointer();
    ui.canvas.focus();
  }

  function exitGameMode() {
    state.gameMode = false;
    ui.btnGame.classList.remove('active');
    ui.remoteCursor.hidden = true;
    if (pointerLocked()) document.exitPointerLock();
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  }

  document.addEventListener('pointerlockchange', () => {
    if (pointerLocked()) {
      toast(state.gameMode ? 'Game mode — mouse captured. Hold Esc to leave.' : 'Mouse captured by the game. Press Esc to release; 🎮 for fullscreen.');
    } else {
      ui.remoteCursor.hidden = true;
      state.autoLocked = false;
      if (state.gameMode) toast('Mouse released — click the screen to recapture, or press 🎮 to leave game mode.');
      else if (state.remoteHidden) toast('Mouse released — click the screen to give it back to the game.');
    }
  });
  document.addEventListener('pointerlockerror', () => toast('Click the screen to capture the mouse.'));

  // Follow the game: when the desktop app hides the cursor it wants raw motion, so capture the mouse;
  // when the cursor comes back (menus, desktop) release it so normal pointing works again.
  function onRemoteCursor(msg) {
    const hidden = !!msg.hidden;
    if (hidden !== state.remoteHidden) {
      state.remoteHidden = hidden;
      if (hidden && !pointerLocked()) {
        lockPointer().then(() => {
          if (pointerLocked()) state.autoLocked = true;
          else if (!state.gameMode) toast('The game took the mouse — click the screen to control it.');
        });
      } else if (!hidden && state.autoLocked && !state.gameMode && pointerLocked()) {
        state.autoLocked = false;
        document.exitPointerLock();
      }
    }
    // While captured, the desktop cursor is only visible if the app shows it (menus).
    if (pointerLocked() && !hidden && typeof msg.x === 'number' && typeof msg.y === 'number') placeRemoteCursor(msg.x, msg.y);
    else if (hidden) ui.remoteCursor.hidden = true;
  }

  function placeRemoteCursor(nx, ny) {
    const r = ui.canvas.getBoundingClientRect();
    const v = ui.viewport.getBoundingClientRect();
    ui.remoteCursor.style.transform = `translate(${r.left - v.left + nx * r.width}px, ${r.top - v.top + ny * r.height}px)`;
    ui.remoteCursor.hidden = false;
  }

  function toast(text) {
    ui.toast.textContent = text;
    ui.toast.hidden = false;
    requestAnimationFrame(() => ui.toast.classList.add('show'));
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => {
      ui.toast.classList.remove('show');
      setTimeout(() => (ui.toast.hidden = true), 250);
    }, 2500);
  }

  ui.canvas.addEventListener('contextmenu', (e) => e.preventDefault());

  ui.canvas.addEventListener(
    'wheel',
    (e) => {
      e.preventDefault();
      const unit = e.deltaMode === 1 ? 3 : e.deltaMode === 2 ? 1 : 100; // lines / pages / pixels -> notches
      const dx = e.deltaMode === 2 ? e.deltaX : e.deltaX / unit;
      const dy = e.deltaMode === 2 ? e.deltaY : e.deltaY / unit;
      send({ t: 'wh', dx: round3(dx), dy: round3(dy) });
    },
    { passive: false },
  );

  function round3(v) {
    return Math.round(v * 1000) / 1000;
  }

  // ---- Keyboard input ------------------------------------------------------

  function keyboardCaptured() {
    if (ui.stage.hidden || !state.ws) return false;
    const a = document.activeElement;
    if (ui.textDialog.open) return false;
    return a === ui.canvas || a === document.body || a === null;
  }

  document.addEventListener('keydown', (e) => {
    if (!keyboardCaptured()) return;
    e.preventDefault();
    state.held.set(e.code || e.key, { key: e.key, code: e.code });
    send({ t: 'kd', key: e.key, code: e.code, r: e.repeat ? 1 : 0 });
  });

  document.addEventListener('keyup', (e) => {
    if (!keyboardCaptured() && !state.held.has(e.code || e.key)) return;
    e.preventDefault();
    state.held.delete(e.code || e.key);
    send({ t: 'ku', key: e.key, code: e.code });
  });

  function releaseAllRemote() {
    for (const k of state.held.values()) send({ t: 'ku', key: k.key, code: k.code });
    state.held.clear();
  }
  window.addEventListener('blur', releaseAllRemote);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) releaseAllRemote();
  });

  // ---- Toolbar -------------------------------------------------------------

  ui.quality.addEventListener('change', sendConfig);
  ui.scale.addEventListener('change', sendConfig);
  ui.fps.addEventListener('change', sendConfig);
  ui.monitor.addEventListener('change', () => send({ t: 'mon', i: Number(ui.monitor.value) }));
  ui.btnRefresh.addEventListener('click', () => {
    send({ t: 'kf' });
    ui.canvas.focus();
  });
  ui.btnGame.addEventListener('click', () => {
    if (state.gameMode) exitGameMode();
    else enterGameMode();
  });
  ui.btnWin.addEventListener('click', () => {
    send({ t: 'tap', keys: ['Meta'] });
    ui.canvas.focus();
  });
  ui.btnLeave.addEventListener('click', leave);
  ui.overlayAction.addEventListener('click', () => {
    const fn = ui.overlayAction._handler;
    if (fn) fn();
  });

  ui.btnText.addEventListener('click', () => {
    ui.textInput.value = '';
    ui.textDialog.showModal();
    ui.textInput.focus();
  });
  ui.textDialog.addEventListener('close', () => {
    if (ui.textDialog.returnValue === 'send' && ui.textInput.value) send({ t: 'type', text: ui.textInput.value.slice(0, 5000) });
    ui.textInput.value = '';
    ui.canvas.focus();
  });

  ui.btnFull.addEventListener('click', async () => {
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
      } else {
        await ui.stage.requestFullscreen({ navigationUI: 'hide' });
        // Capture Alt+Tab, Win, Ctrl+W… while fullscreen (Chromium). Hold Esc to leave.
        if (navigator.keyboard && navigator.keyboard.lock) await navigator.keyboard.lock().catch(() => {});
      }
    } catch (err) {
      console.warn('fullscreen', err);
    }
    ui.canvas.focus();
  });
  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement) {
      if (navigator.keyboard && navigator.keyboard.unlock) navigator.keyboard.unlock();
      ui.stage.classList.remove('show-bar');
      if (state.gameMode) exitGameMode(); // leaving fullscreen ends game mode
    }
    layout();
  });
  ui.hotzone.addEventListener('pointerenter', () => ui.stage.classList.add('show-bar'));
  ui.bar.addEventListener('pointerleave', () => {
    if (document.fullscreenElement) ui.stage.classList.remove('show-bar');
  });

  function renderMonitors(current) {
    ui.monitor.innerHTML = '';
    for (const m of state.monitors) {
      const opt = document.createElement('option');
      opt.value = String(m.i);
      opt.textContent = m.i === 0 ? `All monitors (${m.w}×${m.h})` : `Monitor ${m.i} (${m.w}×${m.h})${m.primary ? ' ★' : ''}`;
      opt.selected = m.i === current;
      ui.monitor.appendChild(opt);
    }
    ui.monitor.hidden = state.monitors.length <= 2; // "all" + one monitor: nothing to choose
  }

  // ---- Status, overlay, timers --------------------------------------------

  function setStatus(text, kind) {
    ui.status.textContent = text;
    ui.status.className = `pill ${kind}`;
  }

  function showOverlay(title, text, actionLabel, action) {
    ui.overlayTitle.textContent = title;
    ui.overlayText.textContent = text || '';
    ui.overlayText.hidden = !text;
    ui.overlayAction.hidden = !actionLabel;
    ui.overlayAction.textContent = actionLabel || '';
    ui.overlayAction._handler = action || null;
    ui.overlay.hidden = false;
  }

  function hideOverlay() {
    ui.overlay.hidden = true;
  }

  function startTimers() {
    stopTimers();
    state.frames = 0;
    state.bytes = 0;
    state.latency = null;
    state.timers.push(
      setInterval(() => {
        const ms = state.latency == null ? '—' : Math.round(state.latency);
        let link = '';
        if (state.link && state.link.codec === 'h264') {
          const enc = (state.link.enc || 'h264').replace('h264_', '').replace('lib', '');
          link = ` · ${state.link.auto ? 'auto ' : ''}${(state.link.q / 1000).toFixed(1)} Mb/s · ${Math.round(state.link.s * 100)}% · ${enc}`;
        } else if (state.link) {
          link = ` · ${state.link.auto ? 'auto ' : ''}${Math.round(state.link.s * 100)}% q${state.link.q} · jpeg`;
        }
        ui.stats.textContent = `${state.frames} updates/s · ${Math.round(state.bytes / 1024)} KB/s · ${ms} ms${link}`;
        state.frames = 0;
        state.bytes = 0;
      }, 1000),
      setInterval(() => send({ t: 'ping', p: performance.now() }), 2000),
      setInterval(() => {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) state.ws.send('ping'); // relay keepalive
      }, 20000),
    );
  }

  function stopTimers() {
    for (const t of state.timers) clearInterval(t);
    state.timers = [];
  }

  // Close cleanly when the tab goes away so the relay frees the single viewer slot right away.
  for (const evt of ['beforeunload', 'pagehide']) {
    window.addEventListener(evt, () => {
      if (state.ws) state.ws.close(1000, 'Page closed');
    });
  }
})();
