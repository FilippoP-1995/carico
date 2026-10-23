// Carico · server notifiche (Cloudflare Worker + KV)
// Stato per utente in KV ("u:<id>"), indice degli utenti in "index", chiavi VAPID in "vapid".
// Il cron gira ogni minuto: per ogni utente calcola l'ora locale e invia i promemoria in scadenza.

const SUBJECT = "https://filippop-1995.github.io/carico/";
const enc = new TextEncoder();

// ---------- utilità base64url ----------
const b64u = buf => {
  const b = new Uint8Array(buf); let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const unb64u = str => {
  str = str.replace(/-/g, "+").replace(/_/g, "/"); while (str.length % 4) str += "=";
  const s = atob(str); const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
};
const concat = (...arrs) => {
  const n = arrs.reduce((a, x) => a + x.length, 0); const out = new Uint8Array(n); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};

// ---------- VAPID ----------
async function vapidKeys(env) {
  const saved = await env.KV.get("vapid", "json");
  if (saved) return saved;
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
  const pub = b64u(await crypto.subtle.exportKey("raw", kp.publicKey));
  const keys = { priv, pub };
  await env.KV.put("vapid", JSON.stringify(keys));
  return keys;
}
async function vapidAuth(keys, endpoint) {
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const body = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT })));
  const key = await crypto.subtle.importKey("jwk", keys.priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(head + "." + body));
  return `vapid t=${head}.${body}.${b64u(sig)}, k=${keys.pub}`;
}

// ---------- cifratura aes128gcm (RFC 8291) ----------
async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
export async function encryptPayload(sub, text, salt) {
  const uaPub = unb64u(sub.keys.p256dh); const auth = unb64u(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", as.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, as.privateKey, 256));
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  const prkKey = await hmac(auth, shared);
  const ikm = await hmac(prkKey, concat(enc.encode("WebPush: info\0"), uaPub, asPub, new Uint8Array([1])));
  const prk = await hmac(salt, ikm);
  const cek = (await hmac(prk, concat(enc.encode("Content-Encoding: aes128gcm\0"), new Uint8Array([1])))).slice(0, 16);
  const nonce = (await hmac(prk, concat(enc.encode("Content-Encoding: nonce\0"), new Uint8Array([1])))).slice(0, 12);
  const key = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, concat(enc.encode(text), new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}
async function sendPush(env, keys, sub, msg) {
  const body = await encryptPayload(sub, JSON.stringify(msg));
  const r = await fetch(sub.endpoint, {
    method: "POST",
    headers: { TTL: "3600", Urgency: "high", "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", Authorization: await vapidAuth(keys, sub.endpoint) },
    body,
  });
  return r.status;
}

// ---------- logica promemoria ----------
function localNow(tz, now) {
  const f = new Intl.DateTimeFormat("en-GB", { timeZone: tz || "Europe/Rome", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23" });
  const p = Object.fromEntries(f.formatToParts(now).map(x => [x.type, x.value]));
  const wd = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }[p.weekday];
  return { date: `${p.year}-${p.month}-${p.day}`, hm: `${p.hour}:${p.minute}`, min: +p.hour * 60 + +p.minute, wd };
}
function hash(str) { let h = 2166136261; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
const pick = (arr, seed) => arr && arr.length ? arr[hash(seed) % arr.length] : "";
const toMin = t => { const m = /^(\d{1,2}):(\d{2})$/.exec(t || ""); return m ? +m[1] * 60 + +m[2] : -1; };
const fill = (s, v) => String(s || "").replace(/\{(\w+)\}/g, (_, k) => v[k] != null ? v[k] : "");

// Restituisce le notifiche da inviare per un utente in questo minuto.
export function dueMessages(u, now) {
  const c = u.cfg || {}; const R = c.rem || {}; const B = c.bank || {}; const L = localNow(c.tz, now);
  const st = (c.today && c.today.date === L.date) ? c.today : { eaten: [], wDone: false };
  const seed = u.id + L.date + L.hm; const out = [];
  const at = r => r && r.on && r.t === L.hm;
  const planned = c.plan && Object.prototype.hasOwnProperty.call(c.plan, L.date) ? c.plan[L.date] : undefined; // con il programma: solo nei giorni con una seduta
  if (at(R.work) && !st.wDone && (planned !== undefined ? !!planned : (!R.work.days || R.work.days.includes(L.wd))))
    out.push({ title: "🏋️ Allenamento", body: fill(pick(B.work, seed + "w"), { next: planned || c.next || "il tuo allenamento" }), tag: "work", go: "allenamento" });
  for (const [k, r] of Object.entries(R.meals || {})) {
    if (at(r) && !(st.eaten || []).includes(k))
      out.push({ title: "🍽️ " + (r.name || "Pasto"), body: fill(pick(B.meal, seed + k), { meal: (r.name || "il pasto").toLowerCase() }), tag: "meal-" + k, go: "dieta" });
  }
  if (at(R.weigh)) out.push({ title: "⚖️ Pesata", body: pick(B.weigh, seed + "p"), tag: "weigh", go: "oggi" });
  if (at(R.water)) out.push({ title: "💧 Acqua", body: pick(B.water, seed + "a"), tag: "water", go: "oggi" });
  if (at(R.check) && L.wd === (c.checkDay == null ? 6 : c.checkDay)) out.push({ title: "📋 Check settimanale", body: pick(B.check, seed + "c"), tag: "check", go: "oggi" });
  // frasi del coach: N orari pseudo-casuali al giorno nella finestra scelta
  const co = c.coach || {}; const n = Math.min(+co.n || 0, 5);
  const a = toMin(co.from || "09:00"), b = toMin(co.to || "21:00");
  if (n > 0 && a >= 0 && b > a) {
    const span = b - a;
    for (let i = 0; i < n; i++) {
      const m = a + Math.floor(span * (i + (hash(u.id + L.date + i) % 1000) / 1000) / n);
      if (m === L.min) out.push({ title: c.coachTitle || "💬 Il Coach", body: pick(B.coachP && B.coachP.d === L.date && (B.coachP.lines || []).length ? B.coachP.lines : B.coach, u.id + L.date + "q" + i), tag: "coach", go: "oggi" });
    }
  }
  return out.filter(m => m.body);
}

// ---------- HTTP ----------
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-Carico-Code, X-Carico-Id" };
const MODELS = ["claude-sonnet-5-5", "claude-haiku-5-5"];

// ---------- AI condivisa: la chiave del proprietario resta qui, gli amici entrano con il codice invito ----------
async function aiProxy(req, env) {
  if (!env.ANTHROPIC_KEY || !env.CARICO_CODE) return json({ error: "not_configured" }, 503);
  const code = req.headers.get("X-Carico-Code") || "";
  if (code !== env.CARICO_CODE) return json({ error: "bad_code" }, 401);
  const id = (req.headers.get("X-Carico-Id") || "anon").replace(/[^a-z0-9]/gi, "").slice(0, 40) || "anon";
  const day = new Date().toISOString().slice(0, 10);
  const perDev = +(env.DAILY_LIMIT || 60), total = +(env.TOTAL_LIMIT || 500);
  const kd = `rl:${id}:${day}`, kt = `rl:all:${day}`;
  const [nd, nt] = await Promise.all([env.KV.get(kd), env.KV.get(kt)]);
  if (+(nd || 0) >= perDev) return json({ error: "daily_limit", limit: perDev }, 429);
  if (+(nt || 0) >= total) return json({ error: "daily_limit_total" }, 429);
  let body; try { body = await req.json(); } catch (e) { return json({ error: "bad_body" }, 400); }
  if (!MODELS.includes(body.model)) body.model = MODELS[0];
  body.max_tokens = Math.min(+body.max_tokens || 2000, 32000);
  await Promise.all([env.KV.put(kd, String(+(nd || 0) + 1), { expirationTtl: 172800 }), env.KV.put(kt, String(+(nt || 0) + 1), { expirationTtl: 172800 })]);
  const up = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "content-type": "application/json", "x-api-key": env.ANTHROPIC_KEY, "anthropic-version": "2023-06-01" }, body: JSON.stringify(body) });
  return new Response(up.body, { status: up.status, headers: { ...CORS, "Content-Type": up.headers.get("content-type") || "application/json", "Cache-Control": "no-cache" } });
}
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...CORS, "Content-Type": "application/json" } });
const validId = id => typeof id === "string" && /^[a-z0-9]{8,40}$/i.test(id);

async function addIndex(env, id) {
  const idx = (await env.KV.get("index", "json")) || [];
  if (!idx.includes(id)) { idx.push(id); await env.KV.put("index", JSON.stringify(idx)); }
}
async function delUser(env, id) {
  await env.KV.delete("u:" + id);
  const idx = (await env.KV.get("index", "json")) || [];
  if (idx.includes(id)) await env.KV.put("index", JSON.stringify(idx.filter(x => x !== id)));
}


// ---------- chat di gruppo in tempo reale (Durable Object con WebSocket, una stanza per gruppo) ----------
export class ChatRoom {
  constructor(ctx, env) {
    this.ctx = ctx; this.env = env; this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS m (id INTEGER PRIMARY KEY AUTOINCREMENT, cid TEXT, mid TEXT, name TEXT, tx TEXT, ph TEXT, sys INTEGER DEFAULT 0, at INTEGER, r TEXT DEFAULT '{}')`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS p (id TEXT PRIMARY KEY, data TEXT, at INTEGER)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)`);
  }
  row(x) { return { id: x.id, cid: x.cid, mid: x.mid, name: x.name, tx: x.tx, ph: x.ph || null, sys: !!x.sys, at: x.at, r: JSON.parse(x.r || "{}") }; }
  recent(n = 60, before = null) {
    const rows = before ? this.sql.exec("SELECT * FROM m WHERE id < ? ORDER BY id DESC LIMIT ?", before, n).toArray() : this.sql.exec("SELECT * FROM m ORDER BY id DESC LIMIT ?", n).toArray();
    return rows.reverse().map(x => this.row(x));
  }
  since(id) { return this.sql.exec("SELECT * FROM m WHERE id > ? ORDER BY id ASC LIMIT 200", id).toArray().map(x => this.row(x)); }
  broadcast(obj, except) { const s = JSON.stringify(obj); for (const ws of this.ctx.getWebSockets()) { if (ws === except) continue; try { ws.send(s); } catch (e) {} } }
  online() { return new Set(this.ctx.getWebSockets().map(ws => (this.ctx.getTags(ws) || [])[0]).filter(Boolean)); }
  prune() { // ultimi 1000 messaggi / 90 giorni, ultime 300 foto
    const lim = Date.now() - 90 * 864e5; this.sql.exec("DELETE FROM m WHERE at < ? OR id <= (SELECT id FROM m ORDER BY id DESC LIMIT 1 OFFSET 1000)", lim);
    this.sql.exec("DELETE FROM p WHERE id NOT IN (SELECT id FROM p ORDER BY at DESC LIMIT 300)");
  }
  add(m) {
    const cur = this.sql.exec("INSERT INTO m (cid, mid, name, tx, ph, sys, at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *", m.cid || "", m.mid, m.name, m.tx || "", m.ph || null, m.sys ? 1 : 0, Date.now()).toArray()[0];
    if (cur.id % 50 === 0) this.prune(); return this.row(cur);
  }
  async notify(msg, room) { // push solo a chi l'ha chiesto e non ha la chat aperta, al massimo uno al minuto
    try {
      const g = await this.env.KV.get("g:" + room, "json"); if (!g) return; const on = this.online(); let keys = null; const now = Date.now();
      for (const [id, mm] of Object.entries(g.members || {})) {
        if (id === msg.mid || !mm.cn || on.has(id)) continue;
        const lk = "last:" + id; const last = +((this.sql.exec("SELECT v FROM kv WHERE k = ?", lk).toArray()[0] || {}).v || 0); if (now - last < 60000) continue;
        const u = await this.env.KV.get("u:" + mm.cn, "json"); if (!u) continue; keys = keys || await vapidKeys(this.env);
        await sendPush(this.env, keys, u.sub, { title: "💬 " + g.name, body: (msg.sys ? msg.tx : `${msg.name}: ${msg.ph && !msg.tx ? "📷 Foto" : msg.tx}`).slice(0, 160), tag: "chat-" + room, go: "chat" }).catch(() => 0);
        this.sql.exec("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", lk, String(now));
      }
    } catch (e) {}
  }
  async fetch(req) {
    const url = new URL(req.url); const room = url.searchParams.get("room") || "";
    if (url.pathname.endsWith("/ws")) {
      const pair = new WebSocketPair(); const mid = url.searchParams.get("mid"); const name = (url.searchParams.get("name") || "Amico").slice(0, 30);
      this.ctx.acceptWebSocket(pair[1], [mid, name, room]);
      const after = +url.searchParams.get("after") || 0;
      pair[1].send(JSON.stringify({ t: "hello", msgs: after ? this.since(after) : this.recent(60), full: !after }));
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (url.pathname.endsWith("/photo") && req.method === "GET") {
      const r = this.sql.exec("SELECT data FROM p WHERE id = ?", (url.searchParams.get("id") || "").split("_")[0]).toArray()[0]; if (!r) return new Response("no", { status: 404 });
      const bin = Uint8Array.from(atob(r.data), c => c.charCodeAt(0));
      return new Response(bin, { headers: { "Content-Type": "image/jpeg", "Cache-Control": "private, max-age=31536000, immutable", ...CORS } });
    }
    if (url.pathname.endsWith("/sys") && req.method === "POST") { // traguardi della bacheca come messaggi speciali
      const b = await req.json(); for (const e of (b.evs || []).slice(0, 10)) { const m = this.add({ mid: b.mid, name: b.name, tx: `${e.ic} ${b.name} ${e.tx}`, sys: 1 }); this.broadcast({ t: "msg", m }); }
      return new Response("ok");
    }
    return new Response("not found", { status: 404 });
  }
  async webSocketMessage(ws, raw) {
    let d; try { d = JSON.parse(raw); } catch (e) { return; } const [mid, name, room] = this.ctx.getTags(ws) || [];
    if (d.t === "send") {
      const tx = String(d.tx || "").replace(/[<>]/g, "").slice(0, 2000); let ph = null;
      if (d.img && typeof d.img === "string" && d.img.length < 900000) { const pid = crypto.randomUUID().replace(/-/g, "").slice(0, 16); this.sql.exec("INSERT INTO p (id, data, at) VALUES (?, ?, ?)", pid, d.img, Date.now()); const w = Math.min(4000, +d.w || 0), h = Math.min(4000, +d.h || 0); ph = w && h ? `${pid}_${w}x${h}` : pid; }
      if (!tx && !ph) return;
      const m = this.add({ cid: String(d.cid || "").slice(0, 24), mid, name, tx, ph }); this.broadcast({ t: "msg", m });
      this.ctx.waitUntil(this.notify(m, room));
    } else if (d.t === "more") { ws.send(JSON.stringify({ t: "more", msgs: this.recent(50, +d.before || 0) }));
    } else if (d.t === "react") {
      const em = ["🔥", "💪", "👏", "😂", "❤️"].includes(d.em) ? d.em : null; const x = this.sql.exec("SELECT r FROM m WHERE id = ?", +d.id).toArray()[0]; if (!x || !em) return;
      const r = JSON.parse(x.r || "{}"); const L = r[em] = r[em] || []; const i = L.indexOf(mid); if (i >= 0) L.splice(i, 1); else L.push(mid); if (!L.length) delete r[em];
      this.sql.exec("UPDATE m SET r = ? WHERE id = ?", JSON.stringify(r), +d.id); this.broadcast({ t: "react", id: +d.id, r });
    } else if (d.t === "typing") { this.broadcast({ t: "typing", mid, name }, ws); }
    else if (d.t === "ping") { try { ws.send('{"t":"pong"}'); } catch (e) {} }
  }
  async webSocketClose(ws, code) { try { ws.close(code, "bye"); } catch (e) {} }
  async webSocketError() {}
}
async function chatRoute(req, url, env) {
  const code = (url.searchParams.get("code") || "").toUpperCase(); const mid = url.searchParams.get("mid") || "";
  if (!validCode(code) || !validId(mid)) return json({ error: "bad" }, 400);
  if (!env.CHAT) return json({ error: "chat_off" }, 503);
  const g = await env.KV.get(gKey(code), "json"); if (!g) return json({ error: "no_group" }, 404); if (!g.members[mid]) return json({ error: "not_member" }, 403);
  const stub = env.CHAT.get(env.CHAT.idFromName(code)); const u = new URL(req.url); u.searchParams.set("room", code); u.searchParams.set("name", g.members[mid].name || "Amico");
  if (url.pathname === "/chat/ws") { if (req.headers.get("Upgrade") !== "websocket") return json({ error: "ws" }, 426); return stub.fetch(new Request(u.toString().replace("/chat/ws", "/x/ws"), req)); }
  if (url.pathname === "/chat/photo") return stub.fetch(new Request(u.toString().replace("/chat/photo", "/x/photo")));
  return json({ error: "not_found" }, 404);
}

// ---------- gruppi di amici: bacheca traguardi, reazioni, classifica settimanale ----------
const gKey = c => "g:" + c, fKey = c => "gf:" + c, sKey = (c, w) => "gs:" + c + ":" + w;
const validCode = c => typeof c === "string" && /^[A-Z0-9]{6}$/.test(c);
const clean = (t, n) => String(t == null ? "" : t).replace(/[<>]/g, "").slice(0, n);
async function groupApi(path, body, env) {
  const mid = body.mid; if (!validId(mid)) return json({ error: "mid" }, 400);
  if (JSON.stringify(body).length > 12000) return json({ error: "too_big" }, 413);
  const name = clean(body.name || "Amico", 30) || "Amico";
  if (path === "/g/create") {
    let code = ""; for (let i = 0; i < 6; i++) { const A = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; code = Array.from(crypto.getRandomValues(new Uint8Array(6)), b => A[b % A.length]).join(""); if (!(await env.KV.get(gKey(code)))) break; }
    const g = { name: clean(body.gname || "Il gruppo", 40) || "Il gruppo", created: Date.now(), members: { [mid]: { name, joined: Date.now() } } };
    await env.KV.put(gKey(code), JSON.stringify(g)); return json({ ok: true, code, group: g });
  }
  const code = String(body.code || "").toUpperCase(); if (!validCode(code)) return json({ error: "code" }, 400);
  const g = await env.KV.get(gKey(code), "json"); if (!g) return json({ error: "no_group" }, 404);
  if (path === "/g/join") {
    if (!g.members[mid] && Object.keys(g.members).length >= 30) return json({ error: "full" }, 409);
    g.members[mid] = { ...(g.members[mid] || { joined: Date.now() }), name }; await env.KV.put(gKey(code), JSON.stringify(g)); return json({ ok: true, group: g });
  }
  if (!g.members[mid]) return json({ error: "not_member" }, 403);
  if (path === "/g/leave") { delete g.members[mid]; await env.KV.put(gKey(code), JSON.stringify(g)); return json({ ok: true }); }
  if (path === "/g/me") { // nome e preferenza notifiche (id dell'iscrizione push dell'app)
    g.members[mid].name = name; if ("notify" in body) g.members[mid].nid = body.notify && validId(body.nid) ? body.nid : null; if ("chat" in body) g.members[mid].cn = body.chat && validId(body.nid) ? body.nid : null; await env.KV.put(gKey(code), JSON.stringify(g)); return json({ ok: true });
  }
  if (path === "/g/post") {
    const evs = Array.isArray(body.evs) ? body.evs.slice(0, 10) : []; if (!evs.length) return json({ ok: true, added: 0 });
    const feed = (await env.KV.get(fKey(code), "json")) || []; const added = [];
    for (const e of evs) { const k = clean(e.k, 60); if (!k || feed.some(x => x.mid === mid && x.k === k)) continue;
      const it = { id: crypto.randomUUID().slice(0, 12), mid, name, k, ic: clean(e.ic, 4), tx: clean(e.tx, 160), at: Date.now(), r: {} }; feed.unshift(it); added.push(it); }
    if (added.length) { await env.KV.put(fKey(code), JSON.stringify(feed.slice(0, 150)));
      if (env.CHAT) { try { await env.CHAT.get(env.CHAT.idFromName(code)).fetch("https://do/x/sys?room=" + code, { method: "POST", body: JSON.stringify({ mid, name, evs: added }) }); } catch (e) {} }
      let keys = null; // notifiche solo a chi le ha attivate nel gruppo
      for (const [id, m] of Object.entries(g.members)) { if (id === mid || !m.nid) continue; const u = await env.KV.get("u:" + m.nid, "json"); if (!u) continue;
        keys = keys || await vapidKeys(env); const last = added[added.length - 1];
        await sendPush(env, keys, u.sub, { title: "👥 " + g.name, body: `${last.ic} ${name} · ${last.tx}`.slice(0, 180), tag: "group-" + code, go: "progressi" }).catch(() => 0); } }
    return json({ ok: true, added: added.length });
  }
  if (path === "/g/react") {
    const feed = (await env.KV.get(fKey(code), "json")) || []; const it = feed.find(x => x.id === body.eid); const em = ["🔥", "💪", "👏"].includes(body.em) ? body.em : null;
    if (!it || !em) return json({ error: "bad" }, 400);
    const L = it.r[em] = it.r[em] || []; const i = L.indexOf(mid); if (i >= 0) L.splice(i, 1); else L.push(mid);
    await env.KV.put(fKey(code), JSON.stringify(feed)); return json({ ok: true, r: it.r });
  }
  if (path === "/g/stats") {
    const w = clean(body.week, 10); if (!/^\d{4}-\d{2}-\d{2}$/.test(w)) return json({ error: "week" }, 400);
    const st = (await env.KV.get(sKey(code, w), "json")) || {}; const x = body.stats || {};
    st[mid] = { name, n: Math.max(0, Math.min(14, +x.n || 0)), t: Math.max(0, Math.min(14, +x.t || 0)), streak: Math.max(0, Math.min(999, +x.streak || 0)), pr: Math.max(0, Math.min(50, +x.pr || 0)), at: Date.now() };
    await env.KV.put(sKey(code, w), JSON.stringify(st), { expirationTtl: 60 * 86400 }); return json({ ok: true });
  }
  if (path === "/g/feed") {
    const w = clean(body.week, 10); const [feed, st] = await Promise.all([env.KV.get(fKey(code), "json"), /^\d{4}-\d{2}-\d{2}$/.test(w) ? env.KV.get(sKey(code, w), "json") : null]);
    const members = Object.fromEntries(Object.entries(g.members).map(([id, m]) => [id, { name: m.name, notify: !!m.nid }]));
    return json({ ok: true, group: { name: g.name, members }, feed: (feed || []).slice(0, 60), board: st || {} });
  }
  return json({ error: "not_found" }, 404);
}

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    try {
      if (url.pathname === "/vapid") return json({ key: (await vapidKeys(env)).pub });
      if (url.pathname === "/" ) return json({ ok: true, app: "carico-push" });
      if (url.pathname === "/ai/status") return json({ enabled: !!(env.ANTHROPIC_KEY && env.CARICO_CODE) });
      if (url.pathname === "/ai" && req.method === "POST") return aiProxy(req, env);
      if (url.pathname.startsWith("/chat/")) return chatRoute(req, url, env);
      if (req.method !== "POST") return json({ error: "method" }, 405);
      const body = await req.json();
      if (url.pathname.startsWith("/g/")) return groupApi(url.pathname, body, env);
      if (!validId(body.id)) return json({ error: "id" }, 400);
      if (JSON.stringify(body).length > 24000) return json({ error: "too_big" }, 413);
      const key = "u:" + body.id;
      if (url.pathname === "/sub") {
        if (!body.sub || !body.sub.endpoint || !body.sub.keys) return json({ error: "sub" }, 400);
        await env.KV.put(key, JSON.stringify({ id: body.id, sub: body.sub, cfg: body.cfg || {} }));
        await addIndex(env, body.id);
        return json({ ok: true });
      }
      const u = await env.KV.get(key, "json");
      if (!u) return json({ error: "unknown" }, 404);
      if (url.pathname === "/sync") { u.cfg = body.cfg || {}; await env.KV.put(key, JSON.stringify(u)); return json({ ok: true }); }
      if (url.pathname === "/test") {
        const st = await sendPush(env, await vapidKeys(env), u.sub, body.msg || { title: "Carico", body: "Notifiche attive ✅", go: "oggi" });
        if (st === 404 || st === 410) await delUser(env, body.id);
        return json({ ok: st < 300, status: st });
      }
      if (url.pathname === "/unsub") { await delUser(env, body.id); return json({ ok: true }); }
      return json({ error: "not_found" }, 404);
    } catch (e) { return json({ error: String(e && e.message || e) }, 500); }
  },
  async scheduled(ev, env, ctx) {
    const idx = (await env.KV.get("index", "json")) || [];
    if (!idx.length) return;
    const now = new Date(ev.scheduledTime || Date.now());
    let keys = null;
    for (const id of idx) {
      const u = await env.KV.get("u:" + id, "json");
      if (!u) continue;
      const msgs = dueMessages(u, now);
      for (const m of msgs) {
        keys = keys || await vapidKeys(env);
        const st = await sendPush(env, keys, u.sub, m).catch(() => 0);
        if (st === 404 || st === 410) { await delUser(env, id); break; }
      }
    }
  },
};
