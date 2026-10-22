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
      if (m === L.min) out.push({ title: c.coachTitle || "💬 Il Coach", body: pick(B.coach, u.id + L.date + "q" + i), tag: "coach", go: "oggi" });
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

export default {
  async fetch(req, env) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
    const url = new URL(req.url);
    try {
      if (url.pathname === "/vapid") return json({ key: (await vapidKeys(env)).pub });
      if (url.pathname === "/" ) return json({ ok: true, app: "carico-push" });
      if (url.pathname === "/ai/status") return json({ enabled: !!(env.ANTHROPIC_KEY && env.CARICO_CODE) });
      if (url.pathname === "/ai" && req.method === "POST") return aiProxy(req, env);
      if (req.method !== "POST") return json({ error: "method" }, 405);
      const body = await req.json();
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
