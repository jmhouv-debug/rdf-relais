// Serveur Employé du Mois / Opération Rideau de fer (Cloudflare Worker)
//  - /room/<nom>  : relais multijoueur (Durable Object, une salle par nom)
//  - /auth/v1/... : comptes joueurs (inscription, connexion, sauvegarde cloud)
//  - /rest/v1/... : saisons, rôles, classement, palmarès (base D1 "DB")
//  - le reste     : le jeu lui-même (dossier public)

export class Room {
  constructor(ctx, env) { this.ctx = ctx; }
  async fetch(request) {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(ws, message) {
    if (typeof message === 'string' && message.length > 200000) return;
    for (const other of this.ctx.getWebSockets()) {
      if (other !== ws) { try { other.send(message); } catch (e) {} }
    }
  }
  webSocketClose(ws, code, reason) { try { ws.close(code, reason); } catch (e) {} }
  webSocketError(ws) { try { ws.close(1011, 'erreur'); } catch (e) {} }
}

/* ---------------- outils ---------------- */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS',
  'Access-Control-Allow-Headers': 'apikey,authorization,content-type,x-client-info,prefer',
  'Access-Control-Max-Age': '86400'
};
function json(o, st) { return new Response(JSON.stringify(o === undefined ? null : o), { status: st || 200, headers: Object.assign({ 'content-type': 'application/json; charset=utf-8' }, CORS) }); }
function err(st, code, msg) { return json({ error_code: code, msg: msg || code }, st); }
const enc = new TextEncoder();
function b64u(bytes) { let s = ''; bytes.forEach(function (b) { s += String.fromCharCode(b); }); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64uStr(str) { return b64u(enc.encode(str)); }
function rnd(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function hex(buf) { return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''); }
async function sha(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
// 20 000 tours : assez solide, et tient dans la limite de calcul de l'offre gratuite
const PW_IT = 20000;
async function pwHash(pw, saltHex, it) {
  const salt = new Uint8Array(saltHex.match(/../g).map(function (h) { return parseInt(h, 16); }));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: it || PW_IT }, key, 256));
}
function uuid() { return crypto.randomUUID(); }
const ACCESS_S = 3600, REFRESH_S = 90 * 86400;

/* ---------------- schéma (créé tout seul au premier appel) ---------------- */
let READY = false;
async function ensure(db) {
  if (READY) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, meta TEXT NOT NULL DEFAULT '{}', created INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions (tok TEXT PRIMARY KEY, uid TEXT NOT NULL, kind TEXT NOT NULL, exp INTEGER NOT NULL)"),
    db.prepare("CREATE INDEX IF NOT EXISTS sessions_uid ON sessions(uid)"),
    db.prepare("CREATE TABLE IF NOT EXISTS fails (k TEXT PRIMARY KEY, n INTEGER NOT NULL, t INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS edm_seasons (n INTEGER PRIMARY KEY, wk TEXT UNIQUE NOT NULL, starts_at INTEGER NOT NULL, ends_at INTEGER NOT NULL, closed INTEGER NOT NULL DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS edm_players (user_id TEXT NOT NULL, slot INTEGER NOT NULL, name TEXT NOT NULL DEFAULT 'Employé', season INTEGER NOT NULL, role TEXT NOT NULL, promoted INTEGER NOT NULL DEFAULT 0, reputation REAL NOT NULL DEFAULT 100, actions INTEGER NOT NULL DEFAULT 0, salary INTEGER NOT NULL DEFAULT 0, minutes INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL, day_off_week INTEGER, day_off_until INTEGER, PRIMARY KEY (user_id, slot))"),
    db.prepare("CREATE INDEX IF NOT EXISTS edm_players_season ON edm_players(season, role)"),
    db.prepare("CREATE TABLE IF NOT EXISTS edm_hall (season INTEGER PRIMARY KEY, user_id TEXT, slot INTEGER, name TEXT, actions INTEGER, salary INTEGER, minutes INTEGER, claimed INTEGER NOT NULL DEFAULT 0)")
  ]);
  READY = true;
}

/* ---------------- comptes ---------------- */
async function newSession(db, uid) {
  const now = Date.now();
  const at = b64uStr(JSON.stringify({ alg: 'none', typ: 'JWT' })) + '.' + b64uStr(JSON.stringify({ sub: uid, exp: Math.floor(now / 1000) + ACCESS_S })) + '.' + b64u(rnd(24));
  const rt = b64u(rnd(32));
  await db.batch([
    db.prepare('INSERT INTO sessions(tok,uid,kind,exp) VALUES (?,?,?,?)').bind(await sha(at), uid, 'a', now + ACCESS_S * 1000),
    db.prepare('INSERT INTO sessions(tok,uid,kind,exp) VALUES (?,?,?,?)').bind(await sha(rt), uid, 'r', now + REFRESH_S * 1000),
    db.prepare('DELETE FROM sessions WHERE uid=? AND exp<?').bind(uid, now)
  ]);
  return { access_token: at, token_type: 'bearer', expires_in: ACCESS_S, refresh_token: rt, user: { id: uid } };
}
async function authUid(db, req) {
  const h = req.headers.get('authorization') || '';
  const t = h.replace(/^Bearer\s+/i, '');
  if (!t || t.split('.').length !== 3) return null;
  const row = await db.prepare("SELECT uid,exp FROM sessions WHERE tok=? AND kind='a'").bind(await sha(t)).first();
  if (!row || row.exp < Date.now()) return null;
  return row.uid;
}
function cleanEmail(e) { return String(e || '').trim().toLowerCase().slice(0, 120); }
async function tooMany(db, k) {
  const r = await db.prepare('SELECT n,t FROM fails WHERE k=?').bind(k).first();
  return !!(r && r.n >= 10 && Date.now() - r.t < 15 * 60000);
}
async function fail(db, k) {
  await db.prepare('INSERT INTO fails(k,n,t) VALUES (?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN ?-t>900000 THEN 1 ELSE n+1 END, t=?').bind(k, Date.now(), Date.now(), Date.now()).run();
}

async function auth(db, req, path, url) {
  if (path === '/auth/v1/signup' && req.method === 'POST') {
    const b = await req.json().catch(function () { return {}; });
    const email = cleanEmail(b.email), pw = String(b.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(400, 'validation_failed', 'invalid email');
    if (pw.length < 6) return err(422, 'weak_password', 'Password should be at least 6 characters');
    const ex = await db.prepare('SELECT id FROM users WHERE email=?').bind(email).first();
    if (ex) return err(422, 'user_already_exists', 'User already registered');
    const id = uuid(), salt = hex(rnd(16));
    await db.prepare('INSERT INTO users(id,email,salt,hash,meta,created) VALUES (?,?,?,?,?,?)').bind(id, email, salt, PW_IT + '$' + (await pwHash(pw, salt, PW_IT)), '{}', Date.now()).run();
    return json(await newSession(db, id));
  }
  if (path === '/auth/v1/token' && req.method === 'POST') {
    const gt = url.searchParams.get('grant_type');
    const b = await req.json().catch(function () { return {}; });
    if (gt === 'password') {
      const email = cleanEmail(b.email), pw = String(b.password || '');
      if (await tooMany(db, email)) return err(429, 'over_request_rate_limit', 'Too many attempts');
      const u = await db.prepare('SELECT id,salt,hash FROM users WHERE email=?').bind(email).first();
      const hp = u ? String(u.hash).split('$') : [];
      if (!u || hp.length !== 2 || (await pwHash(pw, u.salt, +hp[0])) !== hp[1]) { await fail(db, email); return err(400, 'invalid_credentials', 'Invalid login credentials'); }
      await db.prepare('DELETE FROM fails WHERE k=?').bind(email).run();
      return json(await newSession(db, u.id));
    }
    if (gt === 'refresh_token') {
      const h = await sha(String(b.refresh_token || ''));
      const r = await db.prepare("SELECT uid,exp FROM sessions WHERE tok=? AND kind='r'").bind(h).first();
      if (!r || r.exp < Date.now()) return err(400, 'refresh_token_not_found', 'Invalid Refresh Token');
      await db.prepare('DELETE FROM sessions WHERE tok=?').bind(h).run();
      return json(await newSession(db, r.uid));
    }
    return err(400, 'unsupported_grant_type', 'unsupported grant type');
  }
  if (path === '/auth/v1/user') {
    const uid = await authUid(db, req);
    if (!uid) return err(401, 'bad_jwt', 'invalid JWT');
    if (req.method === 'PUT') {
      const txt = await req.text();
      if (txt.length > 900000) return err(413, 'too_large', 'payload too large');
      let b; try { b = JSON.parse(txt); } catch (e) { return err(400, 'bad_json', 'bad json'); }
      const u = await db.prepare('SELECT meta FROM users WHERE id=?').bind(uid).first();
      let meta = {}; try { meta = JSON.parse(u.meta || '{}'); } catch (e) {}
      Object.assign(meta, (b && b.data) || {});
      await db.prepare('UPDATE users SET meta=? WHERE id=?').bind(JSON.stringify(meta), uid).run();
    }
    const u = await db.prepare('SELECT id,email,meta FROM users WHERE id=?').bind(uid).first();
    if (!u) return err(401, 'user_not_found', 'user not found');
    let meta = {}; try { meta = JSON.parse(u.meta || '{}'); } catch (e) {}
    return json({ id: u.id, email: u.email, user_metadata: meta });
  }
  return err(404, 'not_found', 'not found');
}

/* ---------------- saisons (lundi 00:00 → dimanche 23:59, heure de Paris) ---------------- */
function parisParts(ms) {
  const f = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Paris', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', weekday: 'short' });
  const o = {}; f.formatToParts(new Date(ms)).forEach(function (p) { o[p.type] = p.value; }); return o;
}
function parisMidnight(y, m, d) { // instant UTC de minuit à Paris ce jour-là
  let t = Date.UTC(y, m - 1, d, 0, 0, 0);
  for (let i = 0; i < 3; i++) {
    const p = parisParts(t);
    const asUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
    t -= asUtc - Date.UTC(y, m - 1, d, 0, 0, 0);
  }
  return t;
}
function weekStart(now) {
  const p = parisParts(now);
  const wd = { Mon: 0, Tue: 1, Wed: 2, Thu: 3, Fri: 4, Sat: 5, Sun: 6 }[p.weekday];
  const d = new Date(Date.UTC(+p.year, +p.month - 1, +p.day - wd));
  const y = d.getUTCFullYear(), m = d.getUTCMonth() + 1, dd = d.getUTCDate();
  const next = new Date(Date.UTC(y, m - 1, dd + 7));
  return { wk: y + '-' + String(m).padStart(2, '0') + '-' + String(dd).padStart(2, '0'), start: parisMidnight(y, m, dd), end: parisMidnight(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate()) };
}
async function closeOld(db, start) {
  const old = await db.prepare('SELECT n FROM edm_seasons WHERE closed=0 AND ends_at<=?').bind(start).all();
  for (const s of old.results) {
    const p = await db.prepare("SELECT * FROM edm_players WHERE season=? AND role='m' ORDER BY actions DESC, salary DESC, minutes DESC LIMIT 1").bind(s.n).first();
    const st = [];
    if (p && p.actions > 0) st.push(db.prepare('INSERT OR IGNORE INTO edm_hall(season,user_id,slot,name,actions,salary,minutes) VALUES (?,?,?,?,?,?,?)').bind(s.n, p.user_id, p.slot, p.name, p.actions, p.salary, p.minutes));
    st.push(db.prepare('UPDATE edm_seasons SET closed=1 WHERE n=?').bind(s.n));
    await db.batch(st);
  }
}
async function seasonNow(db) {
  const w = weekStart(Date.now());
  let s = await db.prepare('SELECT * FROM edm_seasons WHERE wk=?').bind(w.wk).first();
  if (s) return s;
  await closeOld(db, w.start);
  await db.prepare('INSERT OR IGNORE INTO edm_seasons(n,wk,starts_at,ends_at) SELECT COALESCE(MAX(n),0)+1,?,?,? FROM edm_seasons').bind(w.wk, w.start, w.end).run();
  return await db.prepare('SELECT * FROM edm_seasons WHERE wk=?').bind(w.wk).first();
}
function pl(p) { // même forme que Supabase
  if (!p) return null;
  return { user_id: p.user_id, slot: p.slot, name: p.name, season: p.season, role: p.role, promoted: !!p.promoted, reputation: p.reputation, actions: p.actions, salary: p.salary, minutes: p.minutes, last_seen: new Date(p.last_seen).toISOString(), day_off_week: p.day_off_week, day_off_until: p.day_off_until ? new Date(p.day_off_until).toISOString() : null };
}
const clamp = function (v, a, b) { v = Number(v); if (!isFinite(v)) v = 0; return Math.max(a, Math.min(b, v)); };

async function rpc(db, fn, uid, a) {
  if (fn === 'edm_season_now') { const s = await seasonNow(db); return { n: s.n, starts_at: new Date(s.starts_at).toISOString(), ends_at: new Date(s.ends_at).toISOString(), closed: !!s.closed }; }
  if (fn === 'edm_register') {
    const s = await seasonNow(db), slot = clamp(a.p_slot, 0, 99) | 0, name = String(a.p_name || 'Employé').slice(0, 20);
    let p = await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=?').bind(uid, slot).first();
    if (p && p.season === s.n) {
      await db.prepare('UPDATE edm_players SET name=?, last_seen=? WHERE user_id=? AND slot=?').bind(name, Date.now(), uid, slot).run();
      return pl(await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=?').bind(uid, slot).first());
    }
    const c = await db.prepare("SELECT SUM(CASE WHEN role='m' AND promoted=0 THEN 1 ELSE 0 END) mg, SUM(CASE WHEN role='v' THEN 1 ELSE 0 END) vg FROM edm_players WHERE season=?").bind(s.n).first();
    const r = Math.random();
    let rl = r < .65 ? 'e' : r < .85 ? 'm' : 'v';
    if (rl === 'm' && (c.mg || 0) >= 3) rl = 'e';
    if (rl === 'v' && (c.vg || 0) >= 2) rl = 'e';
    await db.prepare("INSERT INTO edm_players(user_id,slot,name,season,role,last_seen) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id,slot) DO UPDATE SET season=excluded.season, role=excluded.role, promoted=0, reputation=100, actions=0, salary=0, minutes=0, last_seen=excluded.last_seen, name=excluded.name, day_off_until=NULL").bind(uid, slot, name, s.n, rl, Date.now()).run();
    return pl(await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=?').bind(uid, slot).first());
  }
  if (fn === 'edm_beat') {
    const s = await seasonNow(db), slot = clamp(a.p_slot, 0, 99) | 0;
    const p = await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=? AND season=?').bind(uid, slot, s.n).first();
    if (!p) throw new Error('personnage inconnu');
    const now = Date.now(), el = Math.min(120, (now - p.last_seen) / 1000), m = p.role === 'm';
    await db.prepare('UPDATE edm_players SET last_seen=?, reputation=?, actions=?, salary=?, minutes=? WHERE user_id=? AND slot=?').bind(
      now,
      m ? clamp(a.p_rep === undefined || a.p_rep === null ? p.reputation : a.p_rep, 0, 100) : p.reputation,
      p.actions + (m ? Math.round(clamp(a.p_actions, 0, 5)) : 0),
      p.salary + Math.round(clamp(a.p_salary, 0, 50)),
      p.minutes + (m ? Math.round(el / 60) : 0),
      uid, slot).run();
    return pl(await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=?').bind(uid, slot).first());
  }
  if (fn === 'edm_day_off') {
    const s = await seasonNow(db), slot = clamp(a.p_slot, 0, 99) | 0;
    const p = await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=? AND season=?').bind(uid, slot, s.n).first();
    if (!p) throw new Error('personnage inconnu');
    if (p.day_off_week === s.n) throw new Error('congé déjà pris cette semaine');
    const until = Date.now() + 86400000;
    await db.prepare('UPDATE edm_players SET day_off_week=?, day_off_until=? WHERE user_id=? AND slot=?').bind(s.n, until, uid, slot).run();
    return new Date(until).toISOString();
  }
  if (fn === 'edm_board') {
    const s = await seasonNow(db);
    const r = await db.prepare("SELECT name,role,reputation,actions,salary,minutes,user_id FROM edm_players WHERE season=? AND role='m' ORDER BY actions DESC, salary DESC, minutes DESC LIMIT 20").bind(s.n).all();
    return r.results.map(function (p, i) { return { rk: i + 1, name: p.name, role: p.role, reputation: p.reputation, actions: p.actions, salary: p.salary, minutes: p.minutes, mine: p.user_id === uid }; });
  }
  if (fn === 'edm_claim_bonus') {
    await seasonNow(db);
    const h = await db.prepare('SELECT * FROM edm_hall WHERE user_id=? AND claimed=0 ORDER BY season LIMIT 1').bind(uid).first();
    if (!h) return null;
    const r = await db.prepare('UPDATE edm_hall SET claimed=1 WHERE season=? AND claimed=0').bind(h.season).run();
    if (!r.meta || !r.meta.changes) return null;
    h.claimed = true; return h;
  }
  if (fn === 'edm_set_role') {
    const s = await seasonNow(db), slot = clamp(a.p_slot, 0, 99) | 0, role = String(a.p_role || '');
    if (['e', 'm', 'v'].indexOf(role) < 0) throw new Error('rôle invalide');
    await db.prepare("UPDATE edm_players SET reputation=CASE WHEN ?='m' AND role<>'m' THEN 100 ELSE reputation END, role=?, promoted=? WHERE user_id=? AND slot=? AND season=?").bind(role, role, role === 'm' && a.p_promoted ? 1 : 0, uid, slot, s.n).run();
    return pl(await db.prepare('SELECT * FROM edm_players WHERE user_id=? AND slot=?').bind(uid, slot).first());
  }
  return undefined;
}

/* ---------- absences (tâche horaire) ---------- */
async function sweep(db) {
  await ensure(db);
  await seasonNow(db);
  const now = Date.now();
  await db.batch([
    db.prepare("UPDATE edm_players SET reputation=MAX(0, 100 - 100.0*(?-last_seen)/86400000.0) WHERE role='m' AND (day_off_until IS NULL OR day_off_until<?) AND ?-last_seen>600000").bind(now, now, now),
    db.prepare("UPDATE edm_players SET role='e', promoted=0, reputation=100 WHERE role='m' AND ?-last_seen>86400000 AND (day_off_until IS NULL OR day_off_until<?)").bind(now, now),
    db.prepare('DELETE FROM sessions WHERE exp<?').bind(now)
  ]);
}

async function api(env, req, url) {
  const db = env.DB;
  if (!db) return err(503, 'no_database', 'base de données non reliée');
  await ensure(db);
  const path = url.pathname.replace(/\/+$/, '');
  if (path.startsWith('/auth/v1/')) return auth(db, req, path, url);
  const uid = await authUid(db, req);
  if (!uid) return err(401, 'bad_jwt', 'invalid JWT');
  const m = path.match(/^\/rest\/v1\/rpc\/([a-z_]+)$/);
  if (m && req.method === 'POST') {
    const a = await req.json().catch(function () { return {}; });
    try {
      const r = await rpc(db, m[1], uid, a || {});
      if (r === undefined) return err(404, 'PGRST202', 'function not found');
      return json(r);
    } catch (e) { return err(400, 'P0001', String(e && e.message || e)); }
  }
  if (path === '/rest/v1/edm_hall' && req.method === 'GET') {
    await seasonNow(db);
    const r = await db.prepare('SELECT season,user_id,slot,name,actions,salary FROM edm_hall ORDER BY season DESC LIMIT 6').all();
    return json(r.results);
  }
  return err(404, 'not_found', 'not found');
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const m = url.pathname.match(/^\/room\/([a-z0-9-]{1,40})$/i);
    if (m) {
      if (request.headers.get('Upgrade') !== 'websocket') return new Response('WebSocket attendu', { status: 426 });
      const id = env.ROOMS.idFromName(m[1].toLowerCase());
      return env.ROOMS.get(id).fetch(request);
    }
    if (url.pathname.startsWith('/auth/v1/') || url.pathname.startsWith('/rest/v1/')) {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      try { return await api(env, request, url); } catch (e) { return err(500, 'server_error', String(e && e.message || e)); }
    }
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return new Response('Serveur Employé du Mois : OK', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
  },
  async scheduled(event, env, ctx) {
    if (env.DB) ctx.waitUntil(sweep(env.DB));
  }
};
