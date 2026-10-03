const O = 'https://pekkagoisaac.github.io';
const E = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const sha = async t => hex(await crypto.subtle.digest('SHA-256', E.encode(t)));
async function pw(p, salt) {
  const k = await crypto.subtle.importKey('raw', E.encode(p), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({name: 'PBKDF2', hash: 'SHA-256', salt: E.encode(salt), iterations: 100000}, k, 256));
}
const same = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

export default {
 async fetch(req, env) {
  const cors = {'Access-Control-Allow-Origin': O, 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST, OPTIONS'};
  if (req.method === 'OPTIONS') return new Response(null, {headers: cors});
  if (req.method !== 'POST' || req.headers.get('Origin') !== O) return new Response('No autorizado', {status: 403});
  const out = (o, s = 200) => new Response(JSON.stringify(o), {status: s, headers: {...cors, 'content-type': 'application/json'}});
  let b;
  try { b = await req.json(); } catch (e) { return out({error: 'bad'}, 400); }
  const path = new URL(req.url).pathname, now = Date.now(), DB = env.DB;
  const open = async uid => { const t = rnd(32); await DB.prepare('INSERT INTO sessions(token,uid,exp) VALUES(?,?,?)').bind(await sha(t), uid, now + 30 * 864e5).run(); return t; };

  if (path === '/auth/register' || path === '/auth/login') {
    const name = String(b.name || '').trim(), pass = String(b.password || '');
    if (!/^[A-Za-z0-9_.-]{3,20}$/.test(name) || pass.length < 8 || pass.length > 100) return out({error: 'invalid'}, 400);
    const key = name.toLowerCase();
    await DB.prepare('DELETE FROM sessions WHERE exp<?').bind(now).run();
    if (path === '/auth/register') {
      if (await DB.prepare('SELECT id FROM users WHERE lname=?').bind(key).first()) return out({error: 'exists'}, 409);
      const c = await DB.prepare('SELECT COUNT(*) AS c FROM users').first();
      if (c.c >= 100) return out({error: 'full'}, 403);
      const salt = rnd(16);
      await DB.prepare('INSERT INTO users(name,lname,salt,hash,data,created) VALUES(?,?,?,?,?,?)').bind(name, key, salt, await pw(pass, salt), '{}', now).run();
      const u = await DB.prepare('SELECT id FROM users WHERE lname=?').bind(key).first();
      return out({token: await open(u.id), name, data: {}});
    }
    const f = await DB.prepare('SELECT n,t FROM fails WHERE k=?').bind(key).first();
    if (f && f.n >= 5 && now - f.t < 900000) return out({error: 'locked'}, 429);
    const u = await DB.prepare('SELECT id,name,salt,hash,data FROM users WHERE lname=?').bind(key).first();
    const h = await pw(pass, u ? u.salt : 'x'.repeat(32));
    if (!u || !same(h, u.hash)) {
      await DB.prepare('INSERT INTO fails(k,n,t) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN ?-t>900000 THEN 1 ELSE n+1 END, t=?').bind(key, now, now, now).run();
      return out({error: 'bad'}, 401);
    }
    await DB.prepare('DELETE FROM fails WHERE k=?').bind(key).run();
    return out({token: await open(u.id), name: u.name, data: JSON.parse(u.data)});
  }

  if (path === '/auth/logout') {
    await DB.prepare('DELETE FROM sessions WHERE token=?').bind(await sha(String(b.token || ''))).run();
    return out({ok: true});
  }

  const s = b.token && typeof b.token === 'string'
    ? await DB.prepare('SELECT uid FROM sessions WHERE token=? AND exp>?').bind(await sha(b.token), now).first() : null;
  if (!s) return out({error: 'auth'}, 401);

  if (path === '/data/get') {
    const u = await DB.prepare('SELECT data FROM users WHERE id=?').bind(s.uid).first();
    return out({data: JSON.parse(u.data)});
  }
  if (path === '/data/set') {
    const j = JSON.stringify(b.data || {});
    if (j.length > 100000) return out({error: 'big'}, 413);
    await DB.prepare('UPDATE users SET data=? WHERE id=?').bind(j, s.uid).run();
    return out({ok: true});
  }

  const text = b.text;
  if (!text || typeof text !== 'string' || text.length > 500) return out({reply: 'Mensaje no válido, señor.'});
  const messages = [
   {role: 'system', content: 'Eres JARVIS, asistente personal. Responde siempre en el idioma del usuario, con tono elegante y breve (máximo 3 frases), llamándole "señor". Sirves con respeto y sabiduría.'},
   {role: 'user', content: text}
  ];
  for (const model of ['@cf/meta/llama-3.3-70b-instruct-fp8-fast', '@cf/meta/llama-3.2-3b-instruct']) {
   try {
    const r = await env.AI.run(model, {messages, max_tokens: 250});
    if (r && r.response) return out({reply: r.response});
   } catch (e) {}
  }
  return out({reply: 'No he podido responder, señor. Quizá se agotó el límite de hoy.'});
 }
}
