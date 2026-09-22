// ============================================================
//  Backend de pagamentos + contas — Sinuca Strike (Mercado Pago)
//  PIX (API) + Cartão (Checkout Pro) + Boleto (API, linha digitável)
//  Contas: cadastro, login, verificação de e-mail, reset de senha
//  Persistência: Postgres (DATABASE_URL) — cai para memória se ausente
//  ------------------------------------------------------------
//  Endpoints:
//   POST /api/pix                → cobrança PIX (QR + copia-e-cola)
//   POST /api/checkout           → cartão (12x) ou boleto (linha digitável)
//   GET  /api/pix/:id | /api/checkout/:id → status
//   POST /webhooks/mercadopago   → confirmação automática (assinada)
//   POST /api/auth/register|login|forgot|reset → contas
//   GET  /api/auth/verify?token= → verifica e-mail (link enviado)
//   GET  /api/auth/me            → dados da sessão
//   POST /api/wallet/sync        → saldo (servidor = fonte de verdade)
//   POST /api/client-errors      → captura de erros do jogo
//   POST /api/track | GET /api/track/summary → analytics básico
//
//  Variáveis de ambiente:
//   MP_ACCESS_TOKEN, MP_WEBHOOK_SECRET, ALLOWED_ORIGIN (obrigatórias p/ produção)
//   DATABASE_URL       → Postgres do Render (persistência real)
//   RESEND_API_KEY, EMAIL_FROM → envio de e-mail (verificação/reset)
//   TEST_EXPOSE_RESET=1 → SÓ PARA TESTES: devolve tokens na resposta
// ============================================================
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
const MP_API = 'https://api.mercadopago.com';

// ---------- CORS: allowlist (só o domínio do seu site) ----------
app.use((req, res, next) => {
  const o = process.env.ALLOWED_ORIGIN;
  if (o && req.headers.origin === o) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------- Persistência: Postgres se DATABASE_URL, senão memória ----------
let pg = null;
async function db() {
  if (!process.env.DATABASE_URL) return null;
  if (!pg) {
    const { Pool } = require('pg');
    pg = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
    await pg.query(`CREATE TABLE IF NOT EXISTS users(
      email TEXT PRIMARY KEY, data JSONB NOT NULL,
      coins BIGINT NOT NULL DEFAULT 0, verified BOOLEAN NOT NULL DEFAULT false)`);
    await pg.query(`CREATE TABLE IF NOT EXISTS charges(
      id TEXT PRIMARY KEY, data JSONB NOT NULL)`);
  }
  return pg;
}

// Usuários: cache em memória + write-through no banco
const users = new Map();
async function getUser(email) {
  if (users.has(email)) return users.get(email);
  const d = await db();
  if (d) {
    const r = await d.query('SELECT data FROM users WHERE email=$1', [email]);
    if (r.rows[0]) { users.set(email, r.rows[0].data); return r.rows[0].data; }
  }
  return null;
}
async function saveUser(u) {
  users.set(u.email, u);
  const d = await db();
  if (d) await d.query(
    'INSERT INTO users(email, data, coins, verified) VALUES($1,$2,$3,$4) ' +
    'ON CONFLICT(email) DO UPDATE SET data=$2, coins=$3, verified=$4',
    [u.email, JSON.stringify(u), u.coins, !!u.verified]);
}
async function getCharge(id) {
  const c = charges.get(id);
  if (c) return c;
  const d = await db();
  if (d) {
    const r = await d.query('SELECT data FROM charges WHERE id=$1', [id]);
    if (r.rows[0]) { charges.set(id, r.rows[0].data); return r.rows[0].data; }
  }
  return null;
}
async function saveCharge(c, id) {
  charges.set(id, c);
  const d = await db();
  if (d) await d.query(
    'INSERT INTO charges(id, data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2',
    [id, JSON.stringify(c)]);
}

const charges = new Map();          // cache de cobranças
const tokens = new Map();           // sessões (memória; restart desloga)
const resets = new Map();           // tokens de reset de senha
const verifs = new Map();           // tokens de verificação de e-mail
const COIN_VALUE_CENTS = 50;
const TOKEN_TTL = 30 * 24 * 60 * 60 * 1000;
const TOKEN_TTL_SHORT = 30 * 60 * 1000;   // 30 min p/ reset e verificação

function hashPass(pass, salt) { return crypto.scryptSync(String(pass), salt, 64).toString('hex'); }
function shortToken() { return crypto.randomBytes(24).toString('hex'); }
function newToken(email) {
  const t = crypto.randomUUID() + crypto.randomBytes(8).toString('hex');
  tokens.set(t, { email, exp: Date.now() + TOKEN_TTL });
  return t;
}
function userByToken(req) {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  if (!m) return null;
  const t = tokens.get(m[1]);
  if (!t || t.exp < Date.now()) { tokens.delete(m[1]); return null; }
  return users.get(t.email) || null;
}
const validEmail = e => typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 120;
const validPass = p => typeof p === 'string' && p.length >= 6 && p.length <= 100;

// ---------- E-mail (Resend) — sem chave, registra no log ----------
async function sendEmail(to, subject, html) {
  if (!process.env.RESEND_API_KEY) {
    console.log('[E-MAIL DESATIVADO — configure RESEND_API_KEY] para:', to, '|', subject);
    return false;
  }
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: process.env.EMAIL_FROM || 'Sinuca Strike <onboarding@resend.dev>', to, subject, html })
    });
    return true;
  } catch (e) { console.error('sendEmail:', e.message); return false; }
}

// ---------- Rate limits ----------
const hits = new Map(), authHits = new Map();
function mkLimiter(store, max) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?';
    const now = Date.now();
    const arr = (store.get(ip) || []).filter(t => now - t < 60000);
    arr.push(now);
    store.set(ip, arr);
    if (arr.length > max) return res.status(429).json({ error: 'too_many_requests' });
    next();
  };
}
const rateLimit = mkLimiter(hits, 30);
const authRate = mkLimiter(authHits, 10);

function validCents(v) {
  const c = Math.round(Number(v));
  return isFinite(c) && c >= 500 && c <= 5000000 ? c : null;   // R$ 5 a R$ 50.000
}

// ============================================================
//  CONTAS
// ============================================================
app.post('/api/auth/register', authRate, async (req, res) => {
  try {
    const email = ((req.body && req.body.email) || '').toLowerCase().trim();
    if (!validEmail(email)) return res.status(400).json({ error: 'E-mail inválido' });
    if (!validPass(req.body && req.body.password)) return res.status(400).json({ error: 'Senha deve ter ao menos 6 caracteres' });
    if (await getUser(email)) return res.status(409).json({ error: 'E-mail já cadastrado' });
    const salt = crypto.randomBytes(16).toString('hex');
    const u = { email, salt, hash: hashPass(req.body.password, salt), coins: 0, verified: false, created: Date.now() };
    await saveUser(u);
    const vt = shortToken();
    verifs.set(vt, { email, exp: Date.now() + TOKEN_TTL_SHORT });
    const base = process.env.PUBLIC_URL || '';
    await sendEmail(email, 'Confirme seu e-mail — Sinuca Strike',
      '<p>Confirme sua conta clicando no link:</p><p><a href="' + base + '/api/auth/verify?token=' + vt + '">Verificar meu e-mail</a></p>');
    res.json({ token: newToken(email), email, coins: 0, verified: false,
      resetToken: process.env.TEST_EXPOSE_RESET ? undefined : undefined,
      verifyToken: process.env.TEST_EXPOSE_RESET ? vt : undefined });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

app.post('/api/auth/login', authRate, async (req, res) => {
  try {
    const email = ((req.body && req.body.email) || '').toLowerCase().trim();
    const u = await getUser(email);
    if (!u) return res.status(401).json({ error: 'E-mail ou senha incorretos' });
    const h = hashPass((req.body && req.body.password) || '', u.salt);
    const ok = h.length === u.hash.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(u.hash));
    if (!ok) return res.status(401).json({ error: 'E-mail ou senha incorretos' });
    res.json({ token: newToken(email), email, coins: u.coins, verified: !!u.verified });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

// Esqueci minha senha: SEM revelar se o e-mail existe (anti enumeração)
app.post('/api/auth/forgot', authRate, async (req, res) => {
  try {
    const email = ((req.body && req.body.email) || '').toLowerCase().trim();
    const u = await getUser(email);
    let expose;
    if (u) {
      const t = shortToken();
      resets.set(t, { email, exp: Date.now() + TOKEN_TTL_SHORT });
      const base = process.env.PUBLIC_URL || '';
      await sendEmail(email, 'Redefinir senha — Sinuca Strike',
        '<p>Use o link para criar uma nova senha (vale 30 minutos):</p>' +
        '<p><a href="' + base + '/reset.html?token=' + t + '">Redefinir senha</a></p>');
      if (process.env.TEST_EXPOSE_RESET) expose = t;
    }
    res.json({ ok: true, resetToken: expose });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

app.post('/api/auth/reset', authRate, async (req, res) => {
  try {
    const t = String((req.body && req.body.token) || '');
    const r = resets.get(t);
    if (!r || r.exp < Date.now()) return res.status(400).json({ error: 'Link inválido ou expirado' });
    if (!validPass(req.body && req.body.password)) return res.status(400).json({ error: 'Senha deve ter ao menos 6 caracteres' });
    const u = await getUser(r.email);
    if (!u) return res.status(400).json({ error: 'Conta não encontrada' });
    u.salt = crypto.randomBytes(16).toString('hex');
    u.hash = hashPass(req.body.password, u.salt);
    await saveUser(u);
    resets.delete(t);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

// Verificação de e-mail (link clicado)
app.get('/api/auth/verify', async (req, res) => {
  try {
    const t = String(req.query.token || '');
    const v = verifs.get(t);
    if (!v || v.exp < Date.now()) return res.status(400).send('<h2 style="font-family:sans-serif">Link inválido ou expirado.</h2>');
    const u = await getUser(v.email);
    if (u) { u.verified = true; await saveUser(u); }
    verifs.delete(t);
    res.send('<h2 style="font-family:sans-serif;color:#1d5c38">E-mail verificado! ✅ Pode fechar e voltar ao jogo.</h2>');
  } catch (e) { res.status(500).send('erro'); }
});

app.get('/api/auth/me', async (req, res) => {
  const u = userByToken(req);
  if (!u) return res.status(401).json({ error: 'Não autenticado' });
  res.json({ email: u.email, coins: u.coins, verified: !!u.verified });
});

app.post('/api/wallet/sync', async (req, res) => {
  const u = userByToken(req);
  if (!u) return res.status(401).json({ error: 'Não autenticado' });
  const c = Math.round(Number(req.body && req.body.coins));
  if (!isFinite(c) || c < 0 || c > 1e9) return res.status(400).json({ error: 'Valor inválido' });
  u.coins = c;
  await saveUser(u);
  res.json({ coins: u.coins });
});

// ============================================================
//  PAGAMENTOS
// ============================================================
app.post('/api/pix', rateLimit, async (req, res) => {
  try {
    const cents = validCents(req.body && req.body.amountCents);
    if (!cents) return res.status(400).json({ error: 'Valor inválido' });
    const token = process.env.MP_ACCESS_TOKEN;
    if (!token) return res.status(500).json({ error: 'MP_ACCESS_TOKEN não configurado' });
    const localId = crypto.randomUUID();
    const email = ((req.body && req.body.email) || 'comprador@example.com').toLowerCase();

    const mpRes = await fetch(MP_API + '/v1/payments', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'X-Idempotency-Key': localId },
      body: JSON.stringify({
        transaction_amount: cents / 100,
        description: 'Moedas Sinuca Strike',
        payment_method_id: 'pix',
        payer: { email }
      })
    });
    const mp = await mpRes.json();
    if (!mpRes.ok) return res.status(502).json({ error: 'gateway_error', detail: mp });
    const tx = mp.point_of_interaction && mp.point_of_interaction.transaction_data;
    await saveCharge({ kind: 'pix', mpId: mp.id, amountCents: cents, status: 'pending', email, at: Date.now() }, localId);
    res.json({ id: localId, status: 'pending', code: tx && tx.qr_code,
      qrImage: tx && tx.qr_code_base64 ? 'data:image/png;base64,' + tx.qr_code_base64 : null });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

app.post('/api/checkout', rateLimit, async (req, res) => {
  try {
    const cents = validCents(req.body && req.body.amountCents);
    const method = (req.body && req.body.method) === 'boleto' ? 'boleto' : 'card';
    if (!cents) return res.status(400).json({ error: 'Valor inválido' });
    const token = process.env.MP_ACCESS_TOKEN;
    if (!token) return res.status(500).json({ error: 'MP_ACCESS_TOKEN não configurado' });
    const localId = crypto.randomUUID();
    const email = ((req.body && req.body.email) || 'comprador@example.com').toLowerCase();

    if (method === 'boleto') {
      // Boleto via API (bolbradesco): devolve LINHA DIGITÁVEL + PDF. MP exige CPF do pagador.
      const cpf = String((req.body && req.body.cpf) || '').replace(/\D/g, '');
      if (cpf.length !== 11) return res.status(400).json({ error: 'CPF do pagador obrigatório (11 dígitos)' });
      const mpRes = await fetch(MP_API + '/v1/payments', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'X-Idempotency-Key': localId },
        body: JSON.stringify({
          transaction_amount: cents / 100,
          description: 'Moedas Sinuca Strike',
          payment_method_id: 'bolbradesco',
          payer: { email, first_name: 'Jogador', last_name: 'Sinuca Strike',
                   identification: { type: 'CPF', number: cpf } }
        })
      });
      const mp = await mpRes.json();
      if (!mpRes.ok) return res.status(502).json({ error: 'gateway_error', detail: mp });
      const tx = mp.point_of_interaction && mp.point_of_interaction.transaction_data;
      const barcode = (tx && (typeof tx.barcode === 'string' ? tx.barcode : (tx.barcode && tx.barcode.payload))) || null;
      const ticketUrl = (tx && (tx.ticket_url || tx.external_resource_url)) || null;
      await saveCharge({ kind: 'boleto', mpId: mp.id, amountCents: cents, status: 'pending', email, at: Date.now() }, localId);
      return res.json({ id: localId, status: 'pending', barcode, ticketUrl });
    }

    // Cartão: Checkout Pro só cartão (até 12x)
    const pr = await fetch(MP_API + '/checkout/preferences', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        items: [{ title: 'Moedas Sinuca Strike', quantity: 1, unit_price: cents / 100, currency_id: 'BRL' }],
        external_reference: localId,
        payment_methods: { excluded_payment_types: [{ id: 'ticket' }, { id: 'bank_transfer' }], installments: 12 }
      })
    });
    const pref = await pr.json();
    if (!pr.ok) return res.status(502).json({ error: 'gateway_error', detail: pref });
    await saveCharge({ kind: 'checkout', method, prefId: pref.id, amountCents: cents, status: 'pending', email, at: Date.now() }, localId);
    res.json({ id: localId, status: 'pending', url: pref.init_point });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

app.get('/api/pix/:id', rateLimit, async (req, res) => {
  const c = await getCharge(req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  res.json({ status: c.status });
});
app.get('/api/checkout/:id', rateLimit, async (req, res) => {
  const c = await getCharge(req.params.id);
  if (!c) return res.status(404).json({ error: 'not_found' });
  res.json({ status: c.status });
});

// ---------- Webhook do Mercado Pago (assinado) ----------
app.post('/webhooks/mercadopago', async (req, res) => {
  try {
    const dataId = req.body && req.body.data && String(req.body.data.id);
    if (!dataId) return res.sendStatus(200);
    const secret = process.env.MP_WEBHOOK_SECRET;
    if (!secret) console.warn('ATENÇÃO: MP_WEBHOOK_SECRET não configurado — webhook SEM validação!');
    if (secret) {
      const sig = {};
      (req.get('x-signature') || '').split(',').forEach(kv => {
        const i = kv.indexOf('=');
        if (i > 0) sig[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
      });
      const ts = sig.ts, v1 = sig.v1;
      const manifest = 'id:' + dataId + ';request-id:' + (req.get('x-request-id') || '') + ';ts:' + ts + ';';
      const expected = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
      const fresh = ts && Math.abs(Date.now() / 1000 - Number(ts)) < 600;
      const valid = Boolean(fresh && v1 && v1.length === expected.length &&
        crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(v1)));
      if (!valid) {
        console.warn('Webhook rejeitado: assinatura inválida (id=' + dataId + ')');
        return res.status(401).send('invalid signature');
      }
    }
    const token = process.env.MP_ACCESS_TOKEN;
    const pr = await fetch(MP_API + '/v1/payments/' + dataId, { headers: { 'Authorization': 'Bearer ' + token } });
    const pay = await pr.json();
    if (pay.status === 'approved') {
      for (const [k, cm] of charges) {
        const c = await getCharge(k);
        if (!c) continue;
        const mine = String(c.mpId) === dataId || k === String(pay.external_reference);
        if (!mine || c.status === 'paid') continue;
        const paid = Math.round(Number(pay.transaction_amount) * 100);
        c.status = (paid + 1 >= c.amountCents) ? 'paid' : 'underpaid';
        if (c.status === 'underpaid') console.warn('Pagamento com valor menor!', k);
        else {
          const buyer = await getUser(String(c.email || '').toLowerCase());
          if (buyer) {
            const gain = Math.floor(c.amountCents / COIN_VALUE_CENTS);
            buyer.coins += gain;
            await saveUser(buyer);
            console.log('+' + gain + ' moedas para ' + buyer.email);
          }
        }
        await saveCharge(c, k);
      }
    }
    res.sendStatus(200);
  } catch (e) { console.error('webhook error:', e); res.sendStatus(200); }
});

// ============================================================
//  CAPTURA DE ERROS + ANALYTICS (auto-hospedados, sem serviço externo)
// ============================================================
const errLog = [];
app.post('/api/client-errors', rateLimit, (req, res) => {
  const e = { msg: String((req.body && req.body.msg) || '').slice(0, 500),
    stack: String((req.body && req.body.stack) || '').slice(0, 2000),
    ua: String(req.get('user-agent') || '').slice(0, 200), at: new Date().toISOString() };
  errLog.push(e); if (errLog.length > 200) errLog.shift();
  console.error('[CLIENTE]', e.msg);
  res.sendStatus(204);
});
const events = new Map();
app.post('/api/track', rateLimit, (req, res) => {
  const ev = String((req.body && req.body.event) || '').slice(0, 40);
  if (ev) events.set(ev, (events.get(ev) || 0) + 1);
  res.sendStatus(204);
});
app.get('/api/track/summary', (req, res) => {
  res.json(Object.fromEntries([...events.entries()].sort((a, b) => b[1] - a[1])));
});

// ============================================================
//  PAINEL ADMINISTRATIVO — conciliação de cobranças
//  Abrir: https://seu-backend.onrender.com/admin?key=SUA_ADMIN_KEY
//  Dados: /admin/api/overview?key=SUA_ADMIN_KEY (JSON agregado)
// ============================================================
function adminAuth(req, res) {
  const key = process.env.ADMIN_KEY;
  if (!key) { res.status(403).send('<h2 style="font-family:sans-serif">Painel desativado — configure a variável ADMIN_KEY no servidor.</h2>'); return false; }
  if (String(req.query.key) !== key) { res.status(403).send('<h2 style="font-family:sans-serif">Acesso negado.</h2>'); return false; }
  return true;
}
app.get('/admin', (req, res) => {
  if (!adminAuth(req, res)) return;
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/admin/api/overview', async (req, res) => {
  if (!adminAuth(req, res)) return;
  try {
    let all = Array.from(charges.values());
    if (pg) { try { const r = await pg.query('SELECT data FROM charges'); all = r.rows.map(x => x.data); } catch (e) {} }
    const paid = all.filter(c => c.status === 'paid');
    const byMethod = { pix: { count: 0, cents: 0 }, card: { count: 0, cents: 0 }, boleto: { count: 0, cents: 0 } };
    for (const c of paid) {
      const m = byMethod[c.kind] || byMethod.pix;
      m.count++; m.cents += c.amountCents || 0;
    }
    const byDay = [];
    const today = new Date(); today.setHours(0, 0, 0, 0);
    for (let i = 13; i >= 0; i--) {
      const d = new Date(today.getTime() - i * 86400000);
      byDay.push({ day: d.toISOString().slice(0, 10), label: d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit' }), cents: 0, count: 0 });
    }
    const idx = {}; byDay.forEach((d, i) => idx[d.day] = i);
    for (const c of paid) {
      const day = new Date(c.at || 0).toISOString().slice(0, 10);
      if (idx[day] !== undefined) { byDay[idx[day]].cents += c.amountCents || 0; byDay[idx[day]].count++; }
    }
    res.json({
      totals: { paid: paid.length, paidCents: paid.reduce((s2, c) => s2 + (c.amountCents || 0), 0),
        pending: all.filter(c => c.status === 'pending').length, total: all.length },
      byMethod, byDay,
      recent: all.slice().reverse().slice(0, 100),
      events: Object.fromEntries(events.entries()),
      errors: errLog.slice(-15).reverse()
    });
  } catch (e) { res.status(500).json({ error: String(e && e.message || e) }); }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Sinuca Strike backend (PIX+Cartão+Boleto+Contas+Analytics) na porta ' + port));
