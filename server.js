/* ================================================================
   Virtual Oracle — Express server
   Serves the static site (public/) AND a JSON REST API backed by
   PostgreSQL. Auth is via JWT (member / partner / admin roles).
   ================================================================ */
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, query, initSchema } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-me';
// A forgeable JWT secret = full account/admin takeover. Never run on Render
// (production) with the dev fallback.
if (process.env.RENDER && !process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set. Refusing to start with the dev fallback in production.');
  process.exit(1);
}
const ADMIN_PASSCODE = process.env.ADMIN_PASSCODE || '';   // legacy; only works when explicitly set

/* Admin sign-in accounts: email -> bcrypt password hash (never plaintext —
   this repo is public). Add or override without code changes via the
   ADMIN_ACCOUNTS env var: "email:password,email2:password2". */
const ADMIN_HASHES = {
  'groovyalpha@gmail.com': '$2a$10$bGDzCr3v1PAHsHU3i6nsje7XleCXsOQlNUS1wIHwpdtKPfPCuPHPi',
  'andrewturkenterprise@gmail.com': '$2a$10$LGgOEReRiby4n5lsXxho7uMBEfru9tZmsLlc.apSAAbUN9/Kd.ppG',
};
const ADMIN_ENV_ACCOUNTS = {};
String(process.env.ADMIN_ACCOUNTS || '').split(',').forEach((pair) => {
  const i = pair.indexOf(':');
  if (i > 0) ADMIN_ENV_ACCOUNTS[pair.slice(0, i).trim().toLowerCase()] = pair.slice(i + 1);
});
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const CLAUDE_MODEL = process.env.CLAUDE_MODEL || 'claude-haiku-4-5';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const MAIL_FROM = process.env.MAIL_FROM || '';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT, 10) || 465;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
/* Canonical public address — used for links in emails and anywhere a
   shareable URL is produced (never the onrender.com host). */
const PUBLIC_URL = (process.env.PUBLIC_URL || 'https://virtualsoracle.com').replace(/\/+$/, '');

/* Claude client for screenshot scanning (vision). Key lives only here, server-side. */
let anthropic = null;
if (ANTHROPIC_API_KEY) {
  try {
    const { Anthropic } = require('@anthropic-ai/sdk');
    anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });
  } catch (e) {
    console.warn('[scan] @anthropic-ai/sdk not installed:', e && e.message);
  }
}

app.set('trust proxy', 1);   // Render runs behind a proxy — needed for correct client IPs
app.use(cors());
app.use(express.json({ limit: '8mb' }));   // screenshots (base64) can be a few MB

/* Baseline security headers (no extra deps needed) */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');            // nothing here is meant to be framed
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

/* ----------------------------- rate limiting ----------------------------- */
const rlMsg = (m) => ({ windowMs: m.windowMs, max: m.max, standardHeaders: true, legacyHeaders: false, message: { error: m.msg } });
const authLimiter  = rateLimit(rlMsg({ windowMs: 15 * 60 * 1000, max: 40, msg: 'Too many attempts. Please wait a few minutes and try again.' }));
const loginLimiter = rateLimit(rlMsg({ windowMs: 15 * 60 * 1000, max: 12, msg: 'Too many login attempts. Please wait 15 minutes.' }));
const scanLimiter  = rateLimit(rlMsg({ windowMs: 60 * 1000,      max: 30, msg: 'Scanning too fast — wait a moment and try again.' }));
app.use('/api/auth', authLimiter);               // register + login + forgot/reset
app.use('/api/admin/login', loginLimiter);       // credential brute-force guard
app.use('/api/partner/login', loginLimiter);
app.use('/api/scan', scanLimiter);               // protect the paid scanner from abuse
app.use('/api/pay/cowrie/init', authLimiter);    // public: cap charge-creation spam

/* Best-effort transactional email. Prefers SMTP via Nodemailer (set SMTP_USER +
   SMTP_PASS — e.g. a Gmail address + app password; host/port default to Gmail
   over 465). Falls back to Resend's HTTP API, and no-ops when neither is
   configured, so callers never fail on email. Note Render blocks port 25 —
   use 465 (default) or 587. */
let mailer = null;
if (SMTP_USER && SMTP_PASS) {
  try {
    const nodemailer = require('nodemailer');
    mailer = nodemailer.createTransport({
      host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    console.log('✓ SMTP mail via', SMTP_HOST + ':' + SMTP_PORT);
  } catch (e) { console.warn('nodemailer unavailable:', e && e.message); }
}
const mailConfigured = () => !!(mailer || (RESEND_API_KEY && MAIL_FROM));

async function sendMail(to, subject, html) {
  // Gmail forces the authenticated address as the sender, but honors a display
  // name — so recipients see "Virtual Oracle" instead of a bare Gmail address.
  const from = MAIL_FROM || ('"Virtual Oracle" <' + SMTP_USER + '>');
  if (mailer) {
    try { await mailer.sendMail({ from, to, subject, html }); return true; }
    catch (e) { console.warn('[mail] smtp send failed', e && e.message); return false; }
  }
  if (RESEND_API_KEY && MAIL_FROM) {
    try {
      const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + RESEND_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: MAIL_FROM, to, subject, html }),
      });
      if (!r.ok) console.warn('[mail] send failed', r.status, await r.text().catch(() => ''));
      return r.ok;
    } catch (e) {
      console.warn('[mail] error', e && e.message);
      return false;
    }
  }
  console.log('[mail] not configured — skipping email to', to);
  return false;
}

/* ----------------------------- helpers ----------------------------- */
const sign = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
const norm = (e) => String(e || '').trim().toLowerCase();
const hash = (pw) => bcrypt.hashSync(pw, 10);
const check = (pw, h) => { try { return bcrypt.compareSync(pw, h); } catch { return false; } };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function auth(role) {
  return (req, res, next) => {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not signed in' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role) return res.status(403).json({ error: 'Forbidden' });
      req.user = decoded;
      next();
    } catch {
      return res.status(401).json({ error: 'Session expired' });
    }
  };
}

const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => {
  console.error(e);
  res.status(500).json({ error: 'Server error' });
});

function parsePrice(label) {
  if (!label) return 0;
  const s = String(label).replace(/ghs/i, '').trim();
  let n = parseFloat(s);
  if (/k/i.test(s)) n *= 1000;
  return isNaN(n) ? 0 : n;
}

function genCode(name) {
  const base = (name || 'PARTNER').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 5) || 'PART';
  return base + Math.floor(100 + Math.random() * 900);
}
async function uniqueCode(name) {
  let code;
  for (let i = 0; i < 50; i++) {
    code = genCode(name);
    const { rows } = await query('SELECT 1 FROM partners WHERE code=$1', [code]);
    if (!rows.length) return code;
  }
  return code + Date.now().toString().slice(-3);
}

/* Map DB rows to the client-facing field names the front-end expects */
const userOut = (r) => r && ({
  email: r.email, name: r.name, plan: r.plan,
  planEnd: r.plan_end ? Number(r.plan_end) : null,
  ref: r.ref, partner: r.partner,
  sportyAccount: r.sporty_account || null,
  unlimitedUntil: r.unlimited_until ? Number(r.unlimited_until) : null,
  regFeePaid: !!r.reg_fee_paid,
});

/* The one-time registration fee is sold as the "GHS 50" package (0 credits).
   Whenever such a purchase is credited, flip the member's paid flag. */
const REG_FEE_PKG = 'GHS 50';
const markFeeIfPaid = (email, pkg) => {
  if (pkg !== REG_FEE_PKG || !email) return Promise.resolve();
  return query('UPDATE users SET reg_fee_paid=true WHERE email=$1', [email]).catch(() => {});
};

/* Credit a purchase exactly once, atomically. The browser poll and the Cowrie
   webhook can both fire for the same payment; a per-reference advisory lock plus
   a dup-check inside one transaction guarantees a single credit. The unlimited
   tier (>=9999) grants 24h of unlimited predictions (stacking); otherwise it adds
   prediction credits. Returns { credited, duplicate }. */
const DAY_MS = 24 * 60 * 60 * 1000;
/* Which credit pool a package funds: Red & Black packages feed rb_amount,
   everything else feeds the Instant Football pool. */
const isRBPackage = (pkg) => /red\s*&\s*black/i.test(String(pkg || ''));
async function creditPurchaseOnce(email, pkg, reference, predictions) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (reference) {
      // serialize concurrent crediters for the same reference
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [reference]);
      const dup = await client.query('SELECT 1 FROM purchases WHERE reference=$1', [reference]);
      if (dup.rows.length) { await client.query('COMMIT'); return { credited: false, duplicate: true }; }
    }
    await client.query('INSERT INTO purchases (email,pkg,reference,predictions) VALUES ($1,$2,$3,$4)',
      [email, pkg, reference, predictions]);
    if (predictions >= 9999) {
      await client.query(
        'UPDATE users SET unlimited_until = GREATEST(COALESCE(unlimited_until, 0), $2) + $3 WHERE email=$1',
        [email, Date.now(), DAY_MS]);
    } else if (predictions > 0) {
      // separate pools: RB packages fund rb_amount, football packages fund amount
      const fb = isRBPackage(pkg) ? 0 : predictions;
      const rb = isRBPackage(pkg) ? predictions : 0;
      await client.query(
        `INSERT INTO credits (email,amount,rb_amount) VALUES ($1,$2,$3)
         ON CONFLICT (email) DO UPDATE SET
           amount = credits.amount + EXCLUDED.amount,
           rb_amount = credits.rb_amount + EXCLUDED.rb_amount`,
        [email, fb, rb]);
    }
    await client.query('COMMIT');
    return { credited: true, duplicate: false };
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}
const partnerOut = (r) => r && ({
  id: r.id, name: r.name, email: r.email, code: r.code, status: r.status,
  locked: r.locked, commission: r.commission != null ? Number(r.commission) : 10,
  revenueClearedAt: r.revenue_cleared_at || null,
  created: r.created_at, approvedAt: r.approved_at, lockedAt: r.locked_at,
});
const pickOut = (r) => r && ({
  id: r.id, email: r.member_email, home: r.home, away: r.away, out: r.outcome,
  label: r.label, odds: r.odds != null ? Number(r.odds) : null,
  from: r.from_code, fromName: r.from_name, used: r.used, date: r.created_at,
});

/* ============================ MEMBER AUTH ============================ */
app.post('/api/auth/register', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  const ref = String(req.body.ref || '').trim() || null;
  if (!name) return res.status(400).json({ error: 'Enter your name.' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const exists = await query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (exists.rows.length) return res.status(409).json({ error: 'An account with this email already exists.' });

  // attribute to a partner only if the ref code belongs to a real partner
  let partner = null;
  if (ref) {
    const p = await query('SELECT code FROM partners WHERE code=$1', [ref]);
    if (p.rows.length) partner = ref;
  }
  const { rows } = await query(
    'INSERT INTO users (email,name,pw_hash,ref,partner) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [email, name, hash(password), ref, partner]
  );
  await query('INSERT INTO credits (email,amount) VALUES ($1,0) ON CONFLICT (email) DO NOTHING', [email]);
  const user = userOut(rows[0]);
  res.json({ token: sign({ email, role: 'member' }), user });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  const { rows } = await query('SELECT * FROM users WHERE email=$1', [email]);
  const u = rows[0];
  if (!u || !check(password, u.pw_hash)) return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign({ email, role: 'member' }), user: userOut(u) });
}));

/* ---- Forgot password: email a 30-minute reset link ---- */
app.post('/api/auth/forgot', wrap(async (req, res) => {
  const email = norm(req.body.email);
  if (!email) return res.status(400).json({ error: 'Enter your email address.' });
  if (!mailConfigured()) return res.status(503).json({ error: 'Password reset is unavailable right now. Please contact support.' });
  const { rows } = await query('SELECT email, name, pw_hash FROM users WHERE email=$1', [email]);
  if (rows.length) {
    // Bind the token to the current password hash: once the password changes,
    // this link (and any other outstanding one) stops working.
    const token = jwt.sign({ email, role: 'pwreset', h: String(rows[0].pw_hash || '').slice(-12) },
      JWT_SECRET, { expiresIn: '30m' });
    const link = PUBLIC_URL + '/login.html?reset=' + encodeURIComponent(token);
    await sendMail(email, 'Reset your Virtual Oracle password',
      `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#222">
         <h2 style="margin:0 0 12px">Reset your password</h2>
         <p>Hi ${rows[0].name || 'there'},</p>
         <p>Someone (hopefully you) asked to reset the password for this Virtual Oracle account.
            Click the button below to choose a new one. The link works for <b>30 minutes</b>.</p>
         <p style="text-align:center;margin:26px 0">
           <a href="${link}" style="background:#A40E1E;color:#fff;text-decoration:none;padding:13px 26px;border-radius:6px;font-weight:bold">Set a new password</a>
         </p>
         <p style="font-size:12px;color:#777">If the button doesn't work, copy this link into your browser:<br>
           <a href="${link}">${link}</a></p>
         <p style="font-size:12px;color:#777">Didn't request this? You can ignore this email — your password stays unchanged.</p>
       </div>`);
  }
  // Same answer whether or not the account exists — never leak membership.
  res.json({ ok: true });
}));

app.post('/api/auth/reset', wrap(async (req, res) => {
  const password = String(req.body.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  let decoded;
  try { decoded = jwt.verify(String(req.body.token || ''), JWT_SECRET); } catch {
    return res.status(400).json({ error: 'This reset link is invalid or has expired. Request a new one.' });
  }
  if (decoded.role !== 'pwreset') return res.status(400).json({ error: 'This reset link is invalid.' });
  const { rows } = await query('SELECT pw_hash FROM users WHERE email=$1', [decoded.email]);
  if (!rows.length) return res.status(404).json({ error: 'That account no longer exists.' });
  if (decoded.h !== undefined && decoded.h !== String(rows[0].pw_hash || '').slice(-12)) {
    return res.status(400).json({ error: 'This reset link was already used. Request a new one.' });
  }
  await query('UPDATE users SET pw_hash=$2 WHERE email=$1', [decoded.email, hash(password)]);
  res.json({ ok: true });
}));

/* ============================ MEMBER DATA ============================ */
app.get('/api/me', auth('member'), wrap(async (req, res) => {
  const { rows } = await query('SELECT * FROM users WHERE email=$1', [req.user.email]);
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  const c = await query('SELECT amount, rb_amount FROM credits WHERE email=$1', [req.user.email]);
  res.json({ user: userOut(rows[0]),
    credits: c.rows[0] ? c.rows[0].amount : 0,
    rbCredits: c.rows[0] ? c.rows[0].rb_amount : 0 });
}));

// member's pushed picks (optionally only pending)
app.get('/api/me/picks', auth('member'), wrap(async (req, res) => {
  const onlyPending = req.query.pending === '1';
  const { rows } = await query(
    `SELECT * FROM pushed_picks WHERE member_email=$1 ${onlyPending ? 'AND used=false' : ''} ORDER BY created_at DESC`,
    [req.user.email]
  );
  res.json(rows.map(pickOut));
}));

// mark a pick as used (consumed by the dashboard prediction flow)
app.post('/api/me/picks/:id/consume', auth('member'), wrap(async (req, res) => {
  await query('UPDATE pushed_picks SET used=true WHERE id=$1 AND member_email=$2', [req.params.id, req.user.email]);
  res.json({ ok: true });
}));

/* The registration fee is enforced HERE, not just by page redirects — going
   straight to the connect step (login.html#sporty) must not skip payment. */
async function regFeeUnpaid(email) {
  const { rows } = await query('SELECT reg_fee_paid FROM users WHERE email=$1', [email]);
  return rows.length ? rows[0].reg_fee_paid === false : false;
}

// link a SportyBet account number (first-time setup after registration) + email the user
app.post('/api/me/sporty', auth('member'), wrap(async (req, res) => {
  if (await regFeeUnpaid(req.user.email)) {
    return res.status(402).json({ error: 'Pay the GHS 50 registration fee first.' });
  }
  const account = String(req.body.account || '').trim();
  if (!account) return res.status(400).json({ error: 'Enter your SportyBet account number.' });
  const { rows } = await query(
    'UPDATE users SET sporty_account=$1 WHERE email=$2 RETURNING *',
    [account, req.user.email]
  );
  if (!rows.length) return res.status(404).json({ error: 'Account not found.' });
  const user = userOut(rows[0]);
  // fire-and-forget confirmation email (best effort)
  sendMail(
    user.email,
    'Your SportyBet account is connected — Virtual Oracle',
    `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto">
       <h2 style="color:#E11D2A">Virtual Oracle</h2>
       <p>Hi ${user.name || 'there'},</p>
       <p>Your SportyBet account <b>${account}</b> has been <b>connected successfully</b> to your Virtual Oracle account.</p>
       <p>You can now buy a package and start getting instant predictions.</p>
       <p style="color:#888;font-size:12px">If you didn't do this, please contact Virtual Oracle support.</p>
     </div>`
  );
  res.json({ ok: true, user });
}));

// record a purchase + extend plan / add credits
app.post('/api/me/purchases', auth('member'), wrap(async (req, res) => {
  let pkg = String(req.body.pkg || '');
  const reference = String(req.body.reference || '');
  let predictions = parseInt(req.body.predictions, 10) || 0;
  const planEnd = req.body.planEnd ? Number(req.body.planEnd) : null;
  const plan = req.body.plan != null ? String(req.body.plan) : null;

  // Only credit payments we can VERIFY with the gateway. A real Cowrie charge
  // starts with "cwr_"; anything else (demo refs, forged client values, etc.)
  // is rejected so nobody gets free credits.
  if (!/^cwr_/i.test(reference)) {
    // flag the attempt for the admin (best-effort)
    query('INSERT INTO security_alerts (email,kind,detail) VALUES ($1,$2,$3)',
      [req.user.email, 'unverified_purchase',
       'Tried to claim ' + predictions + ' predictions (' + pkg + ') with ref "' + reference.slice(0, 40) + '"']).catch(() => {});
    return res.status(400).json({ error: 'Payment could not be verified.' });
  }
  const v = await verifyCowrieCharge(reference);
  if (!v) return res.status(502).json({ error: 'Could not verify the payment. Please try again.' });
  if (!v.paid) return res.status(402).json({ error: 'Payment is not confirmed yet.' });
  if (v.email && v.email !== req.user.email) return res.status(403).json({ error: 'This payment belongs to another account.' });
  predictions = v.credits;     // gateway is the source of truth
  pkg = v.pkg || pkg;
  if (pkg !== REG_FEE_PKG && await regFeeUnpaid(req.user.email)) {
    return res.status(402).json({ error: 'Pay the GHS 50 registration fee before buying a package.' });
  }

  // Credit exactly once (atomic; safe against the webhook racing this).
  const r = await creditPurchaseOnce(req.user.email, pkg, reference, predictions);
  await markFeeIfPaid(req.user.email, pkg);
  if (!r.duplicate && (plan != null || planEnd != null)) {
    await query('UPDATE users SET plan=COALESCE($2,plan), plan_end=COALESCE($3,plan_end) WHERE email=$1',
      [req.user.email, plan, planEnd]);
  }
  const c = await query('SELECT amount, rb_amount FROM credits WHERE email=$1', [req.user.email]);
  res.json({ ok: true, duplicate: r.duplicate,
    credits: c.rows[0] ? c.rows[0].amount : 0,
    rbCredits: c.rows[0] ? c.rows[0].rb_amount : 0 });
}));

/* ---- Direct MoMo payment claim: "I've sent the money to your number" ----
   No credits are granted here — the buyer's pkg/credits are just a display aid
   for the admin, who checks the money actually arrived and approves the claim
   (that approval is what credits the account). */
/* Canonical claimable packages — MUST stay in sync with PACKAGES in
   public/pricing.html. Credits come from HERE, never from the client, so a
   tampered request can't claim more than the package grants. */
const CLAIM_PACKAGES = {
  'GHS 50': 0,                    // registration fee
  'GHS 250': 2, 'GHS 350': 3, 'GHS 500': 4,   // Instant Football packages
  'GHS 500 · Red & Black': 3,     // Red & Black: one session = 3 screenshots → 3 predictions
};

app.post('/api/me/manual-claims', auth('member'), wrap(async (req, res) => {
  const pkg = String(req.body.pkg || '').slice(0, 40);
  const credits = CLAIM_PACKAGES[pkg];
  if (credits === undefined) {
    return res.status(400).json({ error: 'Unknown package — please refresh the page and try again.' });
  }
  // packages are locked until the registration fee is paid (the fee itself is exempt)
  if (pkg !== REG_FEE_PKG && await regFeeUnpaid(req.user.email)) {
    return res.status(402).json({ error: 'Pay the GHS 50 registration fee before buying a package.' });
  }
  const amount = String(req.body.amount || '').slice(0, 80);
  const txid = String(req.body.txid || '').trim().slice(0, 80);
  const method = String(req.body.method || '').slice(0, 10);
  // Bank transfers are verified by the receipt screenshot alone — no reference needed.
  // MoMo payments are matched by the sender's registered MoMo name (stored in txid).
  if (method !== 'bank' && txid.length < 4) return res.status(400).json({ error: 'Enter the name on the MoMo number you paid from.' });

  // Receipt screenshot: required for bank transfers (no SMS lands on our side)
  let proof = String(req.body.proof || '');
  if (proof && !/^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/.test(proof)) proof = '';
  if (proof.length > 4 * 1024 * 1024) return res.status(413).json({ error: 'That screenshot is too large. Please try again.' });
  if (method === 'bank' && !proof) return res.status(400).json({ error: 'Attach a screenshot of your transfer receipt.' });

  // The same member can't resubmit the same payment (sender names aren't
  // globally unique, so this dedupe is scoped per member).
  if (txid) {
    const dupTx = await query(
      "SELECT status FROM manual_claims WHERE email=$2 AND UPPER(txid)=UPPER($1) AND status='pending' LIMIT 1",
      [txid, req.user.email]);
    if (dupTx.rows.length) {
      return res.status(409).json({ error: 'This deposit has already been submitted and is awaiting confirmation — no need to resend it.' });
    }
  }
  // One pending claim per member — resending just crowds the review queue.
  const dup = await query(
    "SELECT COUNT(*)::int AS n FROM manual_claims WHERE email=$1 AND status='pending'", [req.user.email]);
  if (dup.rows[0].n >= 1) {
    return res.status(429).json({ error: 'Your previous deposit is still awaiting confirmation. Please wait — your credits arrive as soon as it is approved.' });
  }
  const { rows } = await query(
    'INSERT INTO manual_claims (email,pkg,credits,amount,txid,proof) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
    [req.user.email, pkg, credits, amount, txid, proof || null]);

  // Tell every admin a deposit is waiting so it gets approved quickly (best-effort)
  const adminTo = [...new Set([...Object.keys(ADMIN_HASHES), ...Object.keys(ADMIN_ENV_ACCOUNTS)])];
  if (adminTo.length) {
    const link = PUBLIC_URL + '/admin.html';
    const isBank = method === 'bank';
    Promise.resolve(sendMail(adminTo, '💰 Deposit awaiting approval — ' + (amount || pkg),
      `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;padding:24px;color:#222">
         <h2 style="margin:0 0 14px;color:#E41827">New deposit to confirm</h2>
         <table style="border-collapse:collapse;width:100%;font-size:14px">
           <tr><td style="padding:6px 10px 6px 0;color:#777">Member</td><td style="padding:6px 0"><b>${req.user.email}</b></td></tr>
           <tr><td style="padding:6px 10px 6px 0;color:#777">Package</td><td style="padding:6px 0">${pkg} — ${credits >= 9999 ? 'Unlimited · 24h' : (credits ? credits + ' predictions' : 'Registration fee')}</td></tr>
           <tr><td style="padding:6px 10px 6px 0;color:#777">Amount sent</td><td style="padding:6px 0"><b>${amount || pkg}</b></td></tr>
           <tr><td style="padding:6px 10px 6px 0;color:#777">${isBank ? 'Proof' : 'Sender name'}</td>
               <td style="padding:6px 0">${isBank ? 'Receipt screenshot attached — open it from the panel' : (txid || '—')}</td></tr>
         </table>
         <p style="margin:18px 0 6px">Check the money actually arrived, then approve or reject it under
            <b>Transactions → MoMo Payments — Confirm</b>. Credits are granted only when you approve.</p>
         <p style="text-align:center;margin:22px 0 6px">
           <a href="${link}" style="background:#1F9E48;color:#fff;text-decoration:none;padding:12px 24px;border-radius:6px;font-weight:bold">Open admin panel</a>
         </p>
       </div>`)).catch(() => {});
  }
  res.json({ ok: true, id: rows[0].id });
}));

// poll one's own claim so the pricing page can auto-continue once approved
app.get('/api/me/manual-claims/:id', auth('member'), wrap(async (req, res) => {
  const { rows } = await query(
    'SELECT id, status FROM manual_claims WHERE id=$1 AND email=$2', [req.params.id, req.user.email]);
  if (!rows.length) return res.status(404).json({ error: 'Claim not found.' });
  res.json({ id: rows[0].id, status: rows[0].status });
}));

// spend a credit (when generating a prediction)
app.post('/api/me/credits/spend', auth('member'), wrap(async (req, res) => {
  const n = parseInt(req.body.amount, 10) || 1;
  const col = String(req.body.game || '') === 'rb' ? 'rb_amount' : 'amount';
  const { rows } = await query(
    `UPDATE credits SET ${col} = GREATEST(0, ${col} - $2) WHERE email=$1 RETURNING amount, rb_amount`,
    [req.user.email, n]
  );
  res.json({ credits: rows[0] ? rows[0].amount : 0, rbCredits: rows[0] ? rows[0].rb_amount : 0 });
}));

/* ============================ PARTNER AUTH ============================ */
app.post('/api/partner/register', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  if (!name) return res.status(400).json({ error: 'Enter your full name.' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const exists = await query('SELECT 1 FROM partners WHERE email=$1', [email]);
  if (exists.rows.length) return res.status(409).json({ error: 'A partner with this email already exists.' });

  const code = await uniqueCode(name);
  await query('INSERT INTO partners (name,email,pw_hash,code,status) VALUES ($1,$2,$3,$4,$5)',
    [name, email, hash(password), code, 'pending']);
  res.json({ ok: true });
}));

app.post('/api/partner/login', wrap(async (req, res) => {
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  const { rows } = await query('SELECT * FROM partners WHERE email=$1', [email]);
  const p = rows[0];
  if (!p || !check(password, p.pw_hash)) return res.status(401).json({ error: 'Wrong email or password.' });
  if (p.status === 'pending') return res.status(403).json({ error: 'Your application is still awaiting admin approval.' });
  if (p.status === 'rejected') return res.status(403).json({ error: 'Your application was not approved. Contact Virtual Oracle.' });
  if (p.locked) return res.status(403).json({ error: 'Your account has been locked. Contact Virtual Oracle.' });
  res.json({ token: sign({ code: p.code, email: p.email, role: 'partner' }), partner: partnerOut(p) });
}));

/* ============================ PARTNER DATA ============================ */
async function loadPartner(code) {
  const { rows } = await query('SELECT * FROM partners WHERE code=$1', [code]);
  return rows[0];
}

app.get('/api/partner/me', auth('partner'), wrap(async (req, res) => {
  const p = await loadPartner(req.user.code);
  if (!p || p.status !== 'approved' || p.locked) return res.status(403).json({ error: 'Account unavailable' });
  res.json({ partner: partnerOut(p) });
}));

app.get('/api/partner/referrals', auth('partner'), wrap(async (req, res) => {
  const code = req.user.code;
  const p = await loadPartner(code);
  // partner's own "clear revenue" marker — spend only counts newer purchases
  const since = (p && p.revenue_cleared_at) || new Date(0);
  const u = await query('SELECT * FROM users WHERE partner=$1', [code]);
  const buys = await query(
    'SELECT email, pkg FROM purchases WHERE created_at > $2 AND email IN (SELECT email FROM users WHERE partner=$1)',
    [code, since]);
  const spend = {};
  buys.rows.forEach((b) => { spend[b.email] = (spend[b.email] || 0) + parsePrice(b.pkg); });
  res.json(u.rows.map((r) => ({ ...userOut(r), spend: spend[r.email] || 0 })));
}));

// reset the partner's own revenue/earnings display to zero (data is kept)
app.post('/api/partner/revenue-clear', auth('partner'), wrap(async (req, res) => {
  await query('UPDATE partners SET revenue_cleared_at=now() WHERE code=$1', [req.user.code]);
  res.json({ ok: true });
}));

app.get('/api/partner/picks', auth('partner'), wrap(async (req, res) => {
  const { rows } = await query('SELECT * FROM pushed_picks WHERE from_code=$1 ORDER BY created_at DESC', [req.user.code]);
  res.json(rows.map(pickOut));
}));

app.post('/api/partner/picks', auth('partner'), wrap(async (req, res) => {
  const p = await loadPartner(req.user.code);
  if (!p || p.status !== 'approved' || p.locked) return res.status(403).json({ error: 'Account unavailable' });
  const email = norm(req.body.email);
  const picks = Array.isArray(req.body.picks) ? req.body.picks : [];
  if (!email) return res.status(400).json({ error: 'Select an account.' });
  if (!picks.length) return res.status(400).json({ error: 'No picks supplied.' });
  const member = await query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (!member.rows.length) return res.status(404).json({ error: 'Member not found.' });
  await insertPicks(email, picks, p.code, p.name);
  res.json({ ok: true, count: picks.length });
}));

app.delete('/api/partner/picks/:id', auth('partner'), wrap(async (req, res) => {
  await query('DELETE FROM pushed_picks WHERE id=$1 AND from_code=$2 AND used=false', [req.params.id, req.user.code]);
  res.json({ ok: true });
}));

// shared: members list for the "reflect in account" dropdown
app.get('/api/accounts', auth(), wrap(async (req, res) => {
  if (!['partner', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const { rows } = await query('SELECT email,name,partner FROM users ORDER BY name NULLS LAST, email');
  res.json(rows.map((r) => ({ email: r.email, name: r.name, partner: r.partner })));
}));

async function insertPicks(email, picks, fromCode, fromName) {
  for (const pk of picks) {
    await query(
      `INSERT INTO pushed_picks (member_email,home,away,outcome,label,odds,from_code,from_name)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [email, String(pk.home || ''), String(pk.away || ''), String(pk.out || ''),
       String(pk.label || ''), pk.odds != null ? pk.odds : null, fromCode, fromName]
    );
  }
}

/* ============================ ADMIN ============================ */
/* Admin sign-in: email + password against ADMIN_HASHES (bcrypt) or
   ADMIN_ACCOUNTS env pairs. The old {passcode} body only works when the
   ADMIN_PASSCODE env var is explicitly set (no hardcoded fallback). */
app.post('/api/admin/login', wrap(async (req, res) => {
  if (req.body.passcode !== undefined && req.body.email === undefined) {
    if (ADMIN_PASSCODE && String(req.body.passcode || '') === ADMIN_PASSCODE) {
      return res.json({ token: sign({ role: 'admin' }) });
    }
    return res.status(401).json({ error: 'Wrong passcode.' });
  }
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  const ok = password && (
    (ADMIN_ENV_ACCOUNTS[email] !== undefined && password === ADMIN_ENV_ACCOUNTS[email]) ||
    (ADMIN_HASHES[email] !== undefined && check(password, ADMIN_HASHES[email]))
  );
  if (!ok) return res.status(401).json({ error: 'Wrong email or password.' });
  res.json({ token: sign({ role: 'admin', email }) });
}));

app.get('/api/admin/users', auth('admin'), wrap(async (req, res) => {
  const u = await query('SELECT * FROM users ORDER BY created_at DESC');
  const c = await query('SELECT email, amount, rb_amount FROM credits');
  const credits = {}, rbCredits = {};
  c.rows.forEach((r) => { credits[r.email] = r.amount; rbCredits[r.email] = r.rb_amount; });
  res.json(u.rows.map((r) => ({ ...userOut(r), credits: credits[r.email] || 0, rbCredits: rbCredits[r.email] || 0 })));
}));

app.get('/api/admin/partners', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query('SELECT * FROM partners ORDER BY created_at DESC');
  res.json(rows.map(partnerOut));
}));

app.post('/api/admin/partners', auth('admin'), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = norm(req.body.email);
  const password = String(req.body.password || '');
  let code = String(req.body.code || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required.' });
  const exists = await query('SELECT 1 FROM partners WHERE email=$1', [email]);
  if (exists.rows.length) return res.status(409).json({ error: 'A partner with this email already exists.' });
  if (code) {
    const dup = await query('SELECT 1 FROM partners WHERE code=$1', [code]);
    if (dup.rows.length) return res.status(409).json({ error: 'That code is already taken.' });
  } else {
    code = await uniqueCode(name);
  }
  const { rows } = await query(
    `INSERT INTO partners (name,email,pw_hash,code,status,approved_at)
     VALUES ($1,$2,$3,$4,'approved',now()) RETURNING *`,
    [name, email, hash(password), code]
  );
  res.json({ partner: partnerOut(rows[0]) });
}));

app.patch('/api/admin/partners/:id', auth('admin'), wrap(async (req, res) => {
  const action = String(req.body.action || '');
  const id = req.params.id;
  if (action === 'commission') {
    const rate = Number(req.body.rate);
    if (!isFinite(rate) || rate < 0 || rate > 100) return res.status(400).json({ error: 'Commission must be between 0 and 100 percent.' });
    const { rows } = await query('UPDATE partners SET commission=$2 WHERE id=$1 RETURNING *', [id, rate]);
    return res.json({ partner: partnerOut(rows[0]) });
  }
  const map = {
    approve: "UPDATE partners SET status='approved', approved_at=now() WHERE id=$1 RETURNING *",
    reject:  "UPDATE partners SET status='rejected' WHERE id=$1 RETURNING *",
    lock:    "UPDATE partners SET locked=true, locked_at=now() WHERE id=$1 RETURNING *",
    unlock:  "UPDATE partners SET locked=false, locked_at=NULL WHERE id=$1 RETURNING *",
    // reset the partner's revenue/earnings display (e.g. after paying them out)
    'clear-revenue': "UPDATE partners SET revenue_cleared_at=now() WHERE id=$1 RETURNING *",
  };
  if (!map[action]) return res.status(400).json({ error: 'Unknown action.' });
  const { rows } = await query(map[action], [id]);
  res.json({ partner: partnerOut(rows[0]) });
}));

app.delete('/api/admin/partners/:id', auth('admin'), wrap(async (req, res) => {
  await query('DELETE FROM partners WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

// grant (or deduct) prediction credits for a member; game:'rb' targets the
// Red & Black pool, otherwise the Instant Football pool
app.post('/api/admin/credits', auth('admin'), wrap(async (req, res) => {
  const email = norm(req.body.email);
  const amount = parseInt(req.body.amount, 10);
  if (!email || isNaN(amount)) return res.status(400).json({ error: 'Email and a numeric amount are required.' });
  const col = String(req.body.game || '') === 'rb' ? 'rb_amount' : 'amount';
  const { rows } = await query(
    `INSERT INTO credits (email,${col}) VALUES ($1,$2)
     ON CONFLICT (email) DO UPDATE SET ${col} = GREATEST(0, credits.${col} + EXCLUDED.${col})
     RETURNING amount`,
    [email, amount]
  );
  res.json({ ok: true, credits: rows[0] ? rows[0].amount : 0 });
}));

// scan meter — how many screenshot scans are left (so the admin tops up API credits in time)
app.get('/api/admin/scan-usage', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query('SELECT used, remaining FROM scan_meter WHERE id=1');
  const r = rows[0] || { used: 0, remaining: 0 };
  res.json({ used: Number(r.used), remaining: Number(r.remaining) });
}));

// correct the scan counters: `amount` adds/subtracts from remaining,
// `used` (optional) sets the used total to an absolute value
app.post('/api/admin/scan-topup', auth('admin'), wrap(async (req, res) => {
  const amount = parseInt(req.body.amount, 10);
  const used = parseInt(req.body.used, 10);
  if (isNaN(amount) && isNaN(used)) return res.status(400).json({ error: 'Enter a number of scans.' });
  const { rows } = await query(
    `UPDATE scan_meter SET
       remaining = GREATEST(0, remaining + $1),
       used = COALESCE($2, used)
     WHERE id=1 RETURNING used, remaining`,
    [isNaN(amount) ? 0 : amount, isNaN(used) || used < 0 ? null : used]
  );
  const r = rows[0] || { used: 0, remaining: 0 };
  res.json({ ok: true, used: Number(r.used), remaining: Number(r.remaining) });
}));

// grant a member unlimited predictions for N days (default 1; large N = effectively permanent)
app.post('/api/admin/unlimited', auth('admin'), wrap(async (req, res) => {
  const email = norm(req.body.email);
  const days = req.body.days != null ? Number(req.body.days) : 1;
  if (!email) return res.status(400).json({ error: 'Email is required.' });
  if (isNaN(days) || days < 0) return res.status(400).json({ error: 'days must be a non-negative number.' });
  const u = await query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (!u.rows.length) return res.status(404).json({ error: 'Member not found.' });
  const until = days === 0 ? null : Date.now() + Math.round(days * DAY_MS);
  const { rows } = await query('UPDATE users SET unlimited_until=$2 WHERE email=$1 RETURNING unlimited_until', [email, until]);
  res.json({ ok: true, unlimitedUntil: rows[0].unlimited_until ? Number(rows[0].unlimited_until) : null });
}));

// delete a member (keeps their transaction history)
app.delete('/api/admin/users/:email', auth('admin'), wrap(async (req, res) => {
  const email = norm(req.params.email);
  await query('DELETE FROM credits WHERE email=$1', [email]);
  await query('DELETE FROM users WHERE email=$1', [email]);
  res.json({ ok: true });
}));

/* "Clear revenue" is a display reset, not a deletion: dashboards only count
   purchases made after the marker; the rows stay in the database. */
const adminRevenueSince = async () => {
  const { rows } = await query('SELECT revenue_cleared_at FROM payment_config WHERE id=1');
  return (rows[0] && rows[0].revenue_cleared_at) || new Date(0);
};

app.post('/api/admin/revenue-clear', auth('admin'), wrap(async (req, res) => {
  await query('UPDATE payment_config SET revenue_cleared_at=now() WHERE id=1');
  res.json({ ok: true });
}));

/* Factual per-day takings for the last 7 days (today included, Ghana = UTC).
   Deliberately ignores the clear-revenue marker — this is a report of what
   actually came in each day. */
app.get('/api/admin/revenue-daily', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query(
    "SELECT pkg, created_at FROM purchases WHERE created_at > now() - interval '7 days'");
  const byDay = {};
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const key = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
    days.push(key);
    byDay[key] = { day: key, revenue: 0, count: 0 };
  }
  rows.forEach((r) => {
    const key = new Date(r.created_at).toISOString().slice(0, 10);
    if (byDay[key]) { byDay[key].revenue += parsePrice(r.pkg); byDay[key].count++; }
  });
  res.json(days.map((k) => byDay[k]));
}));

app.get('/api/admin/purchases', auth('admin'), wrap(async (req, res) => {
  const since = await adminRevenueSince();
  const { rows } = await query('SELECT * FROM purchases WHERE created_at > $1 ORDER BY created_at DESC', [since]);
  res.json(rows.map((r) => ({
    id: r.id, email: r.email, pkg: r.pkg, reference: r.reference,
    predictions: r.predictions, date: r.created_at,
  })));
}));

// clear transaction history (e.g. wipe test/fake purchases so revenue resets)
app.delete('/api/admin/purchases', auth('admin'), wrap(async (req, res) => {
  const { rowCount } = await query('DELETE FROM purchases');
  res.json({ ok: true, deleted: rowCount });
}));

// delete a single transaction (remove one entry from revenue), by id or reference.
// ?revoke=1 also takes back the credits (or the 24h unlimited pass) it granted —
// use it to fully reverse a refunded or fraudulent purchase.
app.delete('/api/admin/purchases/:key', auth('admin'), wrap(async (req, res) => {
  const key = String(req.params.key || '');
  const byId = /^\d+$/.test(key);
  const revoke = String(req.query.revoke || '') === '1';
  const where = byId ? 'id=$1' : 'reference=$1';

  const sel = await query('SELECT email, predictions, pkg FROM purchases WHERE ' + where, [key]);
  const row = sel.rows[0];
  if (!row) return res.json({ ok: true, deleted: 0, revoked: 0 });

  let revoked = 0;   // credits taken back; -1 means a 24h unlimited pass was removed
  if (revoke) {
    const preds = Number(row.predictions) || 0;
    if (preds >= 9999) {
      await query('UPDATE users SET unlimited_until = GREATEST(0, COALESCE(unlimited_until,0) - $2) WHERE email=$1',
        [row.email, DAY_MS]);
      revoked = -1;
    } else if (preds > 0) {
      const col = isRBPackage(row.pkg) ? 'rb_amount' : 'amount';
      await query(`UPDATE credits SET ${col} = GREATEST(0, ${col} - $2) WHERE email=$1`, [row.email, preds]);
      revoked = preds;
    }
  }
  await query('DELETE FROM purchases WHERE ' + where, [key]);
  res.json({ ok: true, deleted: 1, revoked });
}));

// security alerts (e.g. unverified purchase attempts)
app.get('/api/admin/alerts', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query('SELECT id,email,kind,detail,created_at FROM security_alerts ORDER BY created_at DESC LIMIT 100');
  res.json(rows.map((r) => ({ id: r.id, email: r.email, kind: r.kind, detail: r.detail, date: r.created_at })));
}));
app.delete('/api/admin/alerts', auth('admin'), wrap(async (req, res) => {
  const { rowCount } = await query('DELETE FROM security_alerts');
  res.json({ ok: true, deleted: rowCount });
}));

app.get('/api/admin/picks', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query('SELECT * FROM pushed_picks ORDER BY created_at DESC');
  res.json(rows.map(pickOut));
}));

app.post('/api/admin/picks', auth('admin'), wrap(async (req, res) => {
  const email = norm(req.body.email);
  const picks = Array.isArray(req.body.picks) ? req.body.picks : [];
  if (!email) return res.status(400).json({ error: 'Select an account.' });
  if (!picks.length) return res.status(400).json({ error: 'No picks supplied.' });
  const member = await query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (!member.rows.length) return res.status(404).json({ error: 'Member not found.' });
  await insertPicks(email, picks, 'ADMIN', 'Admin');
  res.json({ ok: true, count: picks.length });
}));

app.delete('/api/admin/picks/:id', auth('admin'), wrap(async (req, res) => {
  await query('DELETE FROM pushed_picks WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
}));

const PROVIDER_IDS = ['paystack', 'flutterwave', 'cowrie', 'manual', 'bank'];

/* Per-method config {id:{enabled,key,secret}}. Falls back to the legacy
   single-provider columns for configs saved before the toggles existed. */
function providersOut(r) {
  const p = (r.providers && typeof r.providers === 'object' && !Array.isArray(r.providers)) ? r.providers : {};
  const out = {};
  PROVIDER_IDS.forEach((id) => { out[id] = { enabled: false, key: '', secret: '' }; });
  if (Object.keys(p).length) {
    PROVIDER_IDS.forEach((id) => {
      const e = p[id] || {};
      out[id] = { enabled: !!e.enabled, key: String(e.key || ''), secret: String(e.secret || '') };
    });
    return out;
  }
  const legacy = PROVIDER_IDS.includes(r.provider) ? r.provider : 'paystack';
  out[legacy].enabled = true;
  if (legacy !== 'manual') { out[legacy].key = r.public_key || ''; out[legacy].secret = r.secret_key || ''; }
  return out;
}
function providersIn(raw) {
  const out = {};
  PROVIDER_IDS.forEach((id) => {
    const e = (raw && typeof raw === 'object' && raw[id]) || {};
    out[id] = {
      enabled: !!e.enabled,
      key: String(e.key || '').trim().slice(0, 200),
      secret: String(e.secret || '').trim().slice(0, 200),
    };
  });
  return out;
}

app.post('/api/admin/payment-config/get', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query('SELECT * FROM payment_config WHERE id=1');
  const r = rows[0] || {};
  res.json({ provider: r.provider, currency: r.currency, key: r.public_key, secret: r.secret_key,
    business: r.business, momoAccounts: momoAccountsOut(r), bankAccounts: bankAccountsOut(r),
    providers: providersOut(r) });
}));

/* The list of direct-MoMo receiving wallets. Falls back to the legacy single
   momo_number/momo_name/momo_network columns for configs saved before the
   list existed. */
function momoAccountsOut(r) {
  const list = Array.isArray(r.momo_accounts) ? r.momo_accounts : [];
  if (list.length) return list;
  if (r.momo_number) return [{ network: r.momo_network || '', number: r.momo_number, name: r.momo_name || '' }];
  return [];
}
function momoAccountsIn(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((a) => ({
      network: String((a && a.network) || '').slice(0, 30),
      number: String((a && a.number) || '').trim().slice(0, 25),
      name: String((a && a.name) || '').trim().slice(0, 60),
    }))
    .filter((a) => a.number)
    .slice(0, 10);
}

/* Direct bank-transfer receiving accounts [{bank,number,name}] */
const bankAccountsOut = (r) => (Array.isArray(r.bank_accounts) ? r.bank_accounts : []);
function bankAccountsIn(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((a) => ({
      bank: String((a && a.bank) || '').trim().slice(0, 60),
      number: String((a && a.number) || '').trim().slice(0, 34),
      name: String((a && a.name) || '').trim().slice(0, 60),
    }))
    .filter((a) => a.number)
    .slice(0, 10);
}

app.put('/api/admin/payment-config', auth('admin'), wrap(async (req, res) => {
  const { currency, business } = req.body;
  const accounts = momoAccountsIn(req.body.momoAccounts);
  const banks = bankAccountsIn(req.body.bankAccounts);
  const provs = req.body.providers !== undefined ? providersIn(req.body.providers) : null;
  const first = accounts[0] || { network: '', number: '', name: '' };

  // Mirror the first enabled method into the legacy single-provider columns so
  // older cached clients (and helpers that read them) keep working.
  let provider = String(req.body.provider || 'paystack');
  let key = String(req.body.key || '');
  let secret = String(req.body.secret || '');
  if (provs) {
    const primary = PROVIDER_IDS.find((id) => id !== 'manual' && provs[id].enabled && provs[id].key)
      || PROVIDER_IDS.find((id) => provs[id].enabled) || 'paystack';
    provider = primary;
    key = primary !== 'manual' ? provs[primary].key : '';
    secret = primary !== 'manual' ? provs[primary].secret : '';
  }

  await query(
    `UPDATE payment_config SET provider=$1, currency=$2, public_key=$3, secret_key=$4, business=$5,
       momo_number=$6, momo_name=$7, momo_network=$8, momo_accounts=$9::jsonb,
       bank_accounts=$10::jsonb, providers=COALESCE($11::jsonb, providers) WHERE id=1`,
    [provider, currency || 'GHS', key, secret, business || 'Virtual Oracle',
     first.number, first.name, first.network, JSON.stringify(accounts),
     JSON.stringify(banks), provs ? JSON.stringify(provs) : null]
  );
  res.json({ ok: true });
}));

/* ---- Direct MoMo payment claims (provider = 'manual') ---- */
app.get('/api/admin/manual-claims', auth('admin'), wrap(async (req, res) => {
  // proof images stay out of the list (they can be MBs) — fetched per claim below
  const { rows } = await query(
    `SELECT id, email, pkg, credits, amount, txid, status, created_at,
            (proof IS NOT NULL AND proof <> '') AS has_proof
       FROM manual_claims ORDER BY (status='pending') DESC, created_at DESC LIMIT 300`);
  res.json(rows.map((r) => ({ id: r.id, email: r.email, pkg: r.pkg, credits: r.credits,
    amount: r.amount, txid: r.txid, status: r.status, created: r.created_at, hasProof: r.has_proof })));
}));

app.get('/api/admin/manual-claims/:id/proof', auth('admin'), wrap(async (req, res) => {
  const { rows } = await query('SELECT proof FROM manual_claims WHERE id=$1', [req.params.id]);
  if (!rows.length || !rows[0].proof) return res.status(404).json({ error: 'No screenshot attached to this claim.' });
  res.json({ proof: rows[0].proof });
}));

// Approve = grant the credits (exactly once — the status flip guards re-clicks);
// reject just marks it. Check the money actually landed before approving.
app.post('/api/admin/manual-claims/:id/:action', auth('admin'), wrap(async (req, res) => {
  const action = req.params.action;
  if (action !== 'approve' && action !== 'reject') return res.status(400).json({ error: 'Unknown action.' });
  const { rows } = await query(
    `UPDATE manual_claims SET status=$2, decided_at=now() WHERE id=$1 AND status='pending' RETURNING *`,
    [req.params.id, action === 'approve' ? 'approved' : 'rejected']);
  if (!rows.length) return res.status(409).json({ error: 'This claim was already handled.' });
  const c = rows[0];
  if (action === 'approve') {
    await creditPurchaseOnce(c.email, c.pkg, 'MOMO_' + c.id + '_' + String(c.txid || '').slice(0, 40), c.credits);
    await markFeeIfPaid(c.email, c.pkg);
  }
  res.json({ ok: true, status: c.status });
}));

app.get('/api/admin/stats', auth('admin'), wrap(async (req, res) => {
  const now = Date.now();
  const since = await adminRevenueSince();
  const [m, a, p, rev] = await Promise.all([
    query('SELECT COUNT(*)::int AS n FROM users'),
    query('SELECT COUNT(*)::int AS n FROM users WHERE plan_end > $1', [now]),
    query('SELECT COUNT(*)::int AS n FROM purchases WHERE created_at > $1', [since]),
    query('SELECT pkg FROM purchases WHERE created_at > $1', [since]),   // revenue needs the GHS-label parse (kept in JS)
  ]);
  res.json({
    members: m.rows[0].n,
    active: a.rows[0].n,
    purchases: p.rows[0].n,
    revenue: rev.rows.reduce((acc, r) => acc + parsePrice(r.pkg), 0),
  });
}));

/* ===================== SCREENSHOT SCAN (Gemini proxy) ===================== */
/* The Gemini key lives only here (GEMINI_API_KEY env var) and never reaches
   the browser. Any signed-in role may scan a betslip screenshot. */
const SCAN_PROMPT =
  'This is a screenshot from a SportyBet Instant Virtual Football betslip or fixture list. ' +
  'The app may be in LIGHT or DARK theme — read the text either way. ' +
  'It may contain SEVERAL matches. Find EVERY match and list ALL of them. ' +
  'Each match has TWO OPPOSING TEAMS shown next to each other, usually separated by "vs", "v", "-", or a scoreline. ' +
  'Return the exact team names as written. Do NOT include country/site names, league names, market names ' +
  '(Over/Under, BTTS, 1X2, Draw), odds, dates, times, or button labels. ' +
  'Also read the EXACT 1X2 odds for each match from the three columns headed "1", "X", "2" ' +
  '(column 1 = Home-win, column X = Draw, column 2 = Away-win). They are decimals between 1.01 and 51.00. ' +
  'Transcribe every digit exactly — do not round or estimate. If unsure about a team use "", about an odd use null. ' +
  'ALSO transcribe into "header" any title, tab, logo, league name or branding text visible near the TOP of the screenshot, ' +
  'EXACTLY as written — for example "Instant Virtuals", "Instant Football", "Premier League", "Bundesliga", "La Liga". ' +
  'If you see no such text, use an empty string. Do NOT put the word "Instant" in "header" unless it is genuinely printed in the image. ' +
  'Set "isInstant" to true ONLY if the screenshot clearly shows the SportyBet Instant Virtuals / Instant Football interface — ' +
  'signs include: an "Instant" tab or title, virtual league tabs (England, Spain, Germany, Italy, Champions), ' +
  'teams shown with star ratings, a "Next Round" button, a round countdown, or the green BB logo. ' +
  'Set it false for regular (real-match) sports betting screens or anything else. ' +
  'Respond with ONLY compact JSON: {"header":"Instant Virtuals","isInstant":true,"matches":[{"home":"Home","away":"Away","oddsHome":1.85,"oddsDraw":3.20,"oddsAway":2.10}]}. ' +
  'Returning EVERY match in "matches", the exact "header" text and "isInstant" are all required.';

/* ---- Red/Black instant game: read round results from the screenshot ---- */
const RB_PROMPT =
  'This is a screenshot from the SportyBet "Red-Black" instant card game (green-themed app; light or dark phone theme). ' +
  'It is usually the BET HISTORY panel: a vertical list of past rounds, NEWEST AT THE TOP, where each entry shows ' +
  'Time/Stake/Status, a "Your Pick" line, and a "Your Card" playing card — the card IS the round result. ' +
  'Read the RESULT of each visible round from its card. Look at the card\'s suit symbol AND its ink colour: ' +
  'hearts ♥ or diamonds ♦ (printed in RED ink) = "red"; spades ♠ or clubs ♣ (printed in BLACK ink) = "black"; ' +
  'a Joker card = "joker". ' +
  'IGNORE the "Your Pick" text completely — that is what the player bet, NOT the result. ' +
  'Ignore Status/win/lost amounts too. If the screenshot instead shows a horizontal results strip of ' +
  'red/black markers, read that the same way. ' +
  'For EACH round also transcribe its time text exactly as shown (e.g. "02:10 15/08/26") into "t" — ' +
  'use "" if no time is visible for that entry. ' +
  'Only include rounds whose card is actually visible; if none are visible, return an empty array. ' +
  'Set "isRedBlack" true ONLY if this is clearly the Red-Black game: signs include a "Red-Black" title, ' +
  '"Your Card" / "Your Pick" entries, or RED and BLACK bet buttons with playing cards. ' +
  'Anything else — football, other games, non-betting screens — is false. ' +
  'Respond with ONLY compact JSON: {"isRedBlack":true,"history":[{"t":"02:10 15/08/26","result":"red"}]}.';

const RB_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    isRedBlack: { type: 'boolean' },
    history: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          t: { type: 'string' },
          result: { type: 'string', enum: ['red', 'black', 'joker'] },
        },
        required: ['t', 'result'],
      },
    },
  },
  required: ['isRedBlack', 'history'],
};

/* Order the transcribed rounds newest-first using their own timestamps (the
   model sometimes reads lists bottom-up; the times are ground truth). Entries
   without a parseable time keep their relative order. */
function rbSortHistory(items) {
  const parseT = (s) => {
    const m = /(\d{1,2}):(\d{2})(?:\s+(\d{1,2})\/(\d{1,2})\/(\d{2,4}))?/.exec(String(s || ''));
    if (!m) return null;
    const [, hh, mm, dd, mo, yy] = m;
    const day = dd ? Date.UTC(2000 + (Number(yy) % 100), Number(mo) - 1, Number(dd)) : 0;
    return day + (Number(hh) * 60 + Number(mm)) * 60000;
  };
  return items
    .map((it, i) => ({ result: it.result, key: parseT(it.t), i }))
    .sort((a, b) => {
      if (a.key === null || b.key === null || a.key === b.key) return a.i - b.i;  // stable
      return b.key - a.key;                                                       // newest first
    })
    .map((it) => it.result);
}

const titleCase = (s) => String(s || '').toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase()).trim();

// JSON shape Claude must return (structured outputs guarantee it parses)
const ODD = { anyOf: [{ type: 'number' }, { type: 'null' }] };
const SCAN_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    header: { type: 'string' },
    isInstant: { type: 'boolean' },
    matches: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          home: { type: 'string' },
          away: { type: 'string' },
          oddsHome: ODD, oddsDraw: ODD, oddsAway: ODD,
        },
        required: ['home', 'away', 'oddsHome', 'oddsDraw', 'oddsAway'],
      },
    },
  },
  required: ['header', 'isInstant', 'matches'],
};

app.post('/api/scan', auth(), wrap(async (req, res) => {
  if (!['member', 'partner', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  if (!anthropic) return res.status(503).json({ error: 'Screenshot scanning is not configured.' });

  // which game's screenshot this is — football (default) or the Red/Black card game
  const game = String(req.body.game || 'football');
  const isRB = game === 'redblack';

  // Each scan costs real API money — members need credits for the game they're
  // scanning: Red & Black uses its own pool, football its own (or unlimited).
  if (req.user.role === 'member') {
    const [c, u] = await Promise.all([
      query('SELECT amount, rb_amount FROM credits WHERE email=$1', [req.user.email]),
      query('SELECT unlimited_until FROM users WHERE email=$1', [req.user.email]),
    ]);
    const credits = c.rows[0] ? c.rows[0].amount : 0;
    const rbCredits = c.rows[0] ? c.rows[0].rb_amount : 0;
    const unlimited = u.rows[0] && Number(u.rows[0].unlimited_until) > Date.now();
    if (isRB) {
      if (rbCredits <= 0) return res.status(402).json({ error: 'You need Red & Black credits — buy the Red & Black package first.' });
    } else if (!credits && !unlimited) {
      return res.status(402).json({ error: 'You need prediction credits to scan — buy a package first.' });
    }
  }
  const m = /^data:(image\/(?:png|jpe?g|gif|webp));base64,(.*)$/i.exec(String(req.body.image || ''));
  if (!m) return res.status(400).json({ error: 'Bad image data' });
  let mediaType = m[1].toLowerCase();
  if (mediaType === 'image/jpg') mediaType = 'image/jpeg';
  const base64 = m[2];

  let text = '';
  try {
    const message = await anthropic.messages.create({
      model: CLAUDE_MODEL,
      max_tokens: 2048,
      output_config: { format: { type: 'json_schema', schema: isRB ? RB_SCHEMA : SCAN_SCHEMA } },
      messages: [{
        role: 'user',
        content: [
          { type: 'image', source: { type: 'base64', media_type: mediaType, data: base64 } },
          { type: 'text', text: isRB ? RB_PROMPT : SCAN_PROMPT },
        ],
      }],
    });
    if (message.stop_reason === 'refusal') return res.status(502).json({ error: 'Scan was declined.' });
    text = message.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
  } catch (e) {
    // SDK auto-retries 429/5xx; if it still surfaces, tell the client it's busy
    if (e && e.status === 429) return res.status(429).json({ error: 'The scanner is busy (rate limit). Please wait a moment and try again.' });
    console.warn('[scan] Claude error', e && e.status, e && e.message);
    return res.status(502).json({ error: 'Scan failed' });
  }

  let parsed;
  try { parsed = JSON.parse(text); }
  catch { const j = text.match(/\{[\s\S]*\}/); parsed = j ? JSON.parse(j[0]) : {}; }

  if (isRB) {
    const items = (Array.isArray(parsed.history) ? parsed.history : [])
      .filter((h) => h && ['red', 'black', 'joker'].includes(h.result))
      .slice(0, 40);
    const history = rbSortHistory(items);
    query('UPDATE scan_meter SET used = used + 1, remaining = GREATEST(0, remaining - 1) WHERE id=1').catch(() => {});
    return res.json({ redblack: parsed.isRedBlack === true, history });
  }

  let arr = [];
  if (Array.isArray(parsed.matches)) arr = parsed.matches;
  else if (Array.isArray(parsed)) arr = parsed;
  else if (parsed.home || parsed.away) arr = [parsed];

  const num = (v) => { const f = parseFloat(v); return (isFinite(f) && f >= 1.01 && f <= 51) ? +f.toFixed(2) : null; };
  const matches = arr.map((mm) => ({
    home: titleCase((mm.home || '').trim()),
    away: titleCase((mm.away || '').trim()),
    odds: { home: num(mm.oddsHome), draw: num(mm.oddsDraw), away: num(mm.oddsAway) },
  })).filter((mm) => mm.home || mm.away);

  // A header that says "Instant" settles it. Otherwise fall back to the
  // model's UI-marker judgment (dark theme / cropped slips often hide the
  // header even on genuine Instant Virtuals screens).
  const headerText = String(parsed.header || '');
  const instant = /\binstant\b/i.test(headerText) || parsed.isInstant === true;

  // meter a completed scan (best-effort; never block the response)
  query('UPDATE scan_meter SET used = used + 1, remaining = GREATEST(0, remaining - 1) WHERE id=1').catch(() => {});

  res.json({ matches, instant });
}));

/* ===================== FX rates (GHS → local; display only) ===================== */
const FX_CODES = ['NGN', 'KES', 'TZS', 'ZMW', 'ZAR'];
app.get('/api/fx-rates', wrap(async (req, res) => {
  const { rows } = await query('SELECT code, rate FROM fx_rates');
  const out = {};
  rows.forEach((r) => { out[r.code] = Number(r.rate); });
  res.json(out);
}));
app.put('/api/admin/fx-rates', auth('admin'), wrap(async (req, res) => {
  const body = req.body || {};
  for (const code of FX_CODES) {
    const rate = Number(body[code]);
    if (!isNaN(rate) && rate > 0) {
      await query('INSERT INTO fx_rates (code,rate) VALUES ($1,$2) ON CONFLICT (code) DO UPDATE SET rate = EXCLUDED.rate', [code, rate]);
    }
  }
  const { rows } = await query('SELECT code, rate FROM fx_rates');
  const out = {};
  rows.forEach((r) => { out[r.code] = Number(r.rate); });
  res.json({ ok: true, rates: out });
}));

/* ===================== PUBLIC payment config ===================== */
// only non-secret fields — safe to expose to the checkout page
app.get('/api/payment-config/public', wrap(async (req, res) => {
  const { rows } = await query('SELECT provider,currency,public_key,business,momo_number,momo_name,momo_network,momo_accounts,bank_accounts,providers FROM payment_config WHERE id=1');
  const r = rows[0] || {};
  const provs = providersOut(r);   // never sent raw — secrets stay server-side
  const methods = PROVIDER_IDS.filter((id) => provs[id].enabled)
    .map((id) => ({ id, key: (id === 'manual' || id === 'bank') ? '' : provs[id].key }));
  res.json({ provider: r.provider, currency: r.currency, key: r.public_key, business: r.business,
    momoAccounts: momoAccountsOut(r), bankAccounts: bankAccountsOut(r), methods });
}));

/* ===================== Cowrie gateway proxy ===================== */
/* Cowrie has no CORS, and its secret key must stay server-side, so the
   browser talks to these endpoints instead of Cowrie directly.
   Public (no auth): used during signup before the member account exists.
   Crediting still happens through the authenticated purchase routes once
   this proxy confirms Cowrie reports the charge as paid. */
const COWRIE_BASE = (process.env.COWRIE_API_BASE || 'https://cowrie-gateway.onrender.com').replace(/\/+$/, '');

async function cowrieKey() {
  const { rows } = await query('SELECT secret_key, public_key, providers FROM payment_config WHERE id=1');
  const r = rows[0] || {};
  const c = (r.providers && r.providers.cowrie) || {};   // per-method keys win over legacy columns
  return (c.secret && c.secret.trim()) || (c.key && c.key.trim())
    || (r.secret_key && r.secret_key.trim()) || (r.public_key && r.public_key.trim()) || '';
}

/* Re-verify a Cowrie charge server-side so crediting never trusts the client.
   Returns { paid, credits, pkg, email } or null if it can't be verified. */
async function verifyCowrieCharge(reference) {
  const key = await cowrieKey();
  if (!key) return null;
  try {
    const r = await fetch(COWRIE_BASE + '/api/charges/' + encodeURIComponent(reference), {
      headers: { 'Authorization': 'Bearer ' + key },
    });
    const data = await r.json().catch(() => null);
    const c = data && data.charge;
    if (!c) return null;
    const meta = c.metadata || {};
    return {
      paid: c.status === 'success' || !!c.paidAt,
      credits: parseInt(meta.credits, 10) || 0,
      pkg: String(meta.package || ('Cowrie ' + (c.amount != null ? c.amount : ''))),
      email: norm(c.email || c.customerEmail || ''),
    };
  } catch (e) { return null; }
}

// create a charge → returns { reference, checkoutUrl }
app.post('/api/pay/cowrie/init', wrap(async (req, res) => {
  const key = await cowrieKey();
  if (!key) return res.status(503).json({ error: 'Payment gateway is not configured.' });
  const { amount, currency, email, metadata, callbackUrl } = req.body || {};
  if (!amount || isNaN(amount)) return res.status(400).json({ error: 'A valid amount is required.' });
  // Always send Cowrie a return URL so the buyer comes back to our pricing page
  // (which then confirms and forwards to the dashboard). Never depend on the
  // client to supply it — a cached old page wouldn't, and Cowrie would then
  // fall back to the landing page.
  const origin = (typeof req.headers.origin === 'string' && /^https?:\/\//.test(req.headers.origin))
    ? req.headers.origin
    : (req.protocol + '://' + req.get('host'));
  const returnUrl = (typeof callbackUrl === 'string' && /^https?:\/\//.test(callbackUrl))
    ? callbackUrl
    : (origin + '/pricing.html');
  let charge;
  try {
    const r = await fetch(COWRIE_BASE + '/api/charges', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      // Cowrie amounts are in minor units (pesewas), like Paystack — GHS 400 = 40000
      body: JSON.stringify({
        amount: Math.round(Number(amount) * 100), currency: currency || 'GHS', email: email || '',
        metadata: metadata || {},
        callbackUrl: returnUrl,
      }),
    });
    const data = await r.json().catch(() => null);
    charge = data && data.charge;
    if (!r.ok || !charge || !charge.reference) return res.status(502).json({ error: 'Could not start payment.' });
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach the payment gateway.' });
  }
  res.json({
    reference: charge.reference,
    checkoutUrl: COWRIE_BASE + '/checkout?reference=' + encodeURIComponent(charge.reference),
  });
}));

// poll a charge → returns { status, paid, failed }
app.get('/api/pay/cowrie/status', wrap(async (req, res) => {
  const key = await cowrieKey();
  if (!key) return res.status(503).json({ error: 'Payment gateway is not configured.' });
  const reference = String(req.query.reference || '');
  if (!reference) return res.status(400).json({ error: 'reference is required.' });
  let charge;
  try {
    const r = await fetch(COWRIE_BASE + '/api/charges/' + encodeURIComponent(reference), {
      headers: { 'Authorization': 'Bearer ' + key },
    });
    const data = await r.json().catch(() => null);
    charge = data && data.charge;
    if (!r.ok || !charge) return res.status(502).json({ error: 'Could not check payment.' });
  } catch (e) {
    return res.status(502).json({ error: 'Could not reach the payment gateway.' });
  }
  const status = charge.status || 'pending';
  res.json({ status, paid: status === 'success' || !!charge.paidAt, failed: status === 'failed' });
}));

// Cowrie webhook — server-to-server payment notification.
// We don't trust the payload's contents: we use it only as a trigger, then
// RE-VERIFY the charge directly with Cowrie (with our secret) before crediting.
// That makes it secure even without a signature. Idempotent per charge reference.
// Always returns 200 so Cowrie doesn't retry endlessly on cases we intentionally skip.
app.post('/api/pay/cowrie/webhook', wrap(async (req, res) => {
  const b = req.body || {};
  const reference =
    b.reference ||
    (b.charge && b.charge.reference) ||
    (b.data && (b.data.reference || (b.data.charge && b.data.charge.reference))) ||
    '';
  if (!reference) return res.status(200).json({ ok: true, ignored: 'no reference' });

  const key = await cowrieKey();
  if (!key) return res.status(200).json({ ok: true, ignored: 'gateway not configured' });

  let charge;
  try {
    const r = await fetch(COWRIE_BASE + '/api/charges/' + encodeURIComponent(reference), {
      headers: { 'Authorization': 'Bearer ' + key },
    });
    const data = await r.json().catch(() => null);
    charge = data && data.charge;
  } catch (e) {
    return res.status(200).json({ ok: true, ignored: 'verify failed' });
  }
  if (!charge) return res.status(200).json({ ok: true, ignored: 'charge not found' });

  const paid = charge.status === 'success' || !!charge.paidAt;
  if (!paid) return res.status(200).json({ ok: true, ignored: 'not paid' });

  const email = norm(charge.email || charge.customerEmail || '');
  const meta = charge.metadata || {};
  const credits = parseInt(meta.credits, 10) || 0;
  const pkg = String(meta.package || ('Cowrie ' + (charge.amount != null ? charge.amount : '')));
  if (!email) return res.status(200).json({ ok: true, ignored: 'no email on charge' });

  // only credit a real, existing member
  const u = await query('SELECT 1 FROM users WHERE email=$1', [email]);
  if (!u.rows.length) return res.status(200).json({ ok: true, ignored: 'no matching member' });

  // credit exactly once (atomic; safe against the browser poll racing this)
  const r = await creditPurchaseOnce(email, pkg, reference, credits);
  await markFeeIfPaid(email, pkg);
  res.status(200).json({ ok: true, credited: r.duplicate ? 0 : credits, duplicate: r.duplicate });
}));

/* ============================ static site ============================ */
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  setHeaders(res, filePath) {
    // Never let browsers serve a stale page/script — always revalidate so fixes
    // (like the payment-return flow) take effect immediately. Static assets are
    // small here, so the revalidation cost is negligible.
    if (/\.(html|js)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache, must-revalidate');
    }
  },
}));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* ============================ boot ============================ */
initSchema()
  .catch((e) => console.error('Schema init failed (continuing):', e.message))
  .finally(() => {
    app.listen(PORT, () => console.log(`✓ Virtual Oracle running on :${PORT}`));
  });
