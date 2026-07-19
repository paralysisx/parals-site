import { EmailMessage } from "cloudflare:email";

// Auth API for parals.net — Cloudflare Workers + D1.
// Endpoints: POST /api/register, POST /api/login, POST /api/logout, GET /api/me,
//            POST /api/approve, POST /api/decline, GET /admin/review
// Registration is gated: a new sign-up is stored as 'pending' and an email with a
// review link is sent to the admin, who approves or declines it.
// Security: parameterized SQL, PBKDF2 hashing, HttpOnly/Secure/SameSite cookies,
// per-IP rate limiting, request-size + password-length caps, hardened headers.

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100_000;
const MAX_BODY_BYTES = 4096;
const MAX_PASSWORD_LEN = 256;
const MAX_EMAIL_LEN = 254;

// Where registration requests are emailed, and the from-address they're sent as.
// NOTIFY_EMAIL must be a *verified* Email Routing destination. it@parals.net
// forwards to this address, so requests arrive in that same inbox.
const NOTIFY_EMAIL = "hristoylasdimitris@gmail.com";
const FROM_EMAIL = "noreply@parals.net";
const FROM_NAME = "parals";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      let res;
      try {
        res = await handleApi(request, env, url, ctx);
      } catch (err) {
        console.error(err);
        res = json({ error: "Server error" }, 500);
      }
      return secure(res);
    }

    // Admin-facing registration review page (reached from the approval email).
    if (url.pathname === "/admin/review") {
      let res;
      try {
        res = await reviewPage(request, env, url);
      } catch (err) {
        console.error(err);
        res = html("<h1>Server error</h1>", 500);
      }
      return secure(res);
    }

    const assetRes = await env.ASSETS.fetch(request);
    return secure(assetRes);
  },
};

async function handleApi(request, env, url, ctx) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  // Layer 1: broad per-IP limit across all API traffic
  if (await limited(env.API_LIMITER, ip)) {
    return tooMany();
  }

  const route = `${request.method} ${url.pathname}`;
  switch (route) {
    case "POST /api/register": return register(request, env, ip, ctx);
    case "POST /api/login": return login(request, env, ip);
    case "POST /api/logout": return logout(request, env);
    case "GET /api/me": return me(request, env);
    case "POST /api/approve": return decide(request, env, "approve");
    case "POST /api/decline": return decide(request, env, "decline");
    case "GET /api/admin/pending": return adminPending(request, env);
    case "POST /api/admin/approve": return adminDecide(request, env, "approve");
    case "POST /api/admin/decline": return adminDecide(request, env, "decline");
    default: return json({ error: "Not found" }, 404);
  }
}

async function register(request, env, ip, ctx) {
  // Layer 2: strict limit on account creation per IP
  if (await limited(env.AUTH_LIMITER, "reg:" + ip)) return tooMany();

  const body = await readBody(request);
  const username = (body.username || "").trim();
  const password = body.password || "";
  const email = (body.email || "").trim();

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return json({ error: "Username must be 3-32 characters (letters, numbers, _ . -)" }, 400);
  }
  if (password.length < 8 || password.length > MAX_PASSWORD_LEN) {
    return json({ error: `Password must be 8-${MAX_PASSWORD_LEN} characters` }, 400);
  }
  if (!validEmail(email)) {
    return json({ error: "Enter a valid email address" }, 400);
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?")
    .bind(username).first();
  if (existing) return json({ error: "That username is already taken or awaiting approval" }, 409);

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const approvalToken = randomHex(32);
  await env.DB.prepare(
    `INSERT INTO users (username, password_hash, salt, email, status, approval_token)
     VALUES (?, ?, ?, ?, 'pending', ?)`
  ).bind(username, hash, salt, email, approvalToken).run();

  // Notify the admin. Don't fail the request if email delivery hiccups — the
  // request is safely recorded and still visible/approvable; just log it.
  const reviewUrl = `${new URL(request.url).origin}/admin/review?token=${approvalToken}`;
  await sendApprovalEmail(env, { username, email, ip, reviewUrl }).catch((err) =>
    console.error("approval email failed:", err)
  );

  return json({ pending: true });
}

async function login(request, env, ip) {
  // Layer 2: strict limit on login attempts per IP (brute-force defense)
  if (await limited(env.AUTH_LIMITER, "login:" + ip)) return tooMany();

  const body = await readBody(request);
  const username = (body.username || "").trim();
  const password = body.password || "";

  // Reject oversized passwords before spending CPU on hashing
  if (password.length > MAX_PASSWORD_LEN) {
    return json({ error: "Wrong username or password" }, 401);
  }

  const user = await env.DB.prepare(
    "SELECT id, username, password_hash, salt, status FROM users WHERE username = ?"
  ).bind(username).first();

  // Hash even when the user doesn't exist so both paths take similar time
  const hash = await hashPassword(password, user ? user.salt : randomHex(16));
  if (!user || !timingSafeEqual(hash, user.password_hash)) {
    return json({ error: "Wrong username or password" }, 401);
  }

  // Correct credentials, but the account still needs admin approval.
  if (user.status !== "approved") {
    return json({ error: "Your registration is still awaiting admin approval." }, 403);
  }

  return createSession(env, user.id, { username: user.username });
}

async function logout(request, env) {
  const token = getCookie(request, "session");
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }
  return withClearedCookies(json({ ok: true }));
}

async function me(request, env) {
  const user = await currentUser(request, env);
  if (!user) return withClearedCookies(json({ error: "Not signed in" }, 401));
  return json({ username: user.username, created_at: user.created_at, role: user.role });
}

// Clear both cookie scopes: the new domain-wide one and the legacy host-only
// one from before the family SSO, so logout always sticks.
function withClearedCookies(res) {
  res.headers.append("Set-Cookie", "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0; Domain=.parals.net");
  res.headers.append("Set-Cookie", "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  return res;
}

// Resolve the signed-in user from the session cookie, or null if none/expired.
async function currentUser(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.role, u.created_at, s.expires_at FROM sessions s
     JOIN users u ON u.id = s.user_id WHERE s.token = ?`
  ).bind(token).first();
  if (!row || row.expires_at < Date.now()) return null;
  return row;
}

// ---- registration approval ----

// Approve or decline a pending registration by its one-time token.
// Called (via fetch) from the buttons on the /admin/review page.
async function decide(request, env, action) {
  const body = await readBody(request);
  const token = (body.token || "").trim();
  if (!token) return json({ error: "Missing token" }, 400);

  const user = await env.DB.prepare(
    "SELECT id, username, status FROM users WHERE approval_token = ?"
  ).bind(token).first();

  // Token already spent (approved/declined) or never existed.
  if (!user) return json({ error: "This request has already been handled or is no longer valid." }, 410);

  if (action === "approve") {
    await env.DB.prepare(
      "UPDATE users SET status = 'approved', approval_token = NULL WHERE id = ?"
    ).bind(user.id).run();
    return json({ ok: true, username: user.username, result: "approved" });
  }

  // Decline: remove the pending account entirely so the username frees up.
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(user.id).run();
  return json({ ok: true, username: user.username, result: "declined" });
}

// List pending sign-ups for the admin panel. Admin session required.
async function adminPending(request, env) {
  const admin = await requireAdmin(request, env);
  if (admin.error) return admin.error;

  const { results } = await env.DB.prepare(
    "SELECT id, username, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at"
  ).all();
  return json({ pending: results });
}

// Approve or decline a pending user by id, from the admin panel. Admin required.
async function adminDecide(request, env, action) {
  const admin = await requireAdmin(request, env);
  if (admin.error) return admin.error;

  const body = await readBody(request);
  const id = parseInt(body.id, 10);
  if (!id) return json({ error: "Missing id" }, 400);

  const target = await env.DB.prepare(
    "SELECT id, username, status FROM users WHERE id = ?"
  ).bind(id).first();
  if (!target || target.status !== "pending") {
    return json({ error: "That request no longer exists." }, 404);
  }

  if (action === "approve") {
    await env.DB.prepare(
      "UPDATE users SET status = 'approved', approval_token = NULL WHERE id = ?"
    ).bind(id).run();
    return json({ ok: true, username: target.username, result: "approved" });
  }

  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
  return json({ ok: true, username: target.username, result: "declined" });
}

// Gate: returns { user } for an admin session, or { error: Response } otherwise.
async function requireAdmin(request, env) {
  const user = await currentUser(request, env);
  if (!user) return { error: json({ error: "Not signed in" }, 401) };
  if (user.role !== "admin") return { error: json({ error: "Forbidden" }, 403) };
  return { user };
}

// Admin-facing HTML page linked from the approval email. Shows the request and
// offers Approve / Decline buttons that POST back to the API with the token.
async function reviewPage(request, env, url) {
  const token = (url.searchParams.get("token") || "").trim();
  const user = token
    ? await env.DB.prepare(
        "SELECT username, email, created_at FROM users WHERE approval_token = ? AND status = 'pending'"
      ).bind(token).first()
    : null;

  if (!user) {
    return html(reviewShell(`
      <h1>Nothing to review</h1>
      <p class="muted">This registration request has already been handled, or the link is no longer valid.</p>
    `), 200);
  }

  const page = reviewShell(`
    <h1>Registration request</h1>
    <dl>
      <dt>Username</dt><dd>${esc(user.username)}</dd>
      <dt>Email</dt><dd>${esc(user.email || "—")}</dd>
      <dt>Requested</dt><dd>${esc(user.created_at)} UTC</dd>
    </dl>
    <div class="actions">
      <button id="approve" class="btn approve">Approve</button>
      <button id="decline" class="btn decline">Decline</button>
    </div>
    <p class="msg" id="msg"></p>
    <script>
      const token = ${JSON.stringify(token)};
      const msg = document.getElementById("msg");
      const buttons = document.querySelectorAll(".btn");
      async function decide(action) {
        buttons.forEach((b) => (b.disabled = true));
        msg.textContent = "Working…";
        try {
          const res = await fetch("/api/" + action, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token }),
          });
          const data = await res.json();
          if (!res.ok) { msg.textContent = data.error || "Something went wrong"; buttons.forEach((b) => (b.disabled = false)); return; }
          document.querySelector(".actions").style.display = "none";
          msg.className = "msg done";
          msg.textContent = data.result === "approved"
            ? "Approved — " + data.username + " can now sign in."
            : "Declined — the request was removed.";
        } catch {
          msg.textContent = "Network error — try again";
          buttons.forEach((b) => (b.disabled = false));
        }
      }
      document.getElementById("approve").onclick = () => decide("approve");
      document.getElementById("decline").onclick = () => decide("decline");
    </script>
  `);
  return html(page, 200);
}

// Send the "new registration request" email to the admin via the Email Routing
// binding. Builds a MIME message by hand so we need no extra dependencies.
async function sendApprovalEmail(env, { username, email, ip, reviewUrl }) {
  if (!env.EMAIL) {
    // No binding (e.g. local dev without --remote): log the link so it's usable.
    console.log(`[registration] ${username} <${email}> — review: ${reviewUrl}`);
    return;
  }
  const subject = `New registration request: ${username}`;
  const text =
    `A new account is awaiting approval.\n\n` +
    `Username: ${username}\n` +
    `Email:    ${email}\n` +
    `IP:       ${ip}\n\n` +
    `Review and approve or decline:\n${reviewUrl}\n`;
  const htmlBody = `<!DOCTYPE html><html><body>
    <div style="font-family:system-ui,Segoe UI,sans-serif;max-width:520px;margin:auto">
      <h2 style="margin:0 0 .5rem">New registration request</h2>
      <p style="color:#555;margin:0 0 1rem">An account is awaiting your approval.</p>
      <table style="border-collapse:collapse;font-size:14px">
        <tr><td style="padding:4px 12px 4px 0;color:#888">Username</td><td><b>${esc(username)}</b></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#888">Email</td><td>${esc(email)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:#888">IP</td><td>${esc(ip)}</td></tr>
      </table>
      <p style="margin:1.5rem 0">
        <a href="${esc(reviewUrl)}" style="background:#7c5cff;color:#fff;text-decoration:none;padding:11px 22px;border-radius:10px;font-weight:600;display:inline-block">Review request &rarr;</a>
      </p>
      <p style="color:#999;font-size:12px">Or paste this link: ${esc(reviewUrl)}</p>
    </div></body></html>`;

  const raw = buildMime({
    fromName: FROM_NAME,
    from: FROM_EMAIL,
    to: NOTIFY_EMAIL,
    subject,
    text,
    html: htmlBody,
  });
  await env.EMAIL.send(new EmailMessage(FROM_EMAIL, NOTIFY_EMAIL, raw));
}

// Assemble a multipart/alternative RFC 5322 message. Bodies are base64-encoded
// so arbitrary UTF-8 content (usernames, URLs) survives without QP escaping.
function buildMime({ fromName, from, to, subject, text, html }) {
  const boundary = "b_" + randomHex(16);
  const headers = [
    `From: ${fromName} <${from}>`,
    `To: ${to}`,
    `Subject: ${encodeHeader(subject)}`,
    `Message-ID: <${randomHex(16)}@parals.net>`,
    `Date: ${new Date().toUTCString()}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
  ];
  const part = (type, body) =>
    [
      `--${boundary}`,
      `Content-Type: ${type}; charset="utf-8"`,
      `Content-Transfer-Encoding: base64`,
      ``,
      base64Wrapped(body),
    ].join("\r\n");
  return (
    headers.join("\r\n") +
    "\r\n\r\n" +
    part("text/plain", text) +
    "\r\n" +
    part("text/html", html) +
    `\r\n--${boundary}--\r\n`
  );
}

// RFC 2047-encode a header value if it contains non-ASCII; otherwise pass through.
function encodeHeader(value) {
  if (/^[\x20-\x7E]*$/.test(value)) return value;
  return `=?utf-8?B?${btoa(unescape(encodeURIComponent(value)))}?=`;
}

// Base64-encode a UTF-8 string, wrapped at 76 chars per line (RFC 2045).
function base64Wrapped(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/.{76}/g, "$&\r\n");
}

async function createSession(env, userId, payload) {
  // Opportunistic cleanup so expired sessions don't pile up
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()).run();

  const token = randomHex(32);
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(token, userId, expiresAt).run();

  // Domain-wide cookie: one sign-in covers the whole Serenity family
  // (parals.net + capture.parals.net share the sessions table).
  const cookie = `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 24 * 60 * 60}; Domain=.parals.net`;
  return json(payload, 200, { "Set-Cookie": cookie });
}

// ---- security helpers ----

async function limited(limiter, key) {
  if (!limiter) return false; // fail open if binding missing (e.g. local dev)
  try {
    const { success } = await limiter.limit({ key });
    return !success;
  } catch {
    return false;
  }
}

function tooMany() {
  return json({ error: "Too many requests — slow down and try again shortly." }, 429, {
    "Retry-After": "60",
  });
}

// Constant-time string comparison to avoid leaking hash bytes via timing
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const salt = new Uint8Array(saltHex.match(/../g).map((b) => parseInt(b, 16)));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomHex(bytes) {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function readBody(request) {
  // Reject oversized payloads before parsing
  const len = parseInt(request.headers.get("Content-Length") || "0", 10);
  if (len > MAX_BODY_BYTES) return {};
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) return {};
    return JSON.parse(text);
  } catch {
    return {};
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

function clearCookieHeader() {
  return { "Set-Cookie": "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function validEmail(email) {
  return email.length <= MAX_EMAIL_LEN && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Escape untrusted values before interpolating into HTML.
function esc(str) {
  return String(str).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// Minimal styled document wrapper for the admin review page.
function reviewShell(inner) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>parals — review registration</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif; background:#070b18; color:#eaeefb; padding:1.5rem; }
  .card { width:100%; max-width:26rem; background:rgba(19,26,48,.72); border:1px solid rgba(110,130,190,.22);
    border-radius:20px; padding:2rem; box-shadow:0 30px 80px rgba(0,0,0,.55); }
  h1 { font-size:1.35rem; margin:0 0 1rem; }
  .muted { color:#8d97b5; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:.4rem 1rem; margin:0 0 1.5rem; font-size:.95rem; }
  dt { color:#8d97b5; }
  dd { margin:0; word-break:break-all; }
  .actions { display:flex; gap:.75rem; }
  .btn { flex:1; padding:.75rem; border:0; border-radius:11px; font:inherit; font-weight:700; color:#fff;
    cursor:pointer; transition:filter .15s ease, opacity .15s ease; }
  .btn:hover { filter:brightness(1.08); }
  .btn:disabled { opacity:.5; cursor:default; }
  .approve { background:linear-gradient(135deg,#22c55e,#16a34a); }
  .decline { background:linear-gradient(135deg,#fb7185,#e11d48); }
  .msg { min-height:1.2rem; margin:1rem 0 0; text-align:center; color:#8d97b5; font-size:.9rem; }
  .msg.done { color:#34d399; font-weight:600; }
</style></head><body><main class="card">${inner}</main></body></html>`;
}

// Attach hardened security headers to every response (assets + API)
function secure(res) {
  const r = new Response(res.body, res);
  const h = r.headers;
  h.set("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=()");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  h.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
    ].join("; ")
  );
  return r;
}
