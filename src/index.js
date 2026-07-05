// Auth API for parals.net — Cloudflare Workers + D1.
// Endpoints: POST /api/register, POST /api/login, POST /api/logout, GET /api/me
// Security: parameterized SQL, PBKDF2 hashing, HttpOnly/Secure/SameSite cookies,
// per-IP rate limiting, request-size + password-length caps, hardened headers.

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100_000;
const MAX_BODY_BYTES = 4096;
const MAX_PASSWORD_LEN = 256;

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
    case "POST /api/register": return register(request, env, ip);
    case "POST /api/login": return login(request, env, ip);
    case "POST /api/logout": return logout(request, env);
    case "GET /api/me": return me(request, env);
    default: return json({ error: "Not found" }, 404);
  }
}

async function register(request, env, ip) {
  // Layer 2: strict limit on account creation per IP
  if (await limited(env.AUTH_LIMITER, "reg:" + ip)) return tooMany();

  const body = await readBody(request);
  const username = (body.username || "").trim();
  const password = body.password || "";

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return json({ error: "Username must be 3-32 characters (letters, numbers, _ . -)" }, 400);
  }
  if (password.length < 8 || password.length > MAX_PASSWORD_LEN) {
    return json({ error: `Password must be 8-${MAX_PASSWORD_LEN} characters` }, 400);
  }

  const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?")
    .bind(username).first();
  if (existing) return json({ error: "Username is already taken" }, 409);

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const result = await env.DB.prepare(
    "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)"
  ).bind(username, hash, salt).run();

  return createSession(env, result.meta.last_row_id, { username, created: true });
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
    "SELECT id, username, password_hash, salt FROM users WHERE username = ?"
  ).bind(username).first();

  // Hash even when the user doesn't exist so both paths take similar time
  const hash = await hashPassword(password, user ? user.salt : randomHex(16));
  if (!user || !timingSafeEqual(hash, user.password_hash)) {
    return json({ error: "Wrong username or password" }, 401);
  }

  return createSession(env, user.id, { username: user.username });
}

async function logout(request, env) {
  const token = getCookie(request, "session");
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
  }
  return json({ ok: true }, 200, clearCookieHeader());
}

async function me(request, env) {
  const token = getCookie(request, "session");
  if (!token) return json({ error: "Not signed in" }, 401);

  const row = await env.DB.prepare(
    `SELECT u.username, u.created_at, s.expires_at FROM sessions s
     JOIN users u ON u.id = s.user_id WHERE s.token = ?`
  ).bind(token).first();

  if (!row || row.expires_at < Date.now()) {
    return json({ error: "Session expired" }, 401, clearCookieHeader());
  }
  return json({ username: row.username, created_at: row.created_at });
}

async function createSession(env, userId, payload) {
  // Opportunistic cleanup so expired sessions don't pile up
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()).run();

  const token = randomHex(32);
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(token, userId, expiresAt).run();

  const cookie = `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 24 * 60 * 60}`;
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
