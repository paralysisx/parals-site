// Auth API for parals.net — runs on Cloudflare Workers with a D1 database.
// Endpoints: POST /api/register, POST /api/login, POST /api/logout, GET /api/me

const SESSION_DAYS = 7;
const PBKDF2_ITERATIONS = 100_000;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (err) {
        console.error(err);
        return json({ error: "Server error" }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  },
};

async function handleApi(request, env, url) {
  const route = `${request.method} ${url.pathname}`;
  switch (route) {
    case "POST /api/register": return register(request, env);
    case "POST /api/login": return login(request, env);
    case "POST /api/logout": return logout(request, env);
    case "GET /api/me": return me(request, env);
    default: return json({ error: "Not found" }, 404);
  }
}

async function register(request, env) {
  const body = await readBody(request);
  const username = (body.username || "").trim();
  const password = body.password || "";

  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
    return json({ error: "Username must be 3-32 characters (letters, numbers, _ . -)" }, 400);
  }
  if (password.length < 8) {
    return json({ error: "Password must be at least 8 characters" }, 400);
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

async function login(request, env) {
  const body = await readBody(request);
  const username = (body.username || "").trim();
  const password = body.password || "";

  const user = await env.DB.prepare(
    "SELECT id, username, password_hash, salt FROM users WHERE username = ?"
  ).bind(username).first();

  // Hash even when the user doesn't exist so both paths take similar time
  const hash = await hashPassword(password, user ? user.salt : randomHex(16));
  if (!user || hash !== user.password_hash) {
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
  try {
    return await request.json();
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
