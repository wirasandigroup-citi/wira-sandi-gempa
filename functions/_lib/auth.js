// ── Shared auth helpers ──────────────────────────────────────────────
// KV binding expected: env.USERS  (namespace: GEMPA_USERS)

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 hari
const PBKDF2_ITERATIONS = 100000;

function b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64ToBuf(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

export async function hashPassword(password, saltB64) {
  const enc = new TextEncoder();
  const salt = saltB64 ? b64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return { hash: b64(bits), salt: b64(salt) };
}

export async function verifyPassword(password, saltB64, hashB64) {
  const { hash } = await hashPassword(password, saltB64);
  return timingSafeEqual(hash, hashB64);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export async function getUser(env, email) {
  const raw = await env.USERS.get('user:' + normalizeEmail(email));
  return raw ? JSON.parse(raw) : null;
}

export async function putUser(env, user) {
  await env.USERS.put('user:' + normalizeEmail(user.email), JSON.stringify(user));
}

export async function listUsers(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.USERS.list({ prefix: 'user:', cursor });
    for (const k of page.keys) {
      const raw = await env.USERS.get(k.name);
      if (raw) out.push(JSON.parse(raw));
    }
    cursor = page.cursor;
    if (page.list_complete) break;
  } while (cursor);
  return out.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
}

export async function createSession(env, email) {
  const token = crypto.randomUUID() + '-' + crypto.randomUUID();
  await env.USERS.put('session:' + token, normalizeEmail(email), { expirationTtl: SESSION_TTL_SECONDS });
  return token;
}

export async function destroySession(env, token) {
  if (token) await env.USERS.delete('session:' + token);
}

export function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

export function sessionCookie(token) {
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
}

export function clearSessionCookie() {
  return `session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

export async function getSessionUser(request, env) {
  const token = getCookie(request, 'session');
  if (!token) return null;
  const email = await env.USERS.get('session:' + token);
  if (!email) return null;
  const user = await getUser(env, email);
  return user ? { ...user, _sessionToken: token } : null;
}

export function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) }
  });
}
