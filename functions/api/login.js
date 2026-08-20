import { getUser, verifyPassword, createSession, sessionCookie, normalizeEmail, json } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Data tidak valid' }, { status: 400 }); }

  const email = normalizeEmail(body.email);
  const password = String(body.password || '');

  const user = await getUser(env, email);
  if (!user) return json({ error: 'Email atau password salah' }, { status: 401 });

  const ok = await verifyPassword(password, user.salt, user.passwordHash);
  if (!ok) return json({ error: 'Email atau password salah' }, { status: 401 });

  if (!user.approved) return json({ error: 'Akun Anda menunggu persetujuan admin' }, { status: 403 });

  const token = await createSession(env, email);
  return json({ ok: true, role: user.role }, {
    headers: { 'Set-Cookie': sessionCookie(token) }
  });
}
