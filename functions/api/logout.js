import { getCookie, destroySession, clearSessionCookie, json } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  const token = getCookie(request, 'session');
  await destroySession(env, token);
  return json({ ok: true }, { headers: { 'Set-Cookie': clearSessionCookie() } });
}
