import { getUser, putUser, normalizeEmail, json } from '../../_lib/auth.js';

// POST body: { email, action: 'approve' | 'reject' | 'promote' | 'demote' | 'delete' }
export async function onRequestPost({ request, env, data }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Data tidak valid' }, { status: 400 }); }

  const email = normalizeEmail(body.email);
  const action = body.action;
  if (!email || !action) return json({ error: 'Parameter kurang' }, { status: 400 });

  const target = await getUser(env, email);
  if (!target) return json({ error: 'User tidak ditemukan' }, { status: 404 });

  const actor = data.user;
  if (target.email === actor.email && (action === 'delete' || action === 'demote')) {
    return json({ error: 'Tidak bisa menghapus/menurunkan role akun sendiri' }, { status: 400 });
  }

  switch (action) {
    case 'approve':
      target.approved = true;
      await putUser(env, target);
      break;
    case 'reject':
      await env.USERS.delete('user:' + email);
      break;
    case 'promote':
      target.role = 'admin';
      target.approved = true;
      await putUser(env, target);
      break;
    case 'demote':
      target.role = 'member';
      await putUser(env, target);
      break;
    case 'delete':
      await env.USERS.delete('user:' + email);
      break;
    default:
      return json({ error: 'Aksi tidak dikenal' }, { status: 400 });
  }

  return json({ ok: true });
}
