import { hashPassword, getUser, putUser, normalizeEmail, listUsers, json } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: 'Data tidak valid' }, { status: 400 }); }

  const email = normalizeEmail(body.email);
  const name = String(body.name || '').trim();
  const password = String(body.password || '');

  if (!email || !email.includes('@')) return json({ error: 'Email tidak valid' }, { status: 400 });
  if (!name) return json({ error: 'Nama wajib diisi' }, { status: 400 });
  if (password.length < 8) return json({ error: 'Password minimal 8 karakter' }, { status: 400 });

  const existing = await getUser(env, email);
  if (existing) return json({ error: 'Email sudah terdaftar' }, { status: 409 });

  // Bootstrap: akun PERTAMA yang mendaftar otomatis jadi admin & langsung disetujui.
  const allUsers = await listUsers(env);
  const isFirstUser = allUsers.length === 0;

  const { hash, salt } = await hashPassword(password);
  const user = {
    email, name,
    passwordHash: hash, salt,
    role: isFirstUser ? 'admin' : 'member',
    approved: isFirstUser,
    createdAt: new Date().toISOString()
  };
  await putUser(env, user);

  return json({
    ok: true,
    isFirstUser,
    message: isFirstUser
      ? 'Akun admin berhasil dibuat. Silakan login.'
      : 'Pendaftaran berhasil. Menunggu persetujuan admin sebelum bisa login.'
  });
}
