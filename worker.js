import {
  hashPassword, verifyPassword, normalizeEmail, getUser, putUser, listUsers,
  createSession, destroySession, getSessionUser, getCookie, sessionCookie,
  clearSessionCookie, json
} from './functions/_lib/auth.js';

function unauthorized() { return json({ error: 'Belum login' }, { status: 401 }); }
function forbidden(message = 'Khusus admin') { return json({ error: message }, { status: 403 }); }

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      if (path === '/api/register' && method === 'POST') {
        const body = await request.json();
        const email = normalizeEmail(body.email);
        const name = String(body.name || '').trim();
        const password = String(body.password || '');
        if (!email || !email.includes('@')) return json({ error: 'Email tidak valid' }, { status: 400 });
        if (!name) return json({ error: 'Nama wajib diisi' }, { status: 400 });
        if (password.length < 8) return json({ error: 'Password minimal 8 karakter' }, { status: 400 });
        if (await getUser(env, email)) return json({ error: 'Email sudah terdaftar' }, { status: 409 });
        const isFirstUser = (await listUsers(env)).length === 0;
        const { hash, salt } = await hashPassword(password);
        await putUser(env, { email, name, passwordHash: hash, salt, role: isFirstUser ? 'admin' : 'member', approved: isFirstUser, createdAt: new Date().toISOString() });
        return json({ ok: true, isFirstUser, message: isFirstUser ? 'Akun admin berhasil dibuat. Silakan login.' : 'Pendaftaran berhasil. Menunggu persetujuan admin sebelum bisa login.' });
      }

      if (path === '/api/login' && method === 'POST') {
        const body = await request.json();
        const email = normalizeEmail(body.email);
        const password = String(body.password || '');
        const user = await getUser(env, email);
        if (!user || !(await verifyPassword(password, user.salt, user.passwordHash))) return json({ error: 'Email atau password salah' }, { status: 401 });
        if (!user.approved) return json({ error: 'Akun Anda menunggu persetujuan admin' }, { status: 403 });
        const token = await createSession(env, email);
        return json({ ok: true, role: user.role }, { headers: { 'Set-Cookie': sessionCookie(token) } });
      }

      if (path === '/api/logout' && method === 'POST') {
        await destroySession(env, getCookie(request, 'session'));
        return json({ ok: true }, { headers: { 'Set-Cookie': clearSessionCookie() } });
      }

      const user = await getSessionUser(request, env);
      if (path === '/api/me' && method === 'GET') {
        return json({ user: user ? { email: user.email, name: user.name, role: user.role, approved: user.approved } : null });
      }

      if (path === '/api/admin/users' && method === 'GET') {
        if (!user) return unauthorized();
        if (user.role !== 'admin') return forbidden();
        const users = (await listUsers(env)).map(u => ({ email: u.email, name: u.name, role: u.role, approved: u.approved, createdAt: u.createdAt }));
        return json({ users });
      }

      if (path === '/api/admin/manage' && method === 'POST') {
        if (!user) return unauthorized();
        if (user.role !== 'admin') return forbidden();
        const body = await request.json();
        const email = normalizeEmail(body.email);
        const action = body.action;
        if (!email || !action) return json({ error: 'Parameter kurang' }, { status: 400 });
        const target = await getUser(env, email);
        if (!target) return json({ error: 'User tidak ditemukan' }, { status: 404 });
        if (target.email === user.email && (action === 'delete' || action === 'demote')) return json({ error: 'Tidak bisa menghapus/menurunkan role akun sendiri' }, { status: 400 });
        if (action === 'approve') { target.approved = true; await putUser(env, target); }
        else if (action === 'reject' || action === 'delete') await env.USERS.delete('user:' + email);
        else if (action === 'promote') { target.role = 'admin'; target.approved = true; await putUser(env, target); }
        else if (action === 'demote') { target.role = 'member'; await putUser(env, target); }
        else return json({ error: 'Aksi tidak dikenal' }, { status: 400 });
        return json({ ok: true });
      }

      if (path.startsWith('/api/')) return json({ error: 'Endpoint tidak ditemukan' }, { status: 404 });

      const response = await env.ASSETS.fetch(request);
      if ((path === '/' || path === '/index.html') && response.headers.get('content-type')?.includes('text/html')) {
        return new HTMLRewriter()
          .on('title', { element(element) { element.setInnerContent('WIRA SANDI - Gempa Monitoring'); } })
          .on('head', { element(element) {
            element.append('<meta name="description" content="WIRA SANDI - Gempa Monitoring">', { html: true });
            element.append('<meta property="og:title" content="WIRA SANDI - Gempa Monitoring">', { html: true });
            element.append('<meta property="og:description" content="WIRA SANDI - Gempa Monitoring">', { html: true });
          }})
          .transform(response);
      }
      return response;
    } catch (err) {
      return json({ error: 'Server error', detail: String(err?.message || err) }, { status: 500 });
    }
  }
};
