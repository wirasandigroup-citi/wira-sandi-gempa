import { getSessionUser } from './_lib/auth.js';

// Path yang boleh diakses TANPA login
const PUBLIC_PATHS = new Set([
  '/login.html', '/register.html', '/pending.html',
  '/api/login', '/api/register'
]);

// Path yang hanya boleh diakses ADMIN
function isAdminPath(pathname) {
  return pathname === '/admin.html' || pathname.startsWith('/api/admin/');
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // Aset statis (favicon, gambar, dll) & path publik → lewati
  if (PUBLIC_PATHS.has(path) || path.startsWith('/assets/')) {
    return next();
  }

  const user = await getSessionUser(request, env);

  if (!user) {
    if (path.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Belum login' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
    return Response.redirect(`${url.origin}/login.html?redirect=${encodeURIComponent(path)}`, 302);
  }

  if (!user.approved) {
    if (path.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Akun menunggu persetujuan admin' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    if (path !== '/pending.html') return Response.redirect(`${url.origin}/pending.html`, 302);
  }

  if (isAdminPath(path) && user.role !== 'admin') {
    if (path.startsWith('/api/')) {
      return new Response(JSON.stringify({ error: 'Khusus admin' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
    }
    return Response.redirect(`${url.origin}/`, 302);
  }

  context.data = context.data || {};
  context.data.user = user;
  return next();
}
