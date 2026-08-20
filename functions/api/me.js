import { json } from '../_lib/auth.js';

export async function onRequestGet({ data }) {
  const u = data.user;
  if (!u) return json({ user: null });
  return json({ user: { email: u.email, name: u.name, role: u.role, approved: u.approved } });
}
