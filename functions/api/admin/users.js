import { listUsers, json } from '../../_lib/auth.js';

export async function onRequestGet({ env }) {
  const users = await listUsers(env);
  const safe = users.map(u => ({
    email: u.email, name: u.name, role: u.role, approved: u.approved, createdAt: u.createdAt
  }));
  return json({ users: safe });
}
