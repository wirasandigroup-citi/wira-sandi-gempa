# Wira Sandi — Gempa Bumi Monitoring Dashboard (Cloudflare Pages + Login)

Sistem login (register/approve/admin) sudah terintegrasi penuh menggunakan
**Cloudflare Pages Functions** + **Workers KV**, menggantikan versi Supabase
sebelumnya.

## Struktur folder
```
index.html          → Dashboard utama (butuh login)
login.html           → Halaman login (publik)
register.html        → Halaman daftar peserta (publik)
pending.html          → Halaman "menunggu persetujuan admin"
admin.html            → Panel kelola peserta (khusus admin)
functions/
  _middleware.js      → Auth gate: cek sesi di setiap request
  _lib/auth.js         → Helper hashing password, sesi, KV
  api/login.js          → POST login
  api/register.js       → POST daftar akun baru
  api/logout.js          → POST logout
  api/me.js               → GET info user yang sedang login
  api/admin/users.js       → GET daftar semua peserta (admin only)
  api/admin/manage.js       → POST approve/reject/promote/demote/delete (admin only)
```

## Cara deploy ke Cloudflare Pages

1. **Push folder ini ke GitHub** (repo baru di `wirasandigroup-citi`, atau upload manual).
2. Di dashboard Cloudflare → **Workers & Pages** → **Create application** → **Pages** →
   **Connect to Git**, pilih repo tersebut.
3. Build settings:
   - Framework preset: **None**
   - Build command: *(kosongkan)*
   - Build output directory: `/` (root)
4. Setelah project dibuat, buka **Settings → Functions → KV namespace bindings**.
   Tambahkan binding:
   - **Variable name:** `USERS`
   - **KV namespace:** `GEMPA_USERS` (sudah dibuat otomatis di akun Cloudflare Anda,
     ID: `663409c086c54e33a6ff3b480acaf0dc`)
5. **Redeploy** (Settings → Deployments → klik ⋯ pada deployment terakhir → Retry deployment)
   supaya binding KV terpasang di deployment yang aktif.

## Pertama kali pakai

1. Buka `https://<project-anda>.pages.dev/register.html`
2. Daftar dengan email & password Anda — **akun pertama otomatis jadi Admin**
   dan langsung bisa login (tidak perlu approval).
3. Login di `/login.html` → Anda akan melihat tombol **"Kelola Peserta"** di
   topbar dashboard (khusus admin).
4. Peserta lain yang mendaftar setelah Anda akan berstatus **"Menunggu"** sampai
   Anda approve lewat panel **Kelola Peserta** (`/admin.html`).

## Keamanan

- Password di-hash dengan PBKDF2 (100.000 iterasi, SHA-256) + salt acak — tidak pernah disimpan plain text.
- Sesi login disimpan sebagai token acak di KV dengan masa berlaku 7 hari, dikirim lewat cookie `HttpOnly; Secure; SameSite=Lax`.
- Semua halaman (kecuali `/login.html`, `/register.html`) diproteksi oleh `functions/_middleware.js` — otomatis redirect ke halaman login jika belum masuk, atau ke `/pending.html` jika akun belum disetujui admin.
- Panel `/admin.html` dan endpoint `/api/admin/*` hanya bisa diakses oleh role `admin`.

## Catatan

- Untuk menambah admin baru: approve dulu akunnya sebagai user biasa, lalu klik **"Jadikan Admin"** di panel Kelola Peserta.
- Untuk mencabut akses seseorang: klik **"Hapus"** di panel Kelola Peserta — akun & sesinya langsung dicabut.
