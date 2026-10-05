-- ============================================================================
-- 03_free_access_phase_b.sql  --  RLS untuk aplikasi GRATIS, FASE B
--
-- JALANKAN HANYA SETELAH aplikasi baru (branch feat/free-access) sudah
-- di-deploy ke produksi dan Anda memastikan halaman live memakai versi baru.
-- Aplikasi lama masih memanggil allowed_users; jika fase B dijalankan lebih
-- awal, semua pengguna aplikasi lama akan melihat "Akses Ditolak".
--
-- Efek: tabel allowed_users tertutup total untuk anon dan user login. Hanya
-- service_role / dashboard Supabase yang bisa membaca atau mengubahnya.
-- Tabel dan isinya TIDAK dihapus (arsip data pembeli lama); jika sudah tidak
-- diperlukan Anda dapat menghapusnya sendiri:  drop table public.allowed_users;
-- ============================================================================

begin;

drop policy if exists allowed_users_select_own on public.allowed_users;
revoke all on public.allowed_users from anon, authenticated;
alter table public.allowed_users enable row level security;  -- tanpa policy = tertutup

commit;
