-- ============================================================================
-- 01_audit_rls.sql  --  AUDIT RLS (HANYA BACA, aman dijalankan di produksi)
--
-- Jalankan di Supabase Dashboard > SQL Editor, satu blok per kali, lalu
-- simpan/screenshot hasilnya SEBELUM menjalankan 02_harden_rls.sql
-- (skrip pengetatan akan menghapus policy lama, jadi hasil audit ini adalah
-- satu-satunya catatan policy aslinya).
-- ============================================================================

-- [A] Apakah RLS aktif? Kedua tabel HARUS rls_enabled = true.
select c.relname as tabel, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relname in ('user_data', 'allowed_users');

-- [B] Semua policy yang ada. Waspada pada:
--     * roles berisi {public} atau {anon}  -> bisa diakses tanpa login
--     * qual / with_check = 'true'         -> terbuka untuk semua baris
--     Policy PERMISSIVE digabung dengan OR, jadi SATU policy longgar
--     membatalkan semua policy ketat lainnya.
select tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public' and tablename in ('user_data', 'allowed_users')
order by tablename, cmd, policyname;

-- [C] Hak akses tabel untuk role anon / authenticated.
--     anon TIDAK perlu hak apa pun pada kedua tabel ini.
select table_name, grantee, string_agg(privilege_type, ', ' order by privilege_type) as hak
from information_schema.role_table_grants
where table_schema = 'public' and table_name in ('user_data', 'allowed_users')
  and grantee in ('anon', 'authenticated', 'public')
group by table_name, grantee
order by table_name, grantee;

-- [D] Tipe kolom (user_id harus uuid agar cocok dengan auth.uid()).
select table_name, column_name, data_type
from information_schema.columns
where table_schema = 'public' and table_name in ('user_data', 'allowed_users')
order by table_name, ordinal_position;

-- [E] Baris user_data ganda untuk satu user (race select-lalu-insert di aplikasi).
--     Harus kosong sebelum constraint UNIQUE bisa dipasang.
select user_id, count(*) as jumlah_baris
from public.user_data
group by user_id having count(*) > 1;

-- [F] Ukuran data: jumlah pembeli & user_data (TIDAK menampilkan email).
select (select count(*) from public.allowed_users) as jumlah_pembeli,
       (select count(*) from public.user_data)     as jumlah_baris_user_data;

-- [G] Siapa yang menulis ke allowed_users? Bila otomasi pembelian (webhook
--     Lynk/n8n/dll.) memakai ANON key, pengetatan akan memutusnya. Otomasi
--     harus memakai service_role key di server (jangan pernah di frontend).
--     Cek di mesin otomasi Anda sebelum menjalankan 02_harden_rls.sql.
