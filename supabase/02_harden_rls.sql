-- ============================================================================
-- 02_harden_rls.sql  --  PENGETATAN RLS untuk fin-web-app
--
-- JANGAN jalankan sebelum:
--   1. 01_audit_rls.sql dijalankan dan hasilnya disimpan,
--   2. query [E] di 01 kosong (tidak ada user_data ganda),
--   3. otomasi yang mengisi allowed_users (mis. webhook pembelian) memakai
--      service_role key, bukan anon key (service_role mem-bypass RLS).
--
-- Satu transaksi: jika ada langkah gagal, semuanya dibatalkan.
-- Hasil yang dijamin:
--   * Role anon (belum login) tidak bisa membaca/menulis kedua tabel.
--   * User login hanya bisa membaca BARIS allowed_users miliknya sendiri
--     (daftar email semua pembeli tidak bisa diambil).
--   * user_data hanya bisa dibaca/ditulis oleh pemiliknya DAN hanya bila
--     emailnya ada di allowed_users (gerbang akses ditegakkan di database,
--     bukan hanya di JavaScript browser).
--
-- Asumsi skema: public.user_data(id, user_id uuid, transactions, goals, plans,
-- wallets, category_map ...) dan public.allowed_users(email text).
-- ============================================================================

begin;

-- 1. Hapus SEMUA policy lama pada kedua tabel (policy permissive digabung OR,
--    jadi satu policy longgar yang terlewat membatalkan semuanya).
--    Definisi yang dihapus dicatat sebagai NOTICE; samakan dengan hasil 01 [B].
do $$
declare p record;
begin
  for p in
    select schemaname, tablename, policyname, cmd, roles::text as roles, qual, with_check
    from pg_policies
    where schemaname = 'public' and tablename in ('user_data', 'allowed_users')
  loop
    raise notice 'DROP POLICY % ON %.% (cmd=%, roles=%, using=%, check=%)',
      p.policyname, p.schemaname, p.tablename, p.cmd, p.roles, p.qual, p.with_check;
    execute format('drop policy %I on %I.%I', p.policyname, p.schemaname, p.tablename);
  end loop;
end $$;

-- 2. Aktifkan RLS dan cabut akses role anon.
alter table public.user_data     enable row level security;
alter table public.allowed_users enable row level security;

revoke all on public.user_data     from anon;
revoke all on public.allowed_users from anon;

-- authenticated hanya mendapat hak yang dibutuhkan aplikasi.
revoke all on public.user_data     from authenticated;
revoke all on public.allowed_users from authenticated;
grant select, insert, update on public.user_data to authenticated;   -- aplikasi tidak menghapus baris
grant select                 on public.allowed_users to authenticated;

-- 3. Fungsi pembantu: apakah email user yang sedang login ada di allowed_users?
--    SECURITY DEFINER agar tidak terkena RLS allowed_users sendiri (hindari rekursi);
--    search_path dikosongkan agar tidak bisa dibajak.
create or replace function public.is_allowed_user()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.allowed_users a
    where lower(a.email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

revoke all on function public.is_allowed_user() from public, anon;
grant execute on function public.is_allowed_user() to authenticated;

-- 4. Policy allowed_users: user hanya melihat baris emailnya sendiri.
--    Tidak ada policy insert/update/delete -> hanya service_role / dashboard.
create policy allowed_users_select_own
  on public.allowed_users
  for select
  to authenticated
  using (lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));

-- 5. Policy user_data: pemilik + pembeli terdaftar.
create policy user_data_select_own
  on public.user_data
  for select
  to authenticated
  using (user_id = auth.uid() and public.is_allowed_user());

create policy user_data_insert_own
  on public.user_data
  for insert
  to authenticated
  with check (user_id = auth.uid() and public.is_allowed_user());

create policy user_data_update_own
  on public.user_data
  for update
  to authenticated
  using (user_id = auth.uid() and public.is_allowed_user())
  with check (user_id = auth.uid() and public.is_allowed_user());

-- 6. Satu baris per user: mencegah duplikat akibat race select-lalu-insert.
--    * Sudah ada unique pada user_id (constraint ATAU index)  -> tidak dilakukan apa pun.
--    * Belum ada tetapi masih ada user_id ganda               -> dilewati dengan NOTICE;
--      rapikan dulu (lihat 01 [E]) lalu jalankan ulang bagian ini.
do $$
begin
  if exists (
    select 1
    from pg_index i
    join pg_attribute a on a.attrelid = i.indrelid and a.attnum = i.indkey[0]
    where i.indrelid = 'public.user_data'::regclass
      and i.indisunique and i.indnatts = 1 and a.attname = 'user_id'
  ) then
    raise notice 'unique(user_id) pada user_data sudah ada, tidak diubah.';
  elsif exists (select 1 from public.user_data group by user_id having count(*) > 1) then
    raise notice 'LEWATI unique index user_data(user_id): masih ada user_id ganda (lihat 01 [E]).';
  else
    create unique index user_data_user_id_key on public.user_data (user_id);
  end if;
end $$;

commit;

-- ============================================================================
-- VERIFIKASI SESUDAH MENJALANKAN (jalankan manual, ganti UUID/email):
--
--   -- a) tanpa login: harus ditolak (permission denied)
--   set local role anon;  select count(*) from public.allowed_users;  reset role;
--
--   -- b) pembeli terdaftar: hanya melihat 1 baris miliknya
--   begin;
--   set local role authenticated;
--   select set_config('request.jwt.claims',
--     '{"sub":"<UUID-USER>","email":"<email-pembeli>","role":"authenticated"}', true);
--   select count(*) from public.allowed_users;   -- harus 1
--   select count(*) from public.user_data;       -- hanya data user itu
--   rollback;
--
-- ROLLBACK DARURAT (bila pembeli sah terkunci): nonaktifkan sementara
--   alter table public.user_data disable row level security;
-- lalu perbaiki penyebabnya dan aktifkan kembali (enable row level security).
-- ============================================================================
