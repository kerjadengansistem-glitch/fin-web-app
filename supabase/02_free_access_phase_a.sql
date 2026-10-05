-- ============================================================================
-- 02_free_access_phase_a.sql  --  RLS untuk aplikasi GRATIS, FASE A
--
-- Aman dijalankan SEKARANG: kompatibel dengan aplikasi lama (yang masih
-- mengecek allowed_users) maupun aplikasi baru (feat/free-access).
--
-- Model akses (aplikasi gratis untuk semua orang):
--   * Siapa pun yang login Google boleh memakai aplikasi.
--   * Setiap user hanya bisa membaca/menulis BARIS user_data miliknya sendiri
--     (user_id = auth.uid()). Tidak ada lagi syarat "pembeli terdaftar".
--   * User yang belum login (role anon) tidak punya akses ke tabel mana pun.
--
-- Yang diperbaiki dibanding kondisi sekarang:
--   1. allowed_users TIDAK lagi bisa dibaca publik. Policy lama
--      "Enable read access for all users" membuka seluruh email pembeli
--      kepada siapa pun yang punya anon key. Sementara aplikasi lama masih
--      live, user login hanya melihat BARIS emailnya sendiri (itu cukup bagi
--      aplikasi lama). Fase B mencabut ini sepenuhnya.
--   2. Hak tabel disempitkan: anon tidak punya hak apa pun; user login hanya
--      select/insert/update pada user_data (tidak ada delete/truncate).
--   3. Batas ukuran data per user, agar satu akun tidak bisa menghabiskan
--      kuota database untuk semua orang (aplikasi terbuka = risiko penyalahgunaan).
--
-- Tidak mengubah/menghapus isi data apa pun. Satu transaksi, idempoten.
-- Jalankan 01_audit_rls.sql lebih dulu dan simpan hasilnya (catatan policy lama).
-- ============================================================================

begin;

-- 1. Hapus semua policy lama pada kedua tabel (dicatat sebagai NOTICE).
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

-- 2. RLS aktif; anon tidak punya hak apa pun di schema public.
alter table public.user_data     enable row level security;
alter table public.allowed_users enable row level security;

revoke all on all tables in schema public from anon;

-- 3. Hak user login: hanya yang dibutuhkan aplikasi.
revoke all on public.user_data     from authenticated;
revoke all on public.allowed_users from authenticated;
grant select, insert, update on public.user_data     to authenticated;
grant select                 on public.allowed_users to authenticated;

-- 4. allowed_users (sementara, untuk aplikasi lama): hanya baris email sendiri.
create policy allowed_users_select_own
  on public.allowed_users
  for select
  to authenticated
  using (lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));

-- 5. user_data: data milik sendiri saja.
create policy user_data_select_own
  on public.user_data
  for select
  to authenticated
  using (user_id = auth.uid());

create policy user_data_insert_own
  on public.user_data
  for insert
  to authenticated
  with check (user_id = auth.uid());

create policy user_data_update_own
  on public.user_data
  for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- 6. Batas ukuran data per user (teks JSON): transactions 5 MB, lainnya 1 MB.
--    Sekitar 30 ribu transaksi per user; jauh di atas pemakaian wajar.
alter table public.user_data drop constraint if exists user_data_size_cap;
alter table public.user_data add constraint user_data_size_cap check (
  octet_length(transactions::text) <= 5000000 and
  octet_length(goals::text)        <= 1000000 and
  octet_length(plans::text)        <= 1000000 and
  octet_length(wallets::text)      <= 1000000 and
  octet_length(category_map::text) <= 1000000
);

-- 7. Satu baris per user. Sudah ada di produksi (user_data_user_id_key);
--    hanya dicek, dan dipasang bila belum ada serta tidak ada duplikat.
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

-- ROLLBACK DARURAT bila pengguna terkunci:
--   create policy user_data_select_own on public.user_data for select to authenticated using (user_id = auth.uid());
--   (policy lama yang dihapus tercatat di NOTICE keluaran skrip ini dan di hasil 01_audit_rls.sql)
