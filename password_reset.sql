-- ====================================================================
-- Şifre sıfırlama (yönetici üzerinden)
-- Supabase > SQL Editor'de bir kez çalıştır.
--
-- Hesaplarda gerçek e-posta yok (kullanıcı adı -> ad@tahmin.local), bu yüzden
-- e-postayla sıfırlama linki gönderilemez. Akış:
--   1) Giriş ekranında "Şifremi unuttum" -> kullanıcı adını yazar -> istek kaydedilir.
--   2) Yönetim sekmesinde istek görünür -> yönetici yeni geçici şifre verir.
--   3) Kişi o şifreyle girer, Bana Özel > Şifre > Değiştir ile kendi şifresini koyar.
-- ====================================================================

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.cl_pw_requests(
  username   text primary key,
  created_at timestamptz not null default now()
);
-- Politika yok: tabloya sadece aşağıdaki fonksiyonlar dokunur.
alter table public.cl_pw_requests enable row level security;

-- Giriş yapmamış kişi de çağırabilir. Kullanıcı adı yoksa sessizce hiçbir şey yapmaz
-- (hangi kullanıcı adlarının var olduğu dışarı sızmasın).
create or replace function public.request_password_reset(p_username text)
returns void language plpgsql security definer set search_path = public as $$
begin
  p_username := lower(regexp_replace(coalesce(p_username, ''), '\s', '', 'g'));
  if length(p_username) < 2 or length(p_username) > 24 then return; end if;
  if not exists (select 1 from profiles where username = p_username) then return; end if;
  insert into cl_pw_requests(username) values (p_username)
    on conflict (username) do update set created_at = now();
end $$;

-- Bekleyen istekler (sadece yönetici görür)
create or replace function public.pw_requests()
returns table(username text, created_at timestamptz)
language sql security definer set search_path = public as $$
  select r.username, r.created_at from cl_pw_requests r
  where exists (select 1 from profiles where id = auth.uid() and is_admin)
  order by r.created_at desc;
$$;

-- İsteği kapat (şifre vermeden)
create or replace function public.dismiss_pw_request(p_username text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from profiles where id = auth.uid() and is_admin) then
    raise exception 'Yetki yok';
  end if;
  delete from cl_pw_requests where username = p_username;
end $$;

-- Yönetici bir kullanıcıya yeni şifre verir
create or replace function public.admin_set_password(p_user uuid, p_password text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare u text;
begin
  if not exists (select 1 from profiles where id = auth.uid() and is_admin) then
    raise exception 'Yetki yok';
  end if;
  if length(coalesce(p_password, '')) < 6 then
    raise exception 'Şifre en az 6 karakter olmalı';
  end if;
  update auth.users
     set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')),
         updated_at = now()
   where id = p_user;
  if not found then raise exception 'Kullanıcı bulunamadı'; end if;
  select username into u from profiles where id = p_user;
  delete from cl_pw_requests where username = u;
end $$;

revoke execute on function public.request_password_reset(text) from public;
revoke execute on function public.pw_requests()                 from public;
revoke execute on function public.dismiss_pw_request(text)      from public;
revoke execute on function public.admin_set_password(uuid, text) from public;
grant  execute on function public.request_password_reset(text) to anon, authenticated;
grant  execute on function public.pw_requests()                 to authenticated;
grant  execute on function public.dismiss_pw_request(text)      to authenticated;
grant  execute on function public.admin_set_password(uuid, text) to authenticated;
