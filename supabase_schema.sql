-- ============================================================
-- Threadlytics — Supabase Schema
-- Run this in: Supabase Dashboard → SQL Editor → New query
-- ============================================================

-- Enable UUID generation
create extension if not exists "uuid-ossp";

-- ── Users (extends Supabase auth.users) ─────────────────────
create table public.profiles (
  id          uuid references auth.users(id) on delete cascade primary key,
  email       text not null,
  full_name   text,
  plan        text not null default 'trial',   -- trial | starter | growth | studio
  trial_ends  timestamptz default (now() + interval '14 days'),
  stripe_customer_id    text,
  stripe_subscription_id text,
  ai_messages_used      int not null default 0,
  ai_messages_reset     timestamptz default date_trunc('month', now()),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Row-level security: users can only see their own profile
alter table public.profiles enable row level security;
create policy "Users can view own profile"
  on public.profiles for select using (auth.uid() = id);
create policy "Users can update own profile"
  on public.profiles for update using (auth.uid() = id);

-- Auto-create profile on signup
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1))
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ── Uploads ──────────────────────────────────────────────────
create table public.uploads (
  id            uuid primary key default uuid_generate_v4(),
  user_id       uuid references public.profiles(id) on delete cascade not null,
  filename      text not null,
  sku_count     int,
  analysis      jsonb,           -- full analysis JSON blob
  created_at    timestamptz not null default now()
);

alter table public.uploads enable row level security;
create policy "Users can manage own uploads"
  on public.uploads for all using (auth.uid() = user_id);

create index idx_uploads_user_id on public.uploads(user_id);
create index idx_uploads_created_at on public.uploads(created_at desc);

-- ── Chat history ─────────────────────────────────────────────
create table public.chat_messages (
  id          uuid primary key default uuid_generate_v4(),
  user_id     uuid references public.profiles(id) on delete cascade not null,
  upload_id   uuid references public.uploads(id) on delete cascade,
  role        text not null check (role in ('user','assistant')),
  content     text not null,
  created_at  timestamptz not null default now()
);

alter table public.chat_messages enable row level security;
create policy "Users can manage own chat"
  on public.chat_messages for all using (auth.uid() = user_id);

create index idx_chat_user_upload on public.chat_messages(user_id, upload_id);

-- ── Stripe webhook events (idempotency) ──────────────────────
create table public.stripe_events (
  id          text primary key,   -- Stripe event ID
  type        text not null,
  processed   boolean default false,
  created_at  timestamptz not null default now()
);

-- ── Helper: reset monthly AI message count ───────────────────
create or replace function public.reset_monthly_messages()
returns void language plpgsql as $$
begin
  update public.profiles
  set ai_messages_used = 0,
      ai_messages_reset = date_trunc('month', now())
  where ai_messages_reset < date_trunc('month', now());
end;
$$;

-- ── Explicit grants (required for new Supabase key format) ──
grant usage on schema public to anon, authenticated, service_role;
grant all on all tables in schema public to service_role;
grant all on all sequences in schema public to service_role;
grant select, insert, update, delete on public.profiles to authenticated;
grant select, insert, update, delete on public.uploads to authenticated;
grant select, insert, update, delete on public.chat_messages to authenticated;
grant select, insert, update on public.stripe_events to service_role;

-- ── Plan limits view ─────────────────────────────────────────
create or replace view public.plan_limits as
select
  p.id,
  p.plan,
  p.ai_messages_used,
  case p.plan
    when 'starter' then 50
    when 'growth'  then 999999
    when 'studio'  then 999999
    when 'trial'   then 20
    else 5
  end as ai_messages_limit,
  case p.plan
    when 'starter' then 200
    when 'growth'  then 999999
    when 'studio'  then 999999
    when 'trial'   then 50
    else 10
  end as sku_limit,
  p.trial_ends,
  (p.plan = 'trial' and p.trial_ends < now()) as trial_expired
from public.profiles p;
