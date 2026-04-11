-- =============================================================================
-- DinDin Supabase schema
-- Run this once in the Supabase SQL editor (Dashboard → SQL Editor → New Query).
-- =============================================================================

-- One row per authenticated user. The `data` JSONB holds the entire finance
-- snapshot (schedules, transactions, debts, settings). Simple now; can be
-- normalized into per-entity tables later (e.g. when Plaid transactions land).
create table if not exists public.user_data (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- Row-Level Security: users can ONLY read/write their own row. This is the
-- single most important line in this file — without it, any logged-in user
-- could read any other user's financial data.
alter table public.user_data enable row level security;

drop policy if exists "user_data_select_own" on public.user_data;
drop policy if exists "user_data_insert_own" on public.user_data;
drop policy if exists "user_data_update_own" on public.user_data;
drop policy if exists "user_data_delete_own" on public.user_data;

create policy "user_data_select_own"
  on public.user_data for select
  using (auth.uid() = user_id);

create policy "user_data_insert_own"
  on public.user_data for insert
  with check (auth.uid() = user_id);

create policy "user_data_update_own"
  on public.user_data for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "user_data_delete_own"
  on public.user_data for delete
  using (auth.uid() = user_id);

-- Bump updated_at on every update for easy freshness checks / conflict UI later.
create or replace function public.touch_user_data_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists user_data_touch_updated_at on public.user_data;
create trigger user_data_touch_updated_at
  before update on public.user_data
  for each row execute function public.touch_user_data_updated_at();

-- -----------------------------------------------------------------------------
-- In-app account deletion (Apple App Store requirement)
-- Deletes the currently authenticated user from auth.users. The ON DELETE
-- CASCADE on user_data.user_id then wipes their data row automatically.
-- SECURITY DEFINER lets it modify auth.users with elevated privileges; we
-- hard-code the check to auth.uid() so a user can only delete themselves.
-- -----------------------------------------------------------------------------
create or replace function public.delete_user()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;
  delete from auth.users where id = auth.uid();
end;
$$;

revoke all on function public.delete_user() from public;
grant execute on function public.delete_user() to authenticated;
