-- =============================================================================
-- DinDin + Plaid schema
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query).
-- =============================================================================

-- Each Plaid "Item" represents one bank connection (e.g. Chase).
-- A user can have multiple items (Chase + Bank of America, etc.).
create table if not exists public.plaid_items (
  item_id          text primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  access_token     text not null,
  institution_id   text,
  institution_name text,
  cursor           text,
  last_sync        timestamptz,
  created_at       timestamptz not null default now()
);

create index if not exists idx_plaid_items_user on public.plaid_items (user_id);

-- Plaid accounts under each item (checking, savings, credit card, etc.).
create table if not exists public.plaid_accounts (
  account_id       text primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  item_id          text not null references public.plaid_items(item_id) on delete cascade,
  name             text,
  official_name    text,
  type             text,
  subtype          text,
  mask             text,
  current_balance  numeric,
  updated_at       timestamptz not null default now()
);

create index if not exists idx_plaid_accounts_user on public.plaid_accounts (user_id);
create index if not exists idx_plaid_accounts_item_id on public.plaid_accounts (item_id);

-- Actual transactions synced from Plaid.
create table if not exists public.plaid_transactions (
  transaction_id   text primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  account_id       text not null references public.plaid_accounts(account_id) on delete cascade,
  amount           numeric not null,
  date             date not null,
  name             text,
  pending          boolean default false,
  category         text,
  created_at       timestamptz not null default now()
);

create index if not exists idx_plaid_transactions_account_id on public.plaid_transactions (account_id);

-- Row-Level Security: users only see their own data
-- Using (select auth.uid()) wrapper for initplan optimization.
alter table public.plaid_items         enable row level security;
alter table public.plaid_accounts      enable row level security;
alter table public.plaid_transactions  enable row level security;

drop policy if exists "plaid_items_own"         on public.plaid_items;
drop policy if exists "plaid_accounts_own"      on public.plaid_accounts;
drop policy if exists "plaid_transactions_own"  on public.plaid_transactions;

create policy "plaid_items_own"
  on public.plaid_items for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "plaid_accounts_own"
  on public.plaid_accounts for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "plaid_transactions_own"
  on public.plaid_transactions for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
