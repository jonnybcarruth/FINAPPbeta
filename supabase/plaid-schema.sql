-- =============================================================================
-- DinDin + Plaid schema
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query).
-- =============================================================================

-- Each Plaid "Item" represents one bank connection (e.g. Chase).
-- A user can have multiple items (Chase + Bank of America, etc.).
create table if not exists public.plaid_items (
  item_id          text primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  access_token     text not null,        -- Plaid's long-lived access token (stored encrypted at rest by Supabase)
  institution_id   text,
  institution_name text,
  cursor           text,                 -- For /transactions/sync incremental pull
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
  type             text,                 -- depository, credit, loan, investment
  subtype          text,                 -- checking, savings, credit card, etc.
  mask             text,                 -- last 4 of account number
  current_balance  numeric,
  updated_at       timestamptz not null default now()
);

create index if not exists idx_plaid_accounts_user on public.plaid_accounts (user_id);

-- Actual transactions synced from Plaid.
create table if not exists public.plaid_transactions (
  transaction_id   text primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  account_id       text not null references public.plaid_accounts(account_id) on delete cascade,
  amount           numeric not null,     -- negative = outflow, positive = inflow (our convention)
  date             date not null,
  name             text,
  pending          boolean default false,
  category         text,
  created_at       timestamptz not null default now()
);

create index if not exists idx_plaid_tx_user_date on public.plaid_transactions (user_id, date desc);

-- Row-Level Security: users only see their own data
alter table public.plaid_items         enable row level security;
alter table public.plaid_accounts      enable row level security;
alter table public.plaid_transactions  enable row level security;

drop policy if exists "plaid_items_own"         on public.plaid_items;
drop policy if exists "plaid_accounts_own"      on public.plaid_accounts;
drop policy if exists "plaid_transactions_own"  on public.plaid_transactions;

create policy "plaid_items_own"
  on public.plaid_items for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

create policy "plaid_accounts_own"
  on public.plaid_accounts for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

create policy "plaid_transactions_own"
  on public.plaid_transactions for all
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Cascading delete when user deletes their account: the auth.users cascade
-- already deletes plaid_items, plaid_accounts, plaid_transactions via ON DELETE CASCADE.
