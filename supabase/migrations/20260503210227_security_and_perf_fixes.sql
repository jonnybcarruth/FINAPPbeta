-- =============================================================================
-- Migration: security_and_perf_fixes
-- Addresses Supabase advisor findings for project uwvowomjtnchqebhqaop
-- =============================================================================

-- ─────────────────────────────────────────────────────────────────────────────
-- 1a. function_search_path_mutable
-- Lock down search_path on touch_user_data_updated_at to prevent
-- search-path-injection attacks against trigger functions.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER FUNCTION public.touch_user_data_updated_at() SET search_path = pg_catalog, public;

-- ─────────────────────────────────────────────────────────────────────────────
-- 1b. anon_security_definer_function_executable /
--     authenticated_security_definer_function_executable
-- delete_user() MUST stay SECURITY DEFINER (Apple App Store account-deletion
-- requirement). Revoke from anon and PUBLIC; only authenticated users may call.
-- Also fix search_path from 'public' to empty (pg_catalog fallback).
-- The function uses auth.uid() internally — no user_id parameter — so an
-- authenticated user can only delete their own account.
-- NOTE: authenticated_security_definer_function_executable will still fire
--       after this fix. That is intentional (lint:ignore=0029).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION public.delete_user()
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
  uid uuid := auth.uid();
BEGIN
  IF uid IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;
  DELETE FROM auth.users WHERE id = uid;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.delete_user() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.delete_user() TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- 1c. auth_rls_initplan
-- Replace auth.uid() with (select auth.uid()) inside every RLS policy.
-- The select wrapper makes Postgres evaluate the function once per query
-- instead of once per row.
-- ─────────────────────────────────────────────────────────────────────────────

-- user_data policies
DROP POLICY IF EXISTS user_data_select_own ON public.user_data;
CREATE POLICY user_data_select_own ON public.user_data
  FOR SELECT TO authenticated
  USING ((select auth.uid()) = user_id);

DROP POLICY IF EXISTS user_data_insert_own ON public.user_data;
CREATE POLICY user_data_insert_own ON public.user_data
  FOR INSERT TO authenticated
  WITH CHECK ((select auth.uid()) = user_id);

DROP POLICY IF EXISTS user_data_update_own ON public.user_data;
CREATE POLICY user_data_update_own ON public.user_data
  FOR UPDATE TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

DROP POLICY IF EXISTS user_data_delete_own ON public.user_data;
CREATE POLICY user_data_delete_own ON public.user_data
  FOR DELETE TO authenticated
  USING ((select auth.uid()) = user_id);

-- plaid_items policies
DROP POLICY IF EXISTS plaid_items_own ON public.plaid_items;
CREATE POLICY plaid_items_own ON public.plaid_items
  FOR ALL TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

-- plaid_accounts policies (has direct user_id column)
DROP POLICY IF EXISTS plaid_accounts_own ON public.plaid_accounts;
CREATE POLICY plaid_accounts_own ON public.plaid_accounts
  FOR ALL TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

-- plaid_transactions policies (has direct user_id column)
DROP POLICY IF EXISTS plaid_transactions_own ON public.plaid_transactions;
CREATE POLICY plaid_transactions_own ON public.plaid_transactions
  FOR ALL TO authenticated
  USING ((select auth.uid()) = user_id)
  WITH CHECK ((select auth.uid()) = user_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 1d. unindexed_foreign_keys
-- Add missing FK indexes for join performance.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_plaid_accounts_item_id
  ON public.plaid_accounts(item_id);

CREATE INDEX IF NOT EXISTS idx_plaid_transactions_account_id
  ON public.plaid_transactions(account_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- 1e. unused_index
-- idx_plaid_tx_user_date has never been used. No query in src/ or
-- supabase/functions/ filters plaid_transactions by (user_id, date).
-- ─────────────────────────────────────────────────────────────────────────────

DROP INDEX IF EXISTS public.idx_plaid_tx_user_date;
