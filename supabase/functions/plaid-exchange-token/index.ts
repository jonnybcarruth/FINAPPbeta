// Supabase Edge Function: plaid-exchange-token
// Exchanges a public_token (from Plaid Link) for a permanent access_token,
// fetches the linked accounts, and stores everything in plaid_items / plaid_accounts.
// Deploy: supabase functions deploy plaid-exchange-token

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0';
import { corsHeaders } from '../_shared/cors.ts';

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });

  try {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) return json({ error: 'Missing Authorization header' }, 401);

    const supabaseUrl = Deno.env.get('SUPABASE_URL') ?? '';
    const supabaseAnon = Deno.env.get('SUPABASE_ANON_KEY') ?? '';
    const supabaseService = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '';

    const userClient = createClient(supabaseUrl, supabaseAnon, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user } } = await userClient.auth.getUser();
    if (!user) return json({ error: 'Not authenticated' }, 401);

    const { public_token } = await req.json();
    if (!public_token) return json({ error: 'Missing public_token' }, 400);

    const PLAID_ENV = Deno.env.get('PLAID_ENV') ?? 'sandbox';
    const PLAID_CLIENT_ID = Deno.env.get('PLAID_CLIENT_ID')!;
    const PLAID_SECRET = Deno.env.get('PLAID_SECRET')!;
    const baseUrl = PLAID_ENV === 'production'
      ? 'https://production.plaid.com'
      : PLAID_ENV === 'development'
      ? 'https://development.plaid.com'
      : 'https://sandbox.plaid.com';

    // Exchange public_token for access_token
    const exchangeRes = await fetch(`${baseUrl}/item/public_token/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: PLAID_CLIENT_ID,
        secret: PLAID_SECRET,
        public_token,
      }),
    });
    const exchangeData = await exchangeRes.json();
    if (!exchangeRes.ok) return json({ error: 'Exchange failed', detail: exchangeData }, 500);
    const { access_token, item_id } = exchangeData;

    // Fetch accounts
    const accountsRes = await fetch(`${baseUrl}/accounts/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: PLAID_CLIENT_ID, secret: PLAID_SECRET, access_token }),
    });
    const accountsData = await accountsRes.json();
    if (!accountsRes.ok) return json({ error: 'Accounts fetch failed', detail: accountsData }, 500);

    // Fetch institution info
    const itemRes = await fetch(`${baseUrl}/item/get`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: PLAID_CLIENT_ID, secret: PLAID_SECRET, access_token }),
    });
    const itemData = await itemRes.json();
    const institutionId = itemData?.item?.institution_id ?? null;
    let institutionName = 'Unknown';
    if (institutionId) {
      const instRes = await fetch(`${baseUrl}/institutions/get_by_id`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: PLAID_CLIENT_ID,
          secret: PLAID_SECRET,
          institution_id: institutionId,
          country_codes: ['US'],
        }),
      });
      const instData = await instRes.json();
      if (instRes.ok) institutionName = instData?.institution?.name ?? 'Unknown';
    }

    // Store with service role (bypasses RLS)
    const admin = createClient(supabaseUrl, supabaseService);

    await admin.from('plaid_items').upsert({
      user_id: user.id,
      item_id,
      access_token,
      institution_id: institutionId,
      institution_name: institutionName,
    }, { onConflict: 'item_id' });

    const accountsRows = (accountsData.accounts || []).map((a: { account_id: string; name: string; official_name: string | null; type: string; subtype: string | null; mask: string | null; balances: { current: number | null } }) => ({
      user_id: user.id,
      item_id,
      account_id: a.account_id,
      name: a.name,
      official_name: a.official_name,
      type: a.type,
      subtype: a.subtype,
      mask: a.mask,
      current_balance: a.balances?.current ?? null,
    }));
    if (accountsRows.length > 0) {
      await admin.from('plaid_accounts').upsert(accountsRows, { onConflict: 'account_id' });
    }

    return json({
      success: true,
      institution: institutionName,
      accounts: accountsData.accounts,
    });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}
