// Supabase Edge Function: plaid-sync-transactions
// Pulls recent transactions from all of the user's linked Plaid items
// and stores them in plaid_transactions. Uses /transactions/sync for
// efficient incremental updates via cursor.
// Deploy: supabase functions deploy plaid-sync-transactions

import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.0';
import { corsHeaders } from '../_shared/cors.ts';

interface PlaidTx {
  transaction_id: string;
  account_id: string;
  amount: number;
  date: string;
  name: string;
  merchant_name?: string;
  pending: boolean;
  category?: string[];
  personal_finance_category?: { primary: string; detailed: string };
}

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

    const admin = createClient(supabaseUrl, supabaseService);
    const PLAID_ENV = Deno.env.get('PLAID_ENV') ?? 'sandbox';
    const PLAID_CLIENT_ID = Deno.env.get('PLAID_CLIENT_ID')!;
    const PLAID_SECRET = Deno.env.get('PLAID_SECRET')!;
    const baseUrl = PLAID_ENV === 'production'
      ? 'https://production.plaid.com'
      : PLAID_ENV === 'development'
      ? 'https://development.plaid.com'
      : 'https://sandbox.plaid.com';

    // Get all this user's items
    const { data: items, error: itemsErr } = await admin
      .from('plaid_items')
      .select('item_id, access_token, cursor')
      .eq('user_id', user.id);
    if (itemsErr) return json({ error: itemsErr.message }, 500);
    if (!items || items.length === 0) return json({ success: true, added: 0, items: 0 });

    let totalAdded = 0;
    for (const item of items) {
      let cursor: string | null = item.cursor || null;
      let hasMore = true;
      while (hasMore) {
        const res = await fetch(`${baseUrl}/transactions/sync`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_id: PLAID_CLIENT_ID,
            secret: PLAID_SECRET,
            access_token: item.access_token,
            ...(cursor ? { cursor } : {}),
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          console.error('Sync error', data);
          break;
        }

        const added: PlaidTx[] = data.added || [];
        const modified: PlaidTx[] = data.modified || [];
        const removed: { transaction_id: string }[] = data.removed || [];

        if (added.length > 0 || modified.length > 0) {
          const rows = [...added, ...modified].map((t) => ({
            user_id: user.id,
            transaction_id: t.transaction_id,
            account_id: t.account_id,
            amount: -t.amount, // Plaid uses positive = outflow; we use negative = outflow
            date: t.date,
            name: t.merchant_name || t.name,
            pending: t.pending,
            category: t.personal_finance_category?.primary || t.category?.[0] || null,
          }));
          await admin.from('plaid_transactions').upsert(rows, { onConflict: 'transaction_id' });
          totalAdded += added.length;
        }

        if (removed.length > 0) {
          await admin
            .from('plaid_transactions')
            .delete()
            .in('transaction_id', removed.map((r) => r.transaction_id));
        }

        cursor = data.next_cursor;
        hasMore = data.has_more;
      }

      // Persist latest cursor
      await admin.from('plaid_items').update({ cursor, last_sync: new Date().toISOString() }).eq('item_id', item.item_id);
    }

    return json({ success: true, added: totalAdded, items: items.length });
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
