'use client';

import { useEffect, useState, useCallback } from 'react';
import { supabase } from '@/lib/supabase';
import ConnectBank from './ConnectBank';
import { useFmt } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

interface Account {
  account_id: string;
  name: string;
  official_name: string | null;
  type: string;
  subtype: string | null;
  mask: string | null;
  current_balance: number | null;
  institution_name?: string;
}

interface Item {
  item_id: string;
  institution_name: string;
  last_sync: string | null;
  accounts: Account[];
}

export default function BankAccounts() {
  const fmt = useFmt();
  const [items, setItems] = useState<Item[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    const { data: itemsData } = await supabase
      .from('plaid_items')
      .select('item_id, institution_name, last_sync');
    const { data: accounts } = await supabase
      .from('plaid_accounts')
      .select('*');

    const grouped: Item[] = (itemsData || []).map((it) => ({
      item_id: it.item_id,
      institution_name: it.institution_name,
      last_sync: it.last_sync,
      accounts: (accounts || []).filter((a: { item_id: string }) => a.item_id === it.item_id),
    }));
    setItems(grouped);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleSync = async () => {
    void hapticLight();
    setSyncing(true);
    try {
      await supabase.functions.invoke('plaid-sync-transactions');
      await load();
    } finally {
      setSyncing(false);
    }
  };

  const handleDisconnect = async (item_id: string) => {
    if (!confirm('Disconnect this bank? You can reconnect it anytime.')) return;
    await supabase.from('plaid_items').delete().eq('item_id', item_id);
    await load();
  };

  return (
    <div className="space-y-4">
      {loading ? (
        <p className="text-center text-xs text-gray-500 py-4">Loading…</p>
      ) : items.length === 0 ? (
        <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg text-center text-xs text-gray-500 dark:text-gray-400">
          No banks connected yet. Connect your bank to automatically import transactions.
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item) => (
            <div key={item.item_id} className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm font-semibold text-gray-800 dark:text-gray-100">{item.institution_name}</p>
                <button
                  onClick={() => handleDisconnect(item.item_id)}
                  className="text-xs text-red-600 hover:text-red-700"
                >
                  Disconnect
                </button>
              </div>
              {item.accounts.map((a) => (
                <div key={a.account_id} className="flex justify-between items-center py-1 text-xs">
                  <div className="min-w-0">
                    <p className="font-medium text-gray-700 dark:text-gray-200 truncate">
                      {a.name} {a.mask && <span className="text-gray-400">••{a.mask}</span>}
                    </p>
                    <p className="text-gray-400 capitalize">{a.subtype || a.type}</p>
                  </div>
                  {a.current_balance !== null && (
                    <p className="font-semibold text-gray-800 dark:text-gray-100">{fmt(a.current_balance)}</p>
                  )}
                </div>
              ))}
            </div>
          ))}
          <button
            onClick={handleSync}
            disabled={syncing}
            className="w-full py-2 text-xs font-semibold text-blue-600 hover:text-blue-700 disabled:opacity-60"
          >
            {syncing ? 'Syncing…' : '↻ Sync transactions'}
          </button>
        </div>
      )}

      <ConnectBank onSuccess={() => load()} />
    </div>
  );
}
