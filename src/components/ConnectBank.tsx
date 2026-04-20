'use client';

import { useCallback, useEffect, useState } from 'react';
import { usePlaidLink } from 'react-plaid-link';
import { supabase } from '@/lib/supabase';
import { hapticSuccess, hapticLight } from '@/lib/haptics';
import { useT } from '@/lib/i18n';

interface Props {
  onSuccess?: (institution: string) => void;
  className?: string;
}

export default function ConnectBank({ onSuccess, className }: Props) {
  const t = useT();
  const [linkToken, setLinkToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const createLinkToken = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data, error: err } = await supabase.functions.invoke('plaid-link-token');
      if (err) throw err;
      if (data?.error) throw new Error(data.error);
      setLinkToken(data.link_token);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const onLinkSuccess = useCallback(async (public_token: string) => {
    try {
      const { data, error: err } = await supabase.functions.invoke('plaid-exchange-token', {
        body: { public_token },
      });
      if (err) throw err;
      if (data?.error) throw new Error(data.error);
      void hapticSuccess();
      // Trigger an initial sync of transactions in the background
      supabase.functions.invoke('plaid-sync-transactions').catch(console.error);
      onSuccess?.(data.institution || 'Bank');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [onSuccess]);

  const { open, ready } = usePlaidLink({
    token: linkToken,
    onSuccess: onLinkSuccess,
    onExit: (err) => {
      if (err) setError(err.display_message || err.error_message || 'Connection cancelled');
    },
  });

  useEffect(() => {
    if (linkToken && ready) open();
  }, [linkToken, ready, open]);

  const handleClick = () => {
    void hapticLight();
    createLinkToken();
  };

  return (
    <div className={className}>
      <button
        onClick={handleClick}
        disabled={loading}
        className="w-full py-3 bg-ios-blue text-white rounded-xl font-semibold text-sm hover:bg-ios-blue-dark disabled:opacity-60 flex items-center justify-center space-x-2"
      >
        <span className="text-lg">🏦</span>
        <span>{loading ? t('please_wait') : 'Connect a bank'}</span>
      </button>
      {error && <p className="mt-2 text-xs text-red-600">{error}</p>}
    </div>
  );
}
