'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { supabase } from '@/lib/supabase';

/**
 * OAuth / magic-link landing page. Supabase's client with `detectSessionInUrl: true`
 * will automatically exchange the code in the URL for a session on load — we just
 * wait briefly, then bounce to home.
 */
export default function AuthCallbackPage() {
  const router = useRouter();

  useEffect(() => {
    let cancelled = false;
    async function run() {
      // Give the supabase client a tick to parse the URL and set the session.
      await supabase.auth.getSession();
      if (!cancelled) router.replace('/');
    }
    run();
    return () => {
      cancelled = true;
    };
  }, [router]);

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-sm text-gray-500">Signing you in…</div>
    </div>
  );
}
