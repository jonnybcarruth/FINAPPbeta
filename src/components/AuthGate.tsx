'use client';

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';

const PUBLIC_PATHS = ['/login', '/signup', '/forgot-password', '/reset-password', '/auth/callback'];

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, loading, configured } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const isPublic = PUBLIC_PATHS.some((p) => pathname?.startsWith(p));

  useEffect(() => {
    if (loading) return;
    if (!configured) return;
    if (!user && !isPublic) {
      router.replace('/login');
    }
    if (user && isPublic && pathname !== '/reset-password') {
      router.replace('/');
    }
  }, [user, loading, configured, isPublic, pathname, router]);

  if (!configured) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6 text-center">
        <div className="max-w-md space-y-3">
          <h1 className="text-xl font-bold">Supabase not configured</h1>
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Copy <code>.env.local.example</code> to <code>.env.local</code> and fill in your Supabase
            project URL and anon key, then restart the dev server.
          </p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-sm text-gray-500">Loading…</div>
      </div>
    );
  }

  if (!user && !isPublic) {
    return null; // redirect is in-flight
  }

  return <>{children}</>;
}
