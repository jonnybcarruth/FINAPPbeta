'use client';

import { useState, type FormEvent, type ReactNode } from 'react';
import Link from 'next/link';
import { useAuth } from '@/context/AuthContext';

interface Props {
  mode: 'login' | 'signup';
}

export default function AuthForm({ mode }: Props) {
  const { signInWithPassword, signUpWithPassword, signInWithOAuth } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setSubmitting(true);
    try {
      if (mode === 'login') {
        const { error } = await signInWithPassword(email, password);
        if (error) setError(error);
      } else {
        if (password.length < 8) {
          setError('Password must be at least 8 characters.');
          return;
        }
        const { error } = await signUpWithPassword(email, password);
        if (error) setError(error);
        else setInfo('Check your email to confirm your account.');
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function handleOAuth(provider: 'google' | 'apple') {
    setError(null);
    const { error } = await signInWithOAuth(provider);
    if (error) setError(error);
  }

  const title = mode === 'login' ? 'Sign in to DinDin' : 'Create your DinDin account';
  const submitLabel = mode === 'login' ? 'Sign in' : 'Sign up';

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-10 bg-gray-50 dark:bg-gray-950">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <p className="text-xs font-semibold uppercase tracking-widest text-ios-gray">DinDin</p>
          <h1 className="text-2xl font-bold mt-1 text-gray-900 dark:text-white">{title}</h1>
        </div>

        <div className="space-y-3">
          <OAuthButton onClick={() => handleOAuth('apple')} label="Continue with Apple" />
          <OAuthButton onClick={() => handleOAuth('google')} label="Continue with Google" />
        </div>

        <div className="flex items-center gap-3 text-xs text-gray-500">
          <div className="h-px flex-1 bg-gray-200 dark:bg-gray-800" />
          <span>or</span>
          <div className="h-px flex-1 bg-gray-200 dark:bg-gray-800" />
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <label className="block">
            <span className="text-xs font-medium text-gray-700 dark:text-gray-300">Email</span>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-gray-700 dark:text-gray-300">Password</span>
            <input
              type="password"
              required
              minLength={mode === 'signup' ? 8 : undefined}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
              className="mt-1 w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </label>

          {error && <Message tone="error">{error}</Message>}
          {info && <Message tone="info">{info}</Message>}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-60 py-2.5 text-sm font-semibold text-white"
          >
            {submitting ? 'Please wait…' : submitLabel}
          </button>
        </form>

        <div className="text-center text-xs text-gray-600 dark:text-gray-400 space-y-2">
          {mode === 'login' ? (
            <>
              <div>
                <Link href="/forgot-password" className="text-blue-600 hover:underline">
                  Forgot your password?
                </Link>
              </div>
              <div>
                New here?{' '}
                <Link href="/signup" className="text-blue-600 hover:underline">
                  Create an account
                </Link>
              </div>
            </>
          ) : (
            <div>
              Already have an account?{' '}
              <Link href="/login" className="text-blue-600 hover:underline">
                Sign in
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function OAuthButton({ onClick, label }: { onClick: () => void; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-900 py-2.5 text-sm font-medium text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-800"
    >
      {label}
    </button>
  );
}

function Message({ tone, children }: { tone: 'error' | 'info'; children: ReactNode }) {
  const cls =
    tone === 'error'
      ? 'bg-red-50 text-red-700 border-red-200 dark:bg-red-950 dark:text-red-200 dark:border-red-900'
      : 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950 dark:text-blue-200 dark:border-blue-900';
  return <div className={`rounded-lg border px-3 py-2 text-xs ${cls}`}>{children}</div>;
}
