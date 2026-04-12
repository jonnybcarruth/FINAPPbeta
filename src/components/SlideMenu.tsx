'use client';

import { useState } from 'react';
import { format } from 'date-fns';
import { useApp } from '@/context/AppContext';
import { useAuth } from '@/context/AuthContext';
import { setHapticsEnabled } from '@/lib/haptics';

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function SlideMenu({ open, onClose }: Props) {
  const { settings, setSettings, saveWithOverrides, projections } = useApp();
  const { user, signOut, deleteAccount } = useAuth();
  const [showLog, setShowLog] = useState(false);
  const [logFilter, setLogFilter] = useState<'all' | 'income' | 'expense'>('all');
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const toggleSetting = (field: 'darkMode' | 'hapticsEnabled' | 'soundsEnabled') => {
    const newVal = !settings[field];
    const newSettings = { ...settings, [field]: newVal };
    setSettings(newSettings);
    if (field === 'darkMode') {
      document.documentElement.classList.toggle('dark', newVal);
    }
    if (field === 'hapticsEnabled') {
      setHapticsEnabled(newVal);
    }
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
  };

  async function handleDeleteAccount() {
    if (!confirm('Permanently delete your account and all saved data? This cannot be undone.')) return;
    setDeleting(true);
    setDeleteError(null);
    const { error } = await deleteAccount();
    setDeleting(false);
    if (error) setDeleteError(error);
  }

  // Transaction log data
  const filtered = projections.filter((p) => {
    if (logFilter === 'income') return p.amount > 0;
    if (logFilter === 'expense') return p.amount < 0;
    return true;
  });

  const typeLabel = (t: typeof projections[0]) => {
    if (t.type === 'Savings') return 'Savings';
    if (t.type === 'Debt Payment') return 'Debt';
    if (t.type === 'One-Time') return t.name.includes('(Planned)') ? 'Plan' : 'One-Time';
    return 'Recurring';
  };

  if (showLog) {
    return (
      <>
        {/* Backdrop */}
        <div className={`fixed inset-0 bg-black/50 z-50 transition-opacity ${open ? 'opacity-100' : 'opacity-0 pointer-events-none'}`} onClick={() => { setShowLog(false); onClose(); }} />
        {/* Full-screen log panel */}
        <div className={`fixed inset-y-0 right-0 w-full sm:w-[420px] bg-white dark:bg-gray-900 z-50 transform transition-transform duration-300 ${open ? 'translate-x-0' : 'translate-x-full'} flex flex-col`}>
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
            <button onClick={() => setShowLog(false)} className="text-sm text-blue-600 font-medium">Back</button>
            <h2 className="text-base font-bold text-gray-800 dark:text-gray-100">Transaction Log</h2>
            <select value={logFilter} onChange={(e) => setLogFilter(e.target.value as typeof logFilter)}
              className="text-xs p-1.5 border rounded-lg dark:bg-gray-800 dark:text-white dark:border-gray-600">
              <option value="all">All</option>
              <option value="income">Income</option>
              <option value="expense">Expenses</option>
            </select>
          </div>
          <div className="flex-1 overflow-y-auto">
            {filtered.length === 0 && <p className="text-center text-gray-500 py-10">No transactions.</p>}
            {filtered.map((p, i) => (
              <div key={i} className="flex justify-between items-center px-4 py-3 border-b border-gray-100 dark:border-gray-800">
                <div className="min-w-0 flex-1 mr-3">
                  <p className="text-sm font-medium text-gray-800 dark:text-gray-100 truncate">{p.name}</p>
                  <p className="text-xs text-gray-500">{format(p.date, 'MMM d, yyyy')} · {typeLabel(p)}</p>
                </div>
                <p className={`text-sm font-semibold flex-shrink-0 ${p.type === 'Savings' ? 'text-emerald-600' : p.amount >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                  {p.amount >= 0 ? '+' : ''}{p.amount.toLocaleString('en-US', { style: 'currency', currency: 'USD' })}
                </p>
              </div>
            ))}
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      {/* Backdrop */}
      <div
        className={`fixed inset-0 bg-black/50 z-50 transition-opacity duration-300 ${open ? 'opacity-100' : 'opacity-0 pointer-events-none'}`}
        onClick={onClose}
      />
      {/* Slide panel */}
      <div className={`fixed inset-y-0 right-0 w-72 bg-white dark:bg-gray-900 z-50 transform transition-transform duration-300 shadow-2xl ${open ? 'translate-x-0' : 'translate-x-full'} flex flex-col`}>
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-bold text-gray-800 dark:text-gray-100">Menu</h2>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-800">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {/* Profile section */}
          {user && (
            <div className="p-5 border-b border-gray-200 dark:border-gray-700">
              <div className="w-12 h-12 rounded-full bg-blue-100 dark:bg-blue-900 flex items-center justify-center mb-3">
                <span className="text-blue-600 dark:text-blue-300 text-lg font-bold">
                  {(user.email?.[0] || 'U').toUpperCase()}
                </span>
              </div>
              <p className="text-sm font-semibold text-gray-800 dark:text-gray-100 truncate">{user.email}</p>
              <p className="text-xs text-gray-500 mt-0.5">DinDin Account</p>
            </div>
          )}

          {/* Toggles */}
          <div className="p-5 space-y-4 border-b border-gray-200 dark:border-gray-700">
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Preferences</p>

            <ToggleRow label="Dark Mode" checked={settings.darkMode} onChange={() => toggleSetting('darkMode')} id="menu-dark" />
            <ToggleRow label="Vibrations" checked={settings.hapticsEnabled} onChange={() => toggleSetting('hapticsEnabled')} id="menu-haptics" />
            <ToggleRow label="Sounds" checked={settings.soundsEnabled} onChange={() => toggleSetting('soundsEnabled')} id="menu-sounds" />
          </div>

          {/* Links */}
          <div className="p-5 space-y-1 border-b border-gray-200 dark:border-gray-700">
            <button onClick={() => setShowLog(true)}
              className="w-full flex items-center space-x-3 p-3 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 text-left">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <line x1="9" y1="6" x2="20" y2="6"/><line x1="9" y1="12" x2="20" y2="12"/><line x1="9" y1="18" x2="20" y2="18"/>
                <circle cx="4" cy="6" r="1.5" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.5" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.5" fill="currentColor" stroke="none"/>
              </svg>
              <span className="text-sm font-medium text-gray-800 dark:text-gray-100">Transaction Log</span>
            </button>
          </div>
        </div>

        {/* Bottom actions */}
        <div className="p-5 border-t border-gray-200 dark:border-gray-700 space-y-2">
          <button onClick={() => signOut()} className="w-full py-2.5 text-sm font-semibold text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-800 rounded-xl hover:bg-gray-200 dark:hover:bg-gray-700">
            Sign out
          </button>
          <button onClick={handleDeleteAccount} disabled={deleting}
            className="w-full py-2.5 text-sm font-semibold text-red-600 bg-red-50 dark:bg-red-950 rounded-xl hover:bg-red-100 dark:hover:bg-red-900 disabled:opacity-60">
            {deleting ? 'Deleting…' : 'Delete account'}
          </button>
          {deleteError && <p className="text-xs text-red-500 text-center">{deleteError}</p>}
        </div>
      </div>
    </>
  );
}

function ToggleRow({ label, checked, onChange, id }: { label: string; checked: boolean; onChange: () => void; id: string }) {
  return (
    <div className="flex items-center justify-between">
      <label htmlFor={id} className="text-sm font-medium text-gray-700 dark:text-gray-300">{label}</label>
      <div className="relative inline-block w-12 h-7 select-none">
        <input type="checkbox" id={id} checked={checked} onChange={onChange}
          className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
        <label htmlFor={id} className="toggle-label block overflow-hidden h-7 rounded-full bg-gray-300 cursor-pointer" />
      </div>
    </div>
  );
}
