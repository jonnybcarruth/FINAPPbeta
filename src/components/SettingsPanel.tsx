'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import { useAuth } from '@/context/AuthContext';

export default function SettingsPanel() {
  const { settings, setSettings, saveAndRefresh } = useApp();
  const { user, signOut, deleteAccount } = useAuth();
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  async function handleDelete() {
    if (!confirm('Permanently delete your account and all saved data? This cannot be undone.')) return;
    setDeleting(true);
    setDeleteError(null);
    const { error } = await deleteAccount();
    setDeleting(false);
    if (error) setDeleteError(error);
  }

  const handleChange = (field: keyof typeof settings, value: string | number | boolean) => {
    setSettings({ ...settings, [field]: value });
    if (field === 'darkMode') {
      document.documentElement.classList.toggle('dark', value as boolean);
    }
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Settings</h2>
        <button onClick={saveAndRefresh} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
          Save Settings
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
        <div className="flex items-center justify-between p-3 bg-gray-100 dark:bg-gray-700 rounded-lg col-span-full">
          <label className="text-sm font-medium text-gray-700 dark:text-gray-300">Dark Mode</label>
          <div className="relative inline-block w-12 align-middle select-none">
            <input type="checkbox" id="darkModeToggle" checked={settings.darkMode}
              onChange={(e) => handleChange('darkMode', e.target.checked)}
              className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
            <label htmlFor="darkModeToggle" className="toggle-label block overflow-hidden cursor-pointer w-12" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Projection Start Date</label>
          <input type="date" value={settings.startDate} onChange={(e) => handleChange('startDate', e.target.value)}
            className="w-full p-2 border border-gray-300 rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Projection Length (Months)</label>
          <select value={settings.projectionMonths} onChange={(e) => handleChange('projectionMonths', parseInt(e.target.value))}
            className="w-full p-2 border border-gray-300 rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600">
            <option value={3}>3 Months</option>
            <option value={6}>6 Months</option>
            <option value={12}>12 Months</option>
            <option value={24}>24 Months</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Starting Balance ($)</label>
          <input type="number" value={settings.startingBalance} onChange={(e) => handleChange('startingBalance', parseFloat(e.target.value))}
            className="w-full p-2 border border-gray-300 rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
      </div>

      {user && (
        <div className="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
          <h3 className="text-sm font-semibold text-gray-800 dark:text-gray-100 mb-3">Account</h3>
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
            Signed in as <span className="font-medium text-gray-700 dark:text-gray-200">{user.email}</span>
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => signOut()}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-100 rounded-xl hover:bg-gray-300 dark:hover:bg-gray-600 font-semibold text-sm"
            >
              Sign out
            </button>
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="px-4 py-2 bg-red-600 text-white rounded-xl hover:bg-red-700 disabled:opacity-60 font-semibold text-sm"
            >
              {deleting ? 'Deleting…' : 'Delete account'}
            </button>
          </div>
          {deleteError && (
            <p className="mt-2 text-xs text-red-600 dark:text-red-400">{deleteError}</p>
          )}
        </div>
      )}
    </section>
  );
}
