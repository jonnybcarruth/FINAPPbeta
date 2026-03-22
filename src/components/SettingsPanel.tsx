'use client';

import { useApp } from '@/context/AppContext';

export default function SettingsPanel() {
  const { settings, setSettings, saveAndRefresh } = useApp();

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
        <button onClick={saveAndRefresh} className="px-4 py-2 bg-dindin-green text-white rounded-lg hover:bg-dindin-green-dark font-semibold">
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
    </section>
  );
}
