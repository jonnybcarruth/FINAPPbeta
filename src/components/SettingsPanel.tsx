'use client';

import { useApp } from '@/context/AppContext';
import { useT, useCurrencySymbol } from '@/lib/i18n';

export default function SettingsPanel() {
  const { settings, setSettings, saveAndRefresh } = useApp();
  const t = useT();
  const sym = useCurrencySymbol();

  const handleChange = (field: keyof typeof settings, value: string | number | boolean) => {
    setSettings({ ...settings, [field]: value });
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">{t('settings')}</h2>
        <button onClick={saveAndRefresh} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
          {t('save_settings')}
        </button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('projection_start_date')}</label>
          <input type="date" value={settings.startDate} onChange={(e) => handleChange('startDate', e.target.value)}
            className="w-full p-2 border border-gray-300 rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('projection_length')}</label>
          <select value={settings.projectionMonths} onChange={(e) => handleChange('projectionMonths', parseInt(e.target.value))}
            className="w-full p-2 border border-gray-300 rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600">
            <option value={3}>3 {t('months')}</option>
            <option value={6}>6 {t('months')}</option>
            <option value={12}>12 {t('months')}</option>
            <option value={24}>24 {t('months')}</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('starting_balance')} ({sym})</label>
          <input type="number" value={settings.startingBalance} onChange={(e) => handleChange('startingBalance', parseFloat(e.target.value))}
            className="w-full p-2 border border-gray-300 rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
      </div>
    </section>
  );
}
