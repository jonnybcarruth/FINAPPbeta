'use client';

import { useT } from '@/lib/i18n';

interface TypeToggleProps {
  value: 'income' | 'expense';
  onChange: (v: 'income' | 'expense') => void;
}

export default function TypeToggle({ value, onChange }: TypeToggleProps) {
  const t = useT();
  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">{t('type')}</label>
      <div className="flex rounded-lg border border-gray-300 overflow-hidden">
        <button
          type="button"
          onClick={() => onChange('expense')}
          className={`flex-1 p-2 font-semibold text-center transition ${
            value === 'expense' ? 'bg-red-100 text-red-700' : 'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300'
          }`}
        >
          {t('expense')}
        </button>
        <button
          type="button"
          onClick={() => onChange('income')}
          className={`flex-1 p-2 font-semibold text-center transition border-l ${
            value === 'income' ? 'bg-green-100 text-green-700' : 'bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300'
          }`}
        >
          {t('income')}
        </button>
      </div>
    </div>
  );
}
