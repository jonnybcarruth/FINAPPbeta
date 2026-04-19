'use client';

import { useState, useEffect, useCallback } from 'react';
import { hapticSuccess, hapticLight } from '@/lib/haptics';
import ModalShell from './ModalShell';
import TypeToggle from './TypeToggle';
import type { OneTimeTransaction } from '@/lib/types';
import { format } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useT, useCurrencySymbol, useLocale } from '@/lib/i18n';

interface Props {
  open: boolean;
  onClose: () => void;
  onSave: (t: OneTimeTransaction) => void;
  initial?: OneTimeTransaction | null;
  defaultDate?: string;
}

const CALC_KEYS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '0', 'del'];

export default function OneTimeModal({ open, onClose, onSave, initial, defaultDate }: Props) {
  const t = useT();
  const sym = useCurrencySymbol();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [type, setType] = useState<'income' | 'expense'>('expense');
  const [date, setDate] = useState(format(new Date(), 'yyyy-MM-dd'));
  const [showDatePicker, setShowDatePicker] = useState(false);

  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setAmount(String(Math.abs(initial.amount)));
      setType(initial.amount > 0 ? 'income' : 'expense');
      setDate(initial.date);
      setShowDatePicker(true);
    } else {
      setName('');
      setAmount('');
      setType('expense');
      if (defaultDate) {
        setDate(defaultDate);
        setShowDatePicker(false);
      } else {
        setDate(format(new Date(), 'yyyy-MM-dd'));
        setShowDatePicker(true);
      }
    }
  }, [initial, defaultDate, open]);

  const handleKey = useCallback((key: string) => {
    void hapticLight();
    setAmount((prev) => {
      if (key === 'del') return prev.slice(0, -1);
      if (key === '.' && prev.includes('.')) return prev;
      const parts = prev.split('.');
      if (parts[1] && parts[1].length >= 2) return prev;
      if (prev.length >= 10) return prev;
      return prev + key;
    });
  }, []);

  const handleSubmit = () => {
    const parsed = parseFloat(amount);
    if (!name.trim() || isNaN(parsed) || parsed <= 0) return;
    const finalAmount = type === 'income' ? parsed : -parsed;
    void hapticSuccess();
    onSave({ id: initial?.id || `ONE-${Date.now()}`, name: name.trim(), amount: finalAmount, date });
  };

  const displayAmount = amount || '0';
  const isValid = name.trim().length > 0 && parseFloat(amount) > 0;

  return (
    <ModalShell open={open} onClose={onClose} title={initial ? t('edit_transaction') : t('add_transaction')}>
      <div className="space-y-4">
        <TypeToggle value={type} onChange={setType} />

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('name')}</label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
          />
        </div>

        {showDatePicker ? (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('date')}</label>
            <input type="date" required value={date} onChange={(e) => setDate(e.target.value)}
              className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
          </div>
        ) : (
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
            {format(new Date(date + 'T00:00:00'), 'EEEE, MMMM d, yyyy', { locale: dateLocale })}
          </p>
        )}

        <div className="text-center py-3">
          <span className={`text-4xl font-bold tracking-tight ${type === 'expense' ? 'text-red-600' : 'text-emerald-600'}`}>
            {type === 'expense' ? '-' : '+'}{sym}{sym.length > 1 ? ' ' : ''}{displayAmount}
          </span>
        </div>

        <div className="grid grid-cols-3 gap-2">
          {CALC_KEYS.map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => handleKey(key)}
              className={`h-12 rounded-xl text-lg font-semibold transition-colors ${
                key === 'del'
                  ? 'bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
                  : 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-700'
              }`}
            >
              {key === 'del' ? (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mx-auto">
                  <path d="M21 4H8l-7 8 7 8h13a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2z" /><line x1="18" y1="9" x2="12" y2="15" /><line x1="12" y1="9" x2="18" y2="15" />
                </svg>
              ) : key}
            </button>
          ))}
        </div>

        <div className="flex justify-end space-x-3 pt-2">
          <button type="button" onClick={onClose} className="px-5 py-2.5 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 text-sm">{t('cancel')}</button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!isValid}
            className="px-5 py-2.5 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm disabled:opacity-40"
          >
            {t('save')}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
