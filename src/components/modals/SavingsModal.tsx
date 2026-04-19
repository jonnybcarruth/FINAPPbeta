'use client';

import { useState, useEffect } from 'react';
import ModalShell from './ModalShell';
import type { SavingsPlan } from '@/lib/types';
import { hapticSuccess, hapticLight } from '@/lib/haptics';
import { format } from 'date-fns';
import { useT, useCurrencySymbol } from '@/lib/i18n';
import { useApp } from '@/context/AppContext';

interface Props {
  open: boolean;
  onClose: () => void;
  onSave: (s: SavingsPlan) => void;
  initial?: SavingsPlan | null;
}

const DAYS_EN = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const DAYS_PT = ['Domingo', 'Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado'];

export default function SavingsModal({ open, onClose, onSave, initial }: Props) {
  const t = useT();
  const sym = useCurrencySymbol();
  const { settings } = useApp();
  const DAYS = settings.language === 'pt' ? DAYS_PT : DAYS_EN;

  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [frequency, setFrequency] = useState<'Weekly' | 'BiWeekly' | 'Monthly'>('Weekly');
  const [dayMonth, setDayMonth] = useState('1');
  const [dayWeek, setDayWeek] = useState('Friday');
  const [startDate, setStartDate] = useState(format(new Date(), 'yyyy-MM-dd'));
  const [endDate, setEndDate] = useState('');
  const [goalAmount, setGoalAmount] = useState('');
  const [isPercent, setIsPercent] = useState(false);
  const [percentValue, setPercentValue] = useState('');

  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setAmount(String(initial.amount));
      setFrequency(initial.frequency);
      if (initial.frequency === 'Monthly') setDayMonth(String(initial.dayValue));
      else setDayWeek(String(initial.dayValue));
      setStartDate(initial.startDate);
      setEndDate(initial.endDate || '');
      setGoalAmount(initial.goalAmount ? String(initial.goalAmount) : '');
      setIsPercent(initial.isPercentOfIncome || false);
      setPercentValue(initial.percentValue ? String(initial.percentValue) : '');
    } else {
      setName(''); setAmount(''); setFrequency('Weekly');
      setDayMonth('1'); setDayWeek('Friday');
      setStartDate(format(new Date(), 'yyyy-MM-dd'));
      setEndDate(''); setGoalAmount(''); setIsPercent(false); setPercentValue('');
    }
  }, [initial, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void hapticSuccess();
    onSave({
      id: initial?.id || `SAV-${Date.now()}`,
      name, amount: parseFloat(amount), frequency,
      dayValue: frequency === 'Monthly' ? parseInt(dayMonth) : dayWeek,
      startDate,
      ...(endDate ? { endDate } : {}),
      ...(goalAmount ? { goalAmount: parseFloat(goalAmount) } : {}),
      enabled: initial?.enabled ?? true,
      ...(isPercent ? { isPercentOfIncome: true, percentValue: parseFloat(percentValue) || 0 } : {}),
    });
  };

  return (
    <ModalShell open={open} onClose={onClose} title={initial ? t('edit_savings') : t('new_savings')}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('name')}</label>
          <input required value={name} onChange={(e) => setName(e.target.value)}
            className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
        </div>
        <div className="flex items-center space-x-3 p-3 bg-gray-100 dark:bg-gray-700 rounded-lg">
          <input type="checkbox" checked={isPercent} onChange={(e) => { void hapticLight(); setIsPercent(e.target.checked); }} className="w-4 h-4" />
          <span className="text-sm font-medium text-gray-700 dark:text-gray-200">
            {settings.language === 'pt' ? '% da renda mensal' : '% of monthly income'}
          </span>
        </div>
        {isPercent ? (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {settings.language === 'pt' ? 'Percentual (%)' : 'Percentage (%)'}
            </label>
            <input type="number" step="0.5" min="0.5" max="100" required value={percentValue} onChange={(e) => setPercentValue(e.target.value)}
              placeholder="10" className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
          </div>
        ) : (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('amount_per_contribution')} ({sym})</label>
            <input type="number" step="0.01" min="0.01" required value={amount} onChange={(e) => setAmount(e.target.value)}
              className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
          </div>
        )}
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('frequency')}</label>
          <select value={frequency} onChange={(e) => setFrequency(e.target.value as typeof frequency)}
            className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm">
            <option value="Weekly">{t('weekly')}</option>
            <option value="BiWeekly">{t('biweekly')}</option>
            <option value="Monthly">{t('monthly')}</option>
          </select>
        </div>
        {frequency === 'Monthly' ? (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('day_of_month')}</label>
            <input type="number" min="1" max="31" required value={dayMonth} onChange={(e) => setDayMonth(e.target.value)}
              className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
          </div>
        ) : (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('day_of_week')}</label>
            <select value={dayWeek} onChange={(e) => setDayWeek(e.target.value)}
              className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm">
              {DAYS_EN.map((d, i) => <option key={d} value={d}>{DAYS[i]}</option>)}
            </select>
          </div>
        )}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('start_date')}</label>
            <input type="date" required value={startDate} onChange={(e) => setStartDate(e.target.value)}
              className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('end_date')} <span className="text-gray-400 font-normal">({t('optional')})</span></label>
            <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)}
              className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            {t('savings_goal')} ({sym}) <span className="text-gray-400 font-normal">({t('goal_desc')})</span>
          </label>
          <input type="number" step="0.01" min="0" value={goalAmount} onChange={(e) => setGoalAmount(e.target.value)}
            className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm" />
        </div>
        <div className="flex justify-end space-x-3 pt-4">
          <button type="button" onClick={onClose} className="px-5 py-2.5 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 text-sm">{t('cancel')}</button>
          <button type="submit" className="px-5 py-2.5 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">{t('save')}</button>
        </div>
      </form>
    </ModalShell>
  );
}
