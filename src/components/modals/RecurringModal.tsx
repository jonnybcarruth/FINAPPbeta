'use client';

import { useState, useEffect } from 'react';
import ModalShell from './ModalShell';
import TypeToggle from './TypeToggle';
import type { RecurringSchedule } from '@/lib/types';
import { format } from 'date-fns';

interface Props {
  open: boolean;
  onClose: () => void;
  onSave: (s: RecurringSchedule) => void;
  initial?: RecurringSchedule | null;
}

const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export default function RecurringModal({ open, onClose, onSave, initial }: Props) {
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [type, setType] = useState<'income' | 'expense'>('expense');
  const [startDate, setStartDate] = useState(format(new Date(), 'yyyy-MM-dd'));
  const [endDate, setEndDate] = useState('');
  const [frequency, setFrequency] = useState<'Monthly' | 'Weekly' | 'BiWeekly'>('Monthly');
  const [dayMonth, setDayMonth] = useState('1');
  const [dayWeek, setDayWeek] = useState('Thursday');

  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setAmount(String(Math.abs(initial.amount)));
      setType(initial.amount > 0 ? 'income' : 'expense');
      setStartDate(initial.startDate);
      setEndDate(initial.endDate || '');
      setFrequency(initial.frequency);
      if (initial.frequency === 'Monthly') setDayMonth(String(initial.dayValue));
      else setDayWeek(String(initial.dayValue));
    } else {
      setName(''); setAmount(''); setType('expense');
      setStartDate(format(new Date(), 'yyyy-MM-dd'));
      setEndDate('');
      setFrequency('Monthly'); setDayMonth('1'); setDayWeek('Thursday');
    }
  }, [initial, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const finalAmount = type === 'income' ? parseFloat(amount) : -parseFloat(amount);
    onSave({
      id: initial?.id || `SCH-${Date.now()}`,
      name, amount: finalAmount, startDate,
      ...(endDate ? { endDate } : {}),
      frequency,
      dayValue: frequency === 'Monthly' ? parseInt(dayMonth) : dayWeek,
      enabled: initial?.enabled ?? true,
    });
  };

  return (
    <ModalShell open={open} onClose={onClose} title={initial ? 'Edit Recurring Schedule' : 'Add Recurring Schedule'}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
          <input required value={name} onChange={(e) => setName(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <TypeToggle value={type} onChange={setType} />
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Amount ($)</label>
          <input type="number" step="0.01" min="0" required value={amount} onChange={(e) => setAmount(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Start Date</label>
          <input type="date" required value={startDate} onChange={(e) => setStartDate(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            End Date <span className="text-gray-400 font-normal">(optional — leave blank to repeat forever)</span>
          </label>
          <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Frequency</label>
          <select value={frequency} onChange={(e) => setFrequency(e.target.value as typeof frequency)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600">
            <option value="Monthly">Monthly</option>
            <option value="Weekly">Weekly</option>
            <option value="BiWeekly">Bi-Weekly</option>
          </select>
        </div>
        {frequency === 'Monthly' ? (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Day of Month (1–31)</label>
            <input type="number" min="1" max="31" required value={dayMonth} onChange={(e) => setDayMonth(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
          </div>
        ) : (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Day of Week</label>
            <select value={dayWeek} onChange={(e) => setDayWeek(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600">
              {DAYS.map((d) => <option key={d}>{d}</option>)}
            </select>
          </div>
        )}
        <div className="flex justify-end space-x-3 pt-4">
          <button type="button" onClick={onClose} className="px-5 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300">Cancel</button>
          <button type="submit" className="px-5 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold">Save</button>
        </div>
      </form>
    </ModalShell>
  );
}
