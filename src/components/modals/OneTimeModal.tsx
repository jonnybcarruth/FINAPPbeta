'use client';

import { useState, useEffect } from 'react';
import ModalShell from './ModalShell';
import TypeToggle from './TypeToggle';
import type { OneTimeTransaction } from '@/lib/types';
import { format } from 'date-fns';

interface Props {
  open: boolean;
  onClose: () => void;
  onSave: (t: OneTimeTransaction) => void;
  initial?: OneTimeTransaction | null;
  defaultDate?: string;
}

export default function OneTimeModal({ open, onClose, onSave, initial, defaultDate }: Props) {
  const [name, setName] = useState('');
  const [amount, setAmount] = useState('');
  const [type, setType] = useState<'income' | 'expense'>('expense');
  const [date, setDate] = useState(format(new Date(), 'yyyy-MM-dd'));

  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setAmount(String(Math.abs(initial.amount)));
      setType(initial.amount > 0 ? 'income' : 'expense');
      setDate(initial.date);
    } else {
      setName(''); setAmount(''); setType('expense');
      setDate(defaultDate || format(new Date(), 'yyyy-MM-dd'));
    }
  }, [initial, defaultDate, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const finalAmount = type === 'income' ? parseFloat(amount) : -parseFloat(amount);
    onSave({ id: initial?.id || `ONE-${Date.now()}`, name, amount: finalAmount, date });
  };

  return (
    <ModalShell open={open} onClose={onClose} title={initial ? 'Edit Transaction' : 'Add One-Time Transaction'}>
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
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Date</label>
          <input type="date" required value={date} onChange={(e) => setDate(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div className="flex justify-end space-x-3 pt-4">
          <button type="button" onClick={onClose} className="px-5 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300">Cancel</button>
          <button type="submit" className="px-5 py-2 bg-dindin-green text-white rounded-lg hover:bg-dindin-green-dark">Save</button>
        </div>
      </form>
    </ModalShell>
  );
}
