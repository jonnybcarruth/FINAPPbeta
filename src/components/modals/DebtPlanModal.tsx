'use client';

import { useState, useEffect } from 'react';
import ModalShell from './ModalShell';
import type { DebtPlan } from '@/lib/types';
import { format } from 'date-fns';

interface Props {
  open: boolean;
  onClose: () => void;
  onSave: (d: DebtPlan) => void;
  initial?: DebtPlan | null;
}

export default function DebtPlanModal({ open, onClose, onSave, initial }: Props) {
  const [name, setName] = useState('');
  const [totalAmount, setTotalAmount] = useState('');
  const [payoffMonths, setPayoffMonths] = useState('12');
  const [startDate, setStartDate] = useState(format(new Date(), 'yyyy-MM-dd'));
  const [payDay, setPayDay] = useState('1');

  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setTotalAmount(String(initial.totalAmount));
      setPayoffMonths(String(initial.payoffMonths));
      setStartDate(initial.startDate);
      setPayDay(String(initial.payDay));
    } else {
      setName(''); setTotalAmount(''); setPayoffMonths('12');
      setStartDate(format(new Date(), 'yyyy-MM-dd')); setPayDay('1');
    }
  }, [initial, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const total = parseFloat(totalAmount);
    const months = parseInt(payoffMonths);
    onSave({
      id: initial?.id || `DEBT-${Date.now()}`,
      name, totalAmount: total, payoffMonths: months,
      monthlyPayment: parseFloat((total / months).toFixed(2)),
      payDay: parseInt(payDay), startDate, enabled: true,
    });
  };

  return (
    <ModalShell open={open} onClose={onClose} title={initial ? 'Edit Debt Plan' : 'Add Debt Plan'}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Debt Name</label>
          <input required value={name} onChange={(e) => setName(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Total Debt Amount ($)</label>
          <input type="number" step="0.01" required value={totalAmount} onChange={(e) => setTotalAmount(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Payoff Months</label>
          <input type="number" min="1" required value={payoffMonths} onChange={(e) => setPayoffMonths(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">First Payment Date</label>
          <input type="date" required value={startDate} onChange={(e) => setStartDate(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Payment Day of Month (1–31)</label>
          <input type="number" min="1" max="31" required value={payDay} onChange={(e) => setPayDay(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div className="flex justify-end space-x-3 pt-4">
          <button type="button" onClick={onClose} className="px-5 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300">Cancel</button>
          <button type="submit" className="px-5 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700">Save</button>
        </div>
      </form>
    </ModalShell>
  );
}
