'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import RecurringModal from '../modals/RecurringModal';
import type { RecurringSchedule } from '@/lib/types';

export default function RecurringSchedulesView() {
  const { recurringSchedules, setRecurringSchedules, saveAndRefresh } = useApp();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<RecurringSchedule | null>(null);

  const handleSave = (s: RecurringSchedule) => {
    const idx = recurringSchedules.findIndex((r) => r.id === s.id);
    const updated = idx >= 0 ? recurringSchedules.map((r) => (r.id === s.id ? s : r)) : [...recurringSchedules, s];
    setRecurringSchedules(updated);
    setOpen(false);
    setTimeout(saveAndRefresh, 0);
  };

  const handleToggle = (id: string, checked: boolean) => {
    setRecurringSchedules(recurringSchedules.map((s) => s.id === id ? { ...s, enabled: checked } : s));
    setTimeout(saveAndRefresh, 0);
  };

  const handleDelete = (id: string) => {
    if (!confirm('Delete this recurring schedule?')) return;
    setRecurringSchedules(recurringSchedules.filter((s) => s.id !== id));
    setTimeout(saveAndRefresh, 0);
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Recurring Schedules</h2>
        <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-dindin-green text-white rounded-lg hover:bg-dindin-green-dark font-semibold">
          Add New Schedule
        </button>
      </div>
      <p className="text-gray-500 mb-6 text-sm">Manage long-term, repeating financial events. Toggle to enable/disable.</p>

      <div className="space-y-4">
        {recurringSchedules.length === 0 && <p className="text-center text-gray-400 italic py-8">No schedules yet.</p>}
        {recurringSchedules.map((s) => {
          const isExpense = s.amount < 0;
          return (
            <div key={s.id} className="flex items-center justify-between p-4 rounded-xl border border-gray-200 bg-white dark:bg-gray-700 shadow-sm hover:shadow-md transition">
              <div className="flex items-center min-w-0">
                <div className={`flex-shrink-0 w-3 h-3 rounded-full mr-4 ${isExpense ? 'bg-red-500' : 'bg-green-500'}`} />
                <div className="min-w-0">
                  <p className="font-semibold text-gray-800 dark:text-gray-100 truncate">{s.name}</p>
                  <p className="text-sm text-gray-500">{isExpense ? 'Expense' : 'Income'} · {s.frequency}</p>
                </div>
              </div>
              <div className="flex items-center space-x-3 flex-shrink-0 ml-4">
                <p className={`font-semibold text-lg w-24 text-right ${isExpense ? 'text-red-600' : 'text-green-600'}`}>
                  ${Math.abs(s.amount).toFixed(2)}
                </p>
                <div className="relative inline-block w-10 align-middle select-none">
                  <input type="checkbox" id={`tog-${s.id}`} checked={s.enabled} onChange={(e) => handleToggle(s.id, e.target.checked)}
                    className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
                  <label htmlFor={`tog-${s.id}`} className="toggle-label block overflow-hidden h-6 rounded-full bg-gray-300 cursor-pointer" />
                </div>
                <button onClick={() => { setEditing(s); setOpen(true); }} className="p-2 text-gray-400 hover:text-blue-600 rounded-full hover:bg-gray-100">✏️</button>
                <button onClick={() => handleDelete(s.id)} className="p-2 text-gray-400 hover:text-red-600 rounded-full hover:bg-gray-100">🗑️</button>
              </div>
            </div>
          );
        })}
      </div>

      <RecurringModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </section>
  );
}
