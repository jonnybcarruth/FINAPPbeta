'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import RecurringModal from '../modals/RecurringModal';
import type { RecurringSchedule } from '@/lib/types';

export default function RecurringSchedulesView() {
  const { recurringSchedules, setRecurringSchedules, saveWithOverrides } = useApp();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<RecurringSchedule | null>(null);

  const handleSave = (s: RecurringSchedule) => {
    const idx = recurringSchedules.findIndex((r) => r.id === s.id);
    const updated = idx >= 0 ? recurringSchedules.map((r) => (r.id === s.id ? s : r)) : [...recurringSchedules, s];
    setRecurringSchedules(updated);
    setOpen(false);
    saveWithOverrides(updated, undefined, undefined, undefined, undefined);
  };

  const handleToggle = (id: string, checked: boolean) => {
    const updated = recurringSchedules.map((s) => s.id === id ? { ...s, enabled: checked } : s);
    setRecurringSchedules(updated);
    saveWithOverrides(updated, undefined, undefined, undefined, undefined);
  };

  const handleDelete = (id: string) => {
    if (!confirm('Delete this recurring schedule?')) return;
    const updated = recurringSchedules.filter((s) => s.id !== id);
    setRecurringSchedules(updated);
    saveWithOverrides(updated, undefined, undefined, undefined, undefined);
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Recurring Schedules</h2>
        <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
          Add Schedule
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
                <button onClick={() => { setEditing(s); setOpen(true); }} className="p-2 text-ios-gray hover:text-ios-blue rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                </button>
                <button onClick={() => handleDelete(s.id)} className="p-2 text-ios-gray hover:text-ios-red rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <RecurringModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </section>
  );
}
