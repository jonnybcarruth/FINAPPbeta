'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import RecurringModal from '../modals/RecurringModal';
import EmptyState from '../EmptyState';
import type { RecurringSchedule } from '@/lib/types';
import { useT, useFmt } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

export default function RecurringSchedulesView() {
  const { recurringSchedules, setRecurringSchedules, saveWithOverrides, settings } = useApp();
  const t = useT();
  const fmt = useFmt();
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
    void hapticLight();
    const updated = recurringSchedules.map((s) => s.id === id ? { ...s, enabled: checked } : s);
    setRecurringSchedules(updated);
    saveWithOverrides(updated, undefined, undefined, undefined, undefined);
  };

  const handleDelete = (id: string) => {
    const msg = settings.language === 'pt' ? 'Excluir este agendamento?' : 'Delete this recurring schedule?';
    if (!confirm(msg)) return;
    const updated = recurringSchedules.filter((s) => s.id !== id);
    setRecurringSchedules(updated);
    saveWithOverrides(updated, undefined, undefined, undefined, undefined);
  };

  const freqLabel = (f: string) => f === 'Monthly' ? t('monthly') : f === 'BiWeekly' ? t('biweekly') : t('weekly');

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      {recurringSchedules.length === 0 ? (
        <EmptyState
          icon={
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="17 2 21 6 17 10"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 22 3 18 7 14"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>
            </svg>
          }
          title={t('no_recurring_title')}
          description={t('no_recurring_desc')}
          cta={{ label: t('add_first_schedule'), onClick: () => { setEditing(null); setOpen(true); } }}
          suggestions={[t('sugg_salary'), t('sugg_rent'), t('sugg_phone'), t('sugg_subscription')]}
        />
      ) : (
        <>
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">{t('recurring_schedules')}</h2>
            <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
              + {t('add')}
            </button>
          </div>

          <div className="space-y-4">
            {recurringSchedules.map((s) => {
              const isExpense = s.amount < 0;
              return (
                <div key={s.id} className={`p-4 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-700 shadow-sm hover:shadow-md transition ${!s.enabled ? 'opacity-50' : ''}`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center min-w-0 mr-3">
                      <div className={`flex-shrink-0 w-3 h-3 rounded-full mr-3 ${isExpense ? 'bg-red-500' : 'bg-emerald-500'}`} />
                      <p className="font-semibold text-gray-800 dark:text-gray-100 truncate">{s.name}</p>
                    </div>
                    <div className="relative inline-block w-12 h-7 flex-shrink-0 select-none">
                      <input type="checkbox" id={`tog-${s.id}`} checked={s.enabled} onChange={(e) => handleToggle(s.id, e.target.checked)}
                        className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
                      <label htmlFor={`tog-${s.id}`} className="toggle-label block overflow-hidden h-7 rounded-full bg-gray-300 cursor-pointer" />
                    </div>
                  </div>
                  <div className="flex items-center justify-between">
                    <p className="text-sm text-gray-500 dark:text-gray-400">{isExpense ? t('expense') : t('income')} · {freqLabel(s.frequency)}</p>
                    <div className="flex items-center space-x-2">
                      <p className={`font-semibold text-base ${isExpense ? 'text-red-600' : 'text-emerald-600'}`}>
                        {fmt(Math.abs(s.amount))}
                      </p>
                      <button onClick={() => { setEditing(s); setOpen(true); }} className="p-2 text-gray-400 hover:text-ios-blue rounded-full hover:bg-gray-100 dark:hover:bg-gray-600">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                      </button>
                      <button onClick={() => handleDelete(s.id)} className="p-2 text-gray-400 hover:text-ios-red rounded-full hover:bg-gray-100 dark:hover:bg-gray-600">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}

      <RecurringModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </section>
  );
}
