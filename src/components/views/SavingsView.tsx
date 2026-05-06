'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import SavingsModal from '../modals/SavingsModal';
import EmptyState from '../EmptyState';
import type { SavingsPlan } from '@/lib/types';
import { useT, useFmt } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

export default function SavingsView() {
  const { savingsPlans, setSavingsPlans, projections, saveWithOverrides, settings } = useApp();
  const t = useT();
  const fmt = useFmt();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<SavingsPlan | null>(null);

  const totalSaved = projections
    .filter((p) => p.type === 'Savings')
    .reduce((sum, p) => sum + Math.abs(p.amount), 0);

  const totalGoals = savingsPlans
    .filter((p) => p.enabled && p.goalAmount)
    .reduce((sum, p) => sum + (p.goalAmount || 0), 0);

  const perPlanSaved: Record<string, number> = {};
  projections
    .filter((p) => p.type === 'Savings')
    .forEach((p) => {
      const planName = p.name.replace('Savings: ', '');
      perPlanSaved[planName] = (perPlanSaved[planName] || 0) + Math.abs(p.amount);
    });

  const handleSave = (plan: SavingsPlan) => {
    const idx = savingsPlans.findIndex((p) => p.id === plan.id);
    const updated = idx >= 0 ? savingsPlans.map((p) => (p.id === plan.id ? plan : p)) : [...savingsPlans, plan];
    setSavingsPlans(updated);
    setOpen(false);
    saveWithOverrides(undefined, undefined, undefined, undefined, undefined, updated);
  };

  const handleToggle = (id: string, checked: boolean) => {
    void hapticLight();
    const updated = savingsPlans.map((p) => p.id === id ? { ...p, enabled: checked } : p);
    setSavingsPlans(updated);
    saveWithOverrides(undefined, undefined, undefined, undefined, undefined, updated);
  };

  const handleDelete = (id: string) => {
    const msg = settings.language === 'pt' ? 'Excluir este plano de poupança?' : 'Delete this savings plan?';
    if (!confirm(msg)) return;
    const updated = savingsPlans.filter((p) => p.id !== id);
    setSavingsPlans(updated);
    saveWithOverrides(undefined, undefined, undefined, undefined, undefined, updated);
  };

  const freqLabel = (f: string) => f === 'Monthly' ? t('monthly') : f === 'BiWeekly' ? t('biweekly') : t('weekly');

  return (
    <div className="space-y-6">
      {savingsPlans.length === 0 ? (
        <section className="dd-surface rounded-2xl shadow-sm">
          <EmptyState
            icon={
              <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                <path d="M19 21V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v16"/><path d="M3 21h18"/><path d="M12 7v7"/><path d="M9 10l3-3 3 3"/>
              </svg>
            }
            title={t('no_savings_title')}
            description={t('no_savings_desc')}
            cta={{ label: t('add_first_savings'), onClick: () => { setEditing(null); setOpen(true); } }}
            suggestions={[t('sugg_emergency'), t('sugg_vacation'), t('sugg_house'), t('sugg_car')]}
          />
        </section>
      ) : (
        <>
          <section className="grid grid-cols-2 gap-4 text-center">
            <div className="dd-surface p-4 rounded-2xl shadow-sm">
              <h3 className="text-xs font-semibold dd-text-3">{t('total_saved')}</h3>
              <p className="text-2xl font-bold text-[var(--brand-neon)] mt-1">{fmt(totalSaved)}</p>
            </div>
            <div className="dd-surface p-4 rounded-2xl shadow-sm">
              <h3 className="text-xs font-semibold dd-text-3">{t('total_goal')}</h3>
              <p className="text-2xl font-bold text-blue-600 mt-1">{totalGoals > 0 ? fmt(totalGoals) : '—'}</p>
            </div>
          </section>

          {totalGoals > 0 && (
            <section className="dd-surface p-4 rounded-2xl shadow-sm">
              <div className="flex justify-between items-center mb-2">
                <span className="text-sm font-medium dd-text-2">{t('overall_progress')}</span>
                <span className="text-sm font-bold text-[var(--brand-neon)]">{Math.min(100, Math.round((totalSaved / totalGoals) * 100))}%</span>
              </div>
              <div className="w-full dd-surface-2 rounded-full h-3">
                <div className="bg-[var(--brand-neon)] h-3 rounded-full transition-all" style={{ width: `${Math.min(100, (totalSaved / totalGoals) * 100)}%` }} />
              </div>
            </section>
          )}

          <section className="dd-surface p-6 rounded-2xl shadow-sm">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold dd-text">{t('savings_plans')}</h2>
              <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-[var(--fg-1)] text-white rounded-xl hover:bg-[var(--brand-neon)] font-semibold text-sm">
                + {t('add')}
              </button>
            </div>

            <div className="space-y-4">
              {savingsPlans.map((plan) => {
                const saved = perPlanSaved[plan.name] || 0;
                const goalPct = plan.goalAmount ? Math.min(100, (saved / plan.goalAmount) * 100) : null;
                return (
                  <div key={plan.id} className={`p-4 rounded-xl border border-[var(--line)] dark:border-[var(--line)] dd-surface shadow-sm hover:shadow-md transition ${!plan.enabled ? 'opacity-50' : ''}`}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center min-w-0 mr-3">
                        <div className="flex-shrink-0 w-3 h-3 rounded-full mr-3 bg-[var(--brand-neon)]" />
                        <p className="font-semibold dd-text truncate">{plan.name}</p>
                      </div>
                      <div className="relative inline-block w-12 h-7 flex-shrink-0 select-none">
                        <input type="checkbox" id={`sav-tog-${plan.id}`} checked={plan.enabled} onChange={(e) => handleToggle(plan.id, e.target.checked)}
                          className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
                        <label htmlFor={`sav-tog-${plan.id}`} className="toggle-label block overflow-hidden h-7 rounded-full bg-gray-300 cursor-pointer" />
                      </div>
                    </div>
                    <div className="flex items-center justify-between mb-2">
                      <p className="text-sm dd-text-3">{freqLabel(plan.frequency)} · {fmt(plan.amount)}</p>
                      <div className="flex items-center space-x-2">
                        <p className="font-bold text-base text-[var(--brand-neon)]">{fmt(saved)}</p>
                        <button onClick={() => { setEditing(plan); setOpen(true); }} className="p-2 text-gray-400 hover:text-ios-blue rounded-full hover:bg-gray-100 dark:hover:bg-gray-600">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                        </button>
                        <button onClick={() => handleDelete(plan.id)} className="p-2 text-gray-400 hover:text-[var(--negative)] rounded-full hover:bg-gray-100 dark:hover:bg-gray-600">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                        </button>
                      </div>
                    </div>
                    {goalPct !== null && plan.goalAmount && (
                      <div>
                        <div className="flex justify-between text-xs dd-text-3 mb-1">
                          <span>{fmt(saved)}</span>
                          <span>{t('goal')}: {fmt(plan.goalAmount)}</span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                          <div className="bg-[var(--brand-neon)] h-2 rounded-full transition-all" style={{ width: `${goalPct}%` }} />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        </>
      )}

      <SavingsModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </div>
  );
}
