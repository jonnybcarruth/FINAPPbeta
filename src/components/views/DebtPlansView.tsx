'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import DebtPlanModal from '../modals/DebtPlanModal';
import EmptyState from '../EmptyState';
import type { DebtPlan } from '@/lib/types';
import { useT, useFmt } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

export default function DebtPlansView() {
  const { debtPlans, setDebtPlans, saveWithOverrides, settings } = useApp();
  const t = useT();
  const fmt = useFmt();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DebtPlan | null>(null);

  const handleSave = (plan: DebtPlan) => {
    const idx = debtPlans.findIndex((p) => p.id === plan.id);
    const updated = idx >= 0 ? debtPlans.map((p) => (p.id === plan.id ? plan : p)) : [...debtPlans, plan];
    setDebtPlans(updated);
    setOpen(false);
    saveWithOverrides(undefined, undefined, updated, undefined, undefined);
  };

  const handleToggle = (id: string, checked: boolean) => {
    void hapticLight();
    const updated = debtPlans.map((p) => p.id === id ? { ...p, enabled: checked } : p);
    setDebtPlans(updated);
    saveWithOverrides(undefined, undefined, updated, undefined, undefined);
  };

  const handleDelete = (id: string) => {
    const msg = settings.language === 'pt' ? 'Excluir este plano de dívida?' : 'Delete this debt plan?';
    if (!confirm(msg)) return;
    const updated = debtPlans.filter((p) => p.id !== id);
    setDebtPlans(updated);
    saveWithOverrides(undefined, undefined, updated, undefined, undefined);
  };

  return (
    <section className="dd-surface p-6 rounded-2xl shadow-sm">
      {debtPlans.length === 0 ? (
        <EmptyState
          icon={
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              <rect x="1" y="5" width="22" height="14" rx="2.5"/><line x1="1" y1="10" x2="23" y2="10"/><line x1="6" y1="15" x2="9" y2="15"/><line x1="12" y1="15" x2="15" y2="15"/>
            </svg>
          }
          title={t('no_debt_title')}
          description={t('no_debt_desc')}
          cta={{ label: t('add_first_debt'), onClick: () => { setEditing(null); setOpen(true); } }}
          suggestions={[t('sugg_credit_card'), t('sugg_student_loan'), t('sugg_car')]}
        />
      ) : (
        <>
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-bold dd-text">{t('debt_plan_management')}</h2>
            <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
              + {t('add')}
            </button>
          </div>

          <div className="space-y-4">
            {debtPlans.map((plan) => (
              <div key={plan.id} className={`p-4 rounded-xl border border-[var(--line)] dark:border-[var(--line)] dd-surface shadow-sm hover:shadow-md transition ${!plan.enabled ? 'opacity-50' : ''}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center min-w-0 mr-3">
                    <div className="flex-shrink-0 w-3 h-3 rounded-full mr-3 bg-[var(--fg-3)]" />
                    <p className="font-semibold dd-text truncate">{plan.name}</p>
                  </div>
                  <div className="relative inline-block w-12 h-7 flex-shrink-0 select-none">
                    <input type="checkbox" id={`debt-tog-${plan.id}`} checked={plan.enabled} onChange={(e) => handleToggle(plan.id, e.target.checked)}
                      className="toggle-checkbox absolute block w-6 h-6 rounded-full bg-white border-4 appearance-none cursor-pointer" />
                    <label htmlFor={`debt-tog-${plan.id}`} className="toggle-label block overflow-hidden h-7 rounded-full bg-gray-300 cursor-pointer" />
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <p className="text-sm dd-text-3">{fmt(plan.totalAmount)} · {plan.payoffMonths} {t('months')}</p>
                  <div className="flex items-center space-x-2">
                    <p className="font-bold text-base text-[var(--fg-3)]">{fmt(plan.totalAmount / plan.payoffMonths)}{t('per_month')}</p>
                    <button onClick={() => { setEditing(plan); setOpen(true); }} className="p-2 text-gray-400 hover:text-ios-blue rounded-full hover:bg-gray-100 dark:hover:bg-gray-600">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    </button>
                    <button onClick={() => handleDelete(plan.id)} className="p-2 text-gray-400 hover:text-[var(--negative)] rounded-full hover:bg-gray-100 dark:hover:bg-gray-600">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <DebtPlanModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </section>
  );
}
