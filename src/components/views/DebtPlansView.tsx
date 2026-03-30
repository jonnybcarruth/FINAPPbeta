'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import DebtPlanModal from '../modals/DebtPlanModal';
import type { DebtPlan } from '@/lib/types';

export default function DebtPlansView() {
  const { debtPlans, setDebtPlans, saveWithOverrides } = useApp();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DebtPlan | null>(null);

  const handleSave = (plan: DebtPlan) => {
    const idx = debtPlans.findIndex((p) => p.id === plan.id);
    const updated = idx >= 0 ? debtPlans.map((p) => (p.id === plan.id ? plan : p)) : [...debtPlans, plan];
    setDebtPlans(updated);
    setOpen(false);
    saveWithOverrides(undefined, undefined, updated, undefined, undefined);
  };

  const handleDelete = (id: string) => {
    if (!confirm('Delete this debt plan?')) return;
    const updated = debtPlans.filter((p) => p.id !== id);
    setDebtPlans(updated);
    saveWithOverrides(undefined, undefined, updated, undefined, undefined);
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Debt Plan Management</h2>
        <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
          Add Debt Plan
        </button>
      </div>
      <p className="text-gray-500 mb-6 text-sm">Define structured debt repayments. Payments are calculated based on the payoff period.</p>

      <div className="space-y-4">
        {debtPlans.length === 0 && <p className="text-center text-gray-400 italic py-8">No debt plans yet.</p>}
        {debtPlans.map((plan) => (
          <div key={plan.id} className="flex items-center justify-between p-4 rounded-xl border border-pink-200 bg-white dark:bg-gray-700 shadow-sm hover:shadow-md transition">
            <div className="flex items-center min-w-0">
              <div className="flex-shrink-0 w-3 h-3 rounded-full mr-4 bg-pink-500" />
              <div className="min-w-0">
                <p className="font-semibold text-gray-800 dark:text-gray-100 truncate">{plan.name}</p>
                <p className="text-sm text-gray-500">Total: ${plan.totalAmount.toLocaleString()} | {plan.payoffMonths} months</p>
              </div>
            </div>
            <div className="flex items-center space-x-3 flex-shrink-0 ml-4">
              <p className="font-bold text-lg text-pink-600">${(plan.totalAmount / plan.payoffMonths).toFixed(2)}/mo</p>
              <button onClick={() => { setEditing(plan); setOpen(true); }} className="p-2 text-ios-gray hover:text-ios-blue rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
              </button>
              <button onClick={() => handleDelete(plan.id)} className="p-2 text-ios-gray hover:text-ios-red rounded-full hover:bg-gray-100 dark:hover:bg-gray-700">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      <DebtPlanModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </section>
  );
}
