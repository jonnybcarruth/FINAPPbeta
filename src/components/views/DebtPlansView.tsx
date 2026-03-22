'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import DebtPlanModal from '../modals/DebtPlanModal';
import type { DebtPlan } from '@/lib/types';

export default function DebtPlansView() {
  const { debtPlans, setDebtPlans, saveAndRefresh } = useApp();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<DebtPlan | null>(null);

  const handleSave = (plan: DebtPlan) => {
    const idx = debtPlans.findIndex((p) => p.id === plan.id);
    const updated = idx >= 0 ? debtPlans.map((p) => (p.id === plan.id ? plan : p)) : [...debtPlans, plan];
    setDebtPlans(updated);
    setOpen(false);
    setTimeout(saveAndRefresh, 0);
  };

  const handleDelete = (id: string) => {
    if (!confirm('Delete this debt plan?')) return;
    setDebtPlans(debtPlans.filter((p) => p.id !== id));
    setTimeout(saveAndRefresh, 0);
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Debt Plan Management</h2>
        <button onClick={() => { setEditing(null); setOpen(true); }} className="px-4 py-2 bg-pink-600 text-white rounded-lg hover:bg-pink-700 font-semibold">
          Add New Debt Plan
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
              <button onClick={() => { setEditing(plan); setOpen(true); }} className="p-2 text-gray-400 hover:text-pink-600 rounded-full hover:bg-gray-100">✏️</button>
              <button onClick={() => handleDelete(plan.id)} className="p-2 text-gray-400 hover:text-red-600 rounded-full hover:bg-gray-100">🗑️</button>
            </div>
          </div>
        ))}
      </div>

      <DebtPlanModal open={open} onClose={() => setOpen(false)} onSave={handleSave} initial={editing} />
    </section>
  );
}
