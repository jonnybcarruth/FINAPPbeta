'use client';

import { useApp } from '@/context/AppContext';
import { calculateTotalWeeks } from '@/lib/finance';
import { PLAN_DEFINITIONS, computePlanBreakdown, applyPlan } from '@/lib/spendingPlan';

export default function SpendingPlanView() {
  const { metrics, settings, setSettings,
    activeSpendingCategories, setActiveSpendingCategories,
    oneTimeTransactions, setOneTimeTransactions, saveWithOverrides } = useApp();

  const totalSavings = metrics.endBalance - metrics.startingBalance;
  const totalWeeks = calculateTotalWeeks(settings.startDate, settings.projectionMonths);
  const sliderMax = Math.max(0, Math.floor(totalSavings / 100) * 100);
  const savedAmount = Math.min(settings.savedAmount, sliderMax);
  const remainingBudget = totalSavings - savedAmount;
  const baseWeekly = remainingBudget > 0 ? remainingBudget / totalWeeks : 0;
  const pct = sliderMax > 0 ? (savedAmount / sliderMax) * 100 : 0;

  const handleSlider = (v: number) => {
    const newSettings = { ...settings, savedAmount: v };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
  };

  const handleCategoryToggle = (name: string, checked: boolean) => {
    const newCats = activeSpendingCategories.map((c) => c.name === name ? { ...c, enabled: checked } : c);
    setActiveSpendingCategories(newCats);
    saveWithOverrides(undefined, undefined, undefined, newCats, undefined);
  };

  const handleApplyPlan = (planName: string, margin: number) => {
    if (!confirm(`Apply the ${planName} and clear existing planned weekly budgets?`)) return;
    const breakdown = computePlanBreakdown(activeSpendingCategories, baseWeekly, margin);
    const updated = applyPlan(breakdown, planName, settings.startDate, settings.projectionMonths, oneTimeTransactions);
    setOneTimeTransactions(updated);
    saveWithOverrides(undefined, updated, undefined, undefined, undefined);
  };

  const handleDeletePlan = () => {
    if (!confirm('Delete all (Planned) transactions?')) return;
    const filtered = oneTimeTransactions.filter((t) => !t.name.includes('(Planned)'));
    setOneTimeTransactions(filtered);
    saveWithOverrides(undefined, filtered, undefined, undefined, undefined);
  };

  const fmt = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <div className="space-y-6">
      <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100 mb-4">Projected Surplus Analysis</h2>
        <div className="grid grid-cols-2 gap-4 text-center">
          <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <p className="text-sm text-gray-500">Projected Savings</p>
            <p className="text-2xl font-bold text-green-700 mt-1">{fmt(totalSavings)}</p>
          </div>
          <div className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <p className="text-sm text-gray-500">Available Weekly Spending</p>
            <p className="text-2xl font-bold text-blue-700 mt-1">{fmt(baseWeekly)}</p>
          </div>
        </div>
      </section>

      <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm space-y-6">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Savings Target</h2>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Commit to Savings: <span className="font-bold text-xl text-green-700">{fmt(savedAmount)}</span>
          </label>
          <input type="range" min="0" max={sliderMax} value={savedAmount} step="10"
            style={{ ['--slider-progress' as string]: `${pct}%` }}
            onChange={(e) => handleSlider(parseFloat(e.target.value))}
            className="w-full h-2 rounded-lg appearance-none cursor-pointer" />
        </div>
        <div>
          <p className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">Spending Categories</p>
          <div className="space-y-2">
            {activeSpendingCategories.map((cat) => (
              <label key={cat.name} className="flex items-center space-x-3 p-3 bg-gray-100 dark:bg-gray-700 rounded-lg cursor-pointer">
                <input type="checkbox" checked={cat.enabled} onChange={(e) => handleCategoryToggle(cat.name, e.target.checked)} className="w-5 h-5 text-blue-600 rounded" />
                <span className="text-sm font-medium text-gray-900 dark:text-gray-100 flex-grow">
                  {cat.name} <span className="text-xs text-gray-500">{cat.fixedWeeklyAmount > 0 ? `($${cat.fixedWeeklyAmount}/wk fixed)` : `(${cat.percentage}%)`}</span>
                </span>
              </label>
            ))}
          </div>
        </div>
      </section>

      <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Spending Plans</h2>
          <button onClick={handleDeletePlan} className="px-3 py-1 text-sm bg-red-50 text-ios-red rounded-lg hover:bg-red-100 font-medium">Delete Plan</button>
        </div>
        {remainingBudget <= 0 ? (
          <p className="text-red-500 p-4 bg-red-100 rounded-lg">Savings goal exceeds surplus — no budget available.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {PLAN_DEFINITIONS.map((plan) => {
              const bd = computePlanBreakdown(activeSpendingCategories, baseWeekly, plan.margin);
              const totalAlloc = bd.reduce((s, c) => s + c.amount, 0);
              return (
                <div key={plan.name} className="bg-gray-50 dark:bg-gray-700 p-4 rounded-xl border border-gray-200 dark:border-gray-600">
                  <h3 className="text-base font-bold text-gray-800 dark:text-gray-100 mb-2">{plan.name}</h3>
                  <p className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                    {fmt(totalAlloc)}/week
                  </p>
                  <ul className="space-y-1 mb-4 text-sm">
                    {bd.filter((c) => c.amount > 0.01).map((c) => (
                      <li key={c.name} className="flex justify-between text-gray-700 dark:text-gray-300">
                        <span>{c.name}:</span>
                        <span className="font-medium text-red-600">{fmt(c.amount)}</span>
                      </li>
                    ))}
                  </ul>
                  <button onClick={() => handleApplyPlan(plan.name, plan.margin)} className={`w-full py-2 text-white font-semibold rounded-lg ${plan.buttonClass}`}>
                    Select Plan
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
