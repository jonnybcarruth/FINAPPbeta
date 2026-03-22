'use client';

import { useState } from 'react';
import { format } from 'date-fns';
import { useApp } from '@/context/AppContext';

export default function TransactionLogView() {
  const { projections } = useApp();
  const [filter, setFilter] = useState<'all' | 'income' | 'expense'>('all');

  const filtered = projections.filter((p) => {
    if (filter === 'income') return p.amount > 0;
    if (filter === 'expense') return p.amount < 0;
    return true;
  });

  const typeLabel = (t: typeof projections[0]) => {
    if (t.type === 'Debt Payment') return 'Debt';
    if (t.type === 'One-Time') return t.name.includes('(Planned)') ? 'PLAN' : 'One-Time';
    return 'Recurring';
  };

  const amtClass = (t: typeof projections[0]) => {
    if (t.type === 'Debt Payment') return 'text-pink-600';
    return t.amount > 0 ? 'text-green-600' : 'text-red-600';
  };

  return (
    <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">Transaction Log</h2>
        <select value={filter} onChange={(e) => setFilter(e.target.value as typeof filter)} className="p-2 border border-gray-300 rounded-lg text-sm dark:bg-gray-700 dark:text-white dark:border-gray-600">
          <option value="all">All Transactions</option>
          <option value="income">Income Only</option>
          <option value="expense">Expenses Only</option>
        </select>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Amount</th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-100 dark:divide-gray-700">
            {filtered.length === 0 && (
              <tr><td colSpan={3} className="text-center py-8 text-gray-500">No transactions for this period.</td></tr>
            )}
            {filtered.map((p, i) => (
              <tr key={i} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-800 dark:text-gray-200">{format(p.date, 'MMM dd, yyyy')}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-800 dark:text-gray-200">
                  {p.name} <span className="text-xs text-gray-400">({typeLabel(p)})</span>
                </td>
                <td className={`px-6 py-4 whitespace-nowrap text-sm text-right font-medium ${amtClass(p)}`}>
                  {p.amount.toLocaleString('en-US', { style: 'currency', currency: 'USD' })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
