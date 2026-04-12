'use client';

import { useEffect, useRef, useState } from 'react';
import { Chart, registerables, type Point } from 'chart.js';
import 'chartjs-adapter-date-fns';
import { format } from 'date-fns';
import { useApp } from '@/context/AppContext';

Chart.register(...registerables);

export default function DashboardView() {
  const { metrics, projections, settings } = useApp();
  const cashFlowRef = useRef<HTMLCanvasElement>(null);
  const monthlyNetRef = useRef<HTMLCanvasElement>(null);
  const incExpRef = useRef<HTMLCanvasElement>(null);
  const categoryRef = useRef<HTMLCanvasElement>(null);
  const cashChart = useRef<Chart<'line', Point[]> | null>(null);
  const netChart = useRef<Chart<'bar', number[]> | null>(null);
  const incExpChart = useRef<Chart<'doughnut', number[]> | null>(null);
  const catChart = useRef<Chart<'bar', number[]> | null>(null);
  const isDark = () => document.documentElement.classList.contains('dark');

  const [minBalance, setMinBalance] = useState(0);
  const [minBalanceDate, setMinBalanceDate] = useState('');
  const [avgMonthlyIncome, setAvgMonthlyIncome] = useState(0);
  const [totalSaved, setTotalSaved] = useState(0);
  const [avgMonthlyExpenses, setAvgMonthlyExpenses] = useState(0);

  // Compute extra stats
  useEffect(() => {
    let min = settings.startingBalance;
    let minDate = settings.startDate;
    let balCents = Math.round(settings.startingBalance * 100);
    projections.forEach((p) => {
      balCents += Math.round(p.amount * 100);
      const bal = balCents / 100;
      if (bal < min) { min = bal; minDate = format(p.date, 'MMM d, yyyy'); }
    });
    setMinBalance(min);
    setMinBalanceDate(minDate);

    const saved = projections.filter((p) => p.type === 'Savings').reduce((s, p) => s + Math.abs(p.amount), 0);
    setTotalSaved(saved);

    const months: Record<string, { inc: number; exp: number }> = {};
    projections.forEach((p) => {
      const m = format(p.date, 'yyyy-MM');
      if (!months[m]) months[m] = { inc: 0, exp: 0 };
      if (p.amount > 0) months[m].inc += p.amount;
      else months[m].exp += Math.abs(p.amount);
    });
    const mKeys = Object.keys(months);
    if (mKeys.length > 0) {
      setAvgMonthlyIncome(mKeys.reduce((s, k) => s + months[k].inc, 0) / mKeys.length);
      setAvgMonthlyExpenses(mKeys.reduce((s, k) => s + months[k].exp, 0) / mKeys.length);
    }
  }, [projections, settings]);

  // Cash flow line chart
  useEffect(() => {
    if (!cashFlowRef.current) return;
    cashChart.current?.destroy();
    let balCents = Math.round(settings.startingBalance * 100);
    const dataPoints: Point[] = [{ x: new Date(settings.startDate + 'T00:00:00').getTime(), y: balCents / 100 }];
    projections.forEach((p) => { balCents += Math.round(p.amount * 100); dataPoints.push({ x: p.date.getTime(), y: balCents / 100 }); });

    cashChart.current = new Chart<'line', Point[]>(cashFlowRef.current, {
      type: 'line',
      data: {
        datasets: [{
          label: 'Projected Balance',
          data: dataPoints,
          borderColor: isDark() ? '#4CAF50' : '#3B82F6',
          backgroundColor: isDark() ? 'rgba(76,175,80,0.2)' : 'rgba(59,130,246,0.1)',
          fill: true, tension: 0.1, pointRadius: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { labels: { color: '#6B7280' } },
          tooltip: { callbacks: { label: (ctx) => `Balance: $${Number(ctx.parsed.y).toLocaleString()}` } },
        },
        scales: {
          x: { type: 'time', time: { unit: 'month' }, ticks: { color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.15)' } },
          y: { ticks: { callback: (v) => `$${Number(v).toLocaleString()}`, color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.15)' } },
        },
      },
    });
    return () => cashChart.current?.destroy();
  }, [projections, settings]);

  // Monthly net bar chart
  useEffect(() => {
    if (!monthlyNetRef.current) return;
    netChart.current?.destroy();
    const monthly: Record<string, number> = {};
    projections.forEach((p) => { const m = format(p.date, 'yyyy-MM'); monthly[m] = (monthly[m] || 0) + p.amount; });
    const labels = Object.keys(monthly).sort();
    const data = labels.map((l) => Math.round(monthly[l] * 100) / 100);

    netChart.current = new Chart(monthlyNetRef.current, {
      type: 'bar',
      data: {
        labels: labels.map((l) => format(new Date(l + '-02T00:00:00'), 'MMM yyyy')),
        datasets: [{
          label: 'Net Monthly Flow',
          data,
          backgroundColor: data.map((v) => v >= 0 ? 'rgba(76,175,80,0.8)' : 'rgba(220,38,38,0.7)'),
          borderColor: data.map((v) => v >= 0 ? '#4CAF50' : '#DC2626'),
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { labels: { color: '#6B7280' } },
          tooltip: { callbacks: { label: (ctx) => `Net: $${Number(ctx.parsed.y).toLocaleString()}` } },
        },
        scales: {
          x: { ticks: { color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.15)' } },
          y: { ticks: { callback: (v) => `$${Number(v).toLocaleString()}`, color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.15)' } },
        },
      },
    });
    return () => netChart.current?.destroy();
  }, [projections]);

  // Income vs Expenses doughnut
  useEffect(() => {
    if (!incExpRef.current) return;
    incExpChart.current?.destroy();
    incExpChart.current = new Chart(incExpRef.current, {
      type: 'doughnut',
      data: {
        labels: ['Income', 'Expenses'],
        datasets: [{
          data: [metrics.totalIncome, Math.abs(metrics.totalExpenses)],
          backgroundColor: ['rgba(76,175,80,0.85)', 'rgba(220,38,38,0.75)'],
          borderColor: ['#4CAF50', '#DC2626'],
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '60%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#6B7280', padding: 16 } },
          tooltip: { callbacks: { label: (ctx) => `${ctx.label}: $${Number(ctx.parsed).toLocaleString()}` } },
        },
      },
    });
    return () => incExpChart.current?.destroy();
  }, [metrics]);

  // Expense category breakdown bar
  useEffect(() => {
    if (!categoryRef.current) return;
    catChart.current?.destroy();
    const cats: Record<string, number> = {};
    projections.forEach((p) => {
      if (p.amount < 0) {
        const label = p.type === 'Debt Payment' ? 'Debt Payments' : p.name.replace(' (Planned)', '');
        cats[label] = (cats[label] || 0) + Math.abs(p.amount);
      }
    });
    const sorted = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const colors = ['#3B82F6', '#8B5CF6', '#EC4899', '#F97316', '#EAB308', '#14B8A6', '#6366F1', '#78716C'];

    catChart.current = new Chart(categoryRef.current, {
      type: 'bar',
      data: {
        labels: sorted.map(([k]) => k.length > 18 ? k.slice(0, 16) + '…' : k),
        datasets: [{
          label: 'Total Spent',
          data: sorted.map(([, v]) => Math.round(v * 100) / 100),
          backgroundColor: sorted.map((_, i) => colors[i % colors.length]),
          borderWidth: 0,
          borderRadius: 6,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (ctx) => `$${Number(ctx.parsed.x).toLocaleString()}` } },
        },
        scales: {
          x: { ticks: { callback: (v) => `$${Number(v).toLocaleString()}`, color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.15)' } },
          y: { ticks: { color: '#6B7280' }, grid: { display: false } },
        },
      },
    });
    return () => catChart.current?.destroy();
  }, [projections]);

  const fmt = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <div className="space-y-6">
      {/* Stat cards - top row */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500">End Balance</h3>
          <p className={`text-xl font-bold mt-1 ${metrics.endBalance >= 0 ? 'text-gray-800 dark:text-gray-100' : 'text-red-600'}`}>{fmt(metrics.endBalance)}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500">Total Income</h3>
          <p className="text-xl font-bold text-green-600 mt-1">{fmt(metrics.totalIncome)}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500">Total Expenses</h3>
          <p className="text-xl font-bold text-red-600 mt-1">{fmt(Math.abs(metrics.totalExpenses))}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500">Net Savings</h3>
          <p className={`text-xl font-bold mt-1 ${metrics.totalIncome + metrics.totalExpenses >= 0 ? 'text-green-600' : 'text-red-600'}`}>
            {fmt(metrics.totalIncome + metrics.totalExpenses)}
          </p>
        </div>
      </section>

      {/* Secondary stats */}
      <section className="grid grid-cols-2 md:grid-cols-3 gap-4 text-center">
        {totalSaved > 0 && (
          <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm col-span-2 md:col-span-1">
            <h3 className="text-xs font-semibold text-gray-500">Total Saved</h3>
            <p className="text-lg font-bold text-emerald-600 mt-1">{fmt(totalSaved)}</p>
          </div>
        )}
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500">Lowest Balance</h3>
          <p className={`text-lg font-bold mt-1 ${minBalance < 0 ? 'text-red-600' : 'text-gray-800 dark:text-gray-100'}`}>{fmt(minBalance)}</p>
          <p className="text-xs text-gray-400 mt-0.5">{minBalanceDate}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500">Avg Monthly Income</h3>
          <p className="text-lg font-bold text-green-600 mt-1">{fmt(avgMonthlyIncome)}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-4 rounded-2xl shadow-sm col-span-2 md:col-span-1">
          <h3 className="text-xs font-semibold text-gray-500">Avg Monthly Expenses</h3>
          <p className="text-lg font-bold text-red-600 mt-1">{fmt(avgMonthlyExpenses)}</p>
        </div>
      </section>

      {/* Negative balance warning */}
      {minBalance < 0 && (
        <div className="bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded-2xl p-4 flex items-start space-x-3">
          <span className="text-red-600 text-xl flex-shrink-0">!</span>
          <div>
            <p className="text-sm font-semibold text-red-700 dark:text-red-300">Projected negative balance</p>
            <p className="text-xs text-red-600 dark:text-red-400">Your balance is projected to drop to {fmt(minBalance)} on {minBalanceDate}. Consider adjusting income or expenses.</p>
          </div>
        </div>
      )}

      {/* Cash flow chart */}
      <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
        <h2 className="text-lg font-bold text-gray-800 dark:text-gray-100 mb-4">Cash Flow Projection</h2>
        <div className="chart-container"><canvas ref={cashFlowRef} /></div>
      </section>

      {/* Income vs Expenses doughnut + category breakdown side by side on desktop */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
          <h2 className="text-lg font-bold text-gray-800 dark:text-gray-100 mb-4">Income vs Expenses</h2>
          <div className="chart-container-sm"><canvas ref={incExpRef} /></div>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
          <h2 className="text-lg font-bold text-gray-800 dark:text-gray-100 mb-4">Top Expenses</h2>
          <div className="chart-container-sm"><canvas ref={categoryRef} /></div>
        </div>
      </section>

      {/* Monthly net flow */}
      <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
        <h2 className="text-lg font-bold text-gray-800 dark:text-gray-100 mb-4">Net Monthly Flow</h2>
        <div className="chart-container"><canvas ref={monthlyNetRef} /></div>
      </section>
    </div>
  );
}
