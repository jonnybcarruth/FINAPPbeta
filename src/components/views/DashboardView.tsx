'use client';

import { useEffect, useRef } from 'react';
import { Chart, registerables, type Point } from 'chart.js';
import 'chartjs-adapter-date-fns';
import { format } from 'date-fns';
import { useApp } from '@/context/AppContext';

Chart.register(...registerables);

export default function DashboardView() {
  const { metrics, projections, settings } = useApp();
  const cashFlowRef = useRef<HTMLCanvasElement>(null);
  const monthlyNetRef = useRef<HTMLCanvasElement>(null);
  const cashChart = useRef<Chart<'line', Point[]> | null>(null);
  const netChart = useRef<Chart<'bar', number[]> | null>(null);
  const isDark = () => document.documentElement.classList.contains('dark');

  useEffect(() => {
    if (!cashFlowRef.current) return;
    cashChart.current?.destroy();

    let bal = Math.round(settings.startingBalance * 100);
    const dataPoints: Point[] = [{ x: new Date(settings.startDate + 'T00:00:00').getTime(), y: bal / 100 }];
    projections.forEach((p) => { bal += Math.round(p.amount * 100); dataPoints.push({ x: p.date.getTime(), y: bal / 100 }); });

    cashChart.current = new Chart<'line', Point[]>(cashFlowRef.current, {
      type: 'line',
      data: {
        datasets: [{
          label: 'Projected Balance',
          data: dataPoints,
          borderColor: isDark() ? '#4CAF50' : '#3B82F6',
          backgroundColor: isDark() ? 'rgba(76,175,80,0.2)' : 'rgba(59,130,246,0.1)',
          fill: true, tension: 0.1, pointRadius: 3,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { type: 'time', time: { unit: 'month' }, ticks: { color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.2)' } },
          y: { ticks: { callback: (v) => `$${Number(v).toLocaleString()}`, color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.2)' } },
        },
        plugins: { legend: { labels: { color: '#6B7280' } } },
      },
    });
    return () => cashChart.current?.destroy();
  }, [projections, settings]);

  useEffect(() => {
    if (!monthlyNetRef.current) return;
    netChart.current?.destroy();

    const monthly: Record<string, number> = {};
    projections.forEach((p) => {
      const m = format(p.date, 'yyyy-MM');
      monthly[m] = (monthly[m] || 0) + p.amount;
    });
    const labels = Object.keys(monthly).sort();
    const data = labels.map((l) => monthly[l]);

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
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.2)' } },
          y: { ticks: { callback: (v) => `$${Number(v).toLocaleString()}`, color: '#6B7280' }, grid: { color: 'rgba(100,100,100,0.2)' } },
        },
        plugins: { legend: { labels: { color: '#6B7280' } } },
      },
    });
    return () => netChart.current?.destroy();
  }, [projections]);

  const fmt = (n: number) => n.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
          <h3 className="text-sm font-semibold text-gray-500">Projected End Balance</h3>
          <p className="text-3xl font-bold text-gray-800 dark:text-gray-100 mt-2">{fmt(metrics.endBalance)}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
          <h3 className="text-sm font-semibold text-gray-500">Total Income</h3>
          <p className="text-3xl font-bold text-green-600 mt-2">{fmt(metrics.totalIncome)}</p>
        </div>
        <div className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm">
          <h3 className="text-sm font-semibold text-gray-500">Total Expenses</h3>
          <p className="text-3xl font-bold text-red-600 mt-2">{fmt(Math.abs(metrics.totalExpenses))}</p>
        </div>
      </section>
      <section className="bg-white dark:bg-gray-800 p-6 rounded-2xl shadow-sm space-y-10">
        <div>
          <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100 mb-4 text-center">Cash Flow Projection</h2>
          <div className="chart-container"><canvas ref={cashFlowRef} /></div>
        </div>
        <div>
          <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100 mb-4 text-center">Net Monthly Flow</h2>
          <div className="chart-container"><canvas ref={monthlyNetRef} /></div>
        </div>
      </section>
    </div>
  );
}
