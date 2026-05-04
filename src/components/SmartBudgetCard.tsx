'use client';

import { useState, useMemo } from 'react';
import { format } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useApp } from '@/context/AppContext';
import { computeWeeklyBudget } from '@/lib/finance';
import { useT, useFmt, useLocale } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

export default function SmartBudgetCard() {
  const { projections, dailyBalanceMap, settings, activeSpendingCategories } = useApp();
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const [expanded, setExpanded] = useState(false);

  const budget = useMemo(
    () => computeWeeklyBudget(projections, settings.startingBalance, dailyBalanceMap, settings.startDate),
    [projections, dailyBalanceMap, settings]
  );

  // Compute suggested split from enabled spending categories
  const splits = useMemo(() => {
    const enabled = activeSpendingCategories.filter((c) => c.enabled);
    const totalFixed = enabled.filter((c) => c.fixedWeeklyAmount > 0).reduce((s, c) => s + c.fixedWeeklyAmount, 0);
    const varCats = enabled.filter((c) => c.fixedWeeklyAmount === 0);
    const totalPct = varCats.reduce((s, c) => s + c.percentage, 0);
    const varBudget = Math.max(0, budget.safeToSpend - totalFixed);

    return enabled
      .map((cat) => {
        let amount: number;
        if (cat.fixedWeeklyAmount > 0) amount = Math.min(cat.fixedWeeklyAmount, budget.safeToSpend);
        else if (totalPct > 0) amount = (varBudget * cat.percentage) / totalPct;
        else amount = 0;
        return { name: cat.name, amount: Math.max(0, amount) };
      })
      .filter((c) => c.amount > 0.01);
  }, [activeSpendingCategories, budget.safeToSpend]);

  // If they have no meaningful data, show empty state
  if (budget.incomeThisWeek === 0 && budget.billsThisWeek === 0 && budget.balanceToday <= 0) {
    return (
      <section className="bg-white dark:bg-gray-800 p-5 rounded-2xl shadow-sm">
        <div className="flex items-center space-x-2 mb-2">
          <span className="text-xl">💡</span>
          <h3 className="text-base font-bold text-gray-800 dark:text-gray-100">{t('smart_budget')}</h3>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400">{t('no_budget_data')}</p>
      </section>
    );
  }

  const categoryIcon = (name: string): string => {
    const n = name.toLowerCase();
    if (n.includes('groc') || n.includes('alim')) return '🛒';
    if (n.includes('gas') || n.includes('fuel') || n.includes('combust')) return '⛽';
    if (n.includes('transport')) return '🚗';
    return '📌';
  };

  return (
    <section className="dd-card" style={{ padding: 20, background: 'var(--surface)', border: '1px solid var(--line)' }}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <span className="text-xl">💡</span>
          <h3 className="text-sm font-bold text-gray-800 dark:text-gray-100">{t('smart_budget')}</h3>
        </div>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          {format(budget.weekStart, 'MMM d', { locale: dateLocale })} – {format(budget.weekEnd, 'MMM d', { locale: dateLocale })}
        </span>
      </div>

      {/* Hero amount */}
      <div className="mb-4">
        <p className="text-xs font-medium text-gray-600 dark:text-gray-300 mb-1">{t('you_can_spend')}</p>
        <p style={{ fontFamily: 'var(--font-display)', fontSize: 36, fontWeight: 500, letterSpacing: '-0.02em', color: 'var(--fg-1)' }}>{fmt(budget.safeToSpend)}</p>
      </div>

      {/* Suggested category split */}
      {splits.length > 0 && budget.safeToSpend > 0 && (
        <div className="space-y-2 mb-4">
          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">{t('suggested_split')}</p>
          {splits.map((s) => {
            const pct = budget.safeToSpend > 0 ? (s.amount / budget.safeToSpend) * 100 : 0;
            return (
              <div key={s.name}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="font-medium text-gray-700 dark:text-gray-200">{categoryIcon(s.name)} {s.name}</span>
                  <span className="font-semibold text-gray-800 dark:text-gray-100">{fmt(s.amount)}</span>
                </div>
                <div className="w-full bg-white/60 dark:bg-gray-800/60 rounded-full h-1.5">
                  <div style={{ background: 'var(--brand-neon)', height: 6, borderRadius: 3, transition: 'width 0.6s var(--ease)', width: `${Math.min(100, pct)}%` }} />
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Expandable details */}
      <button
        onClick={() => { void hapticLight(); setExpanded(!expanded); }}
        className="w-full flex items-center justify-center space-x-1 py-1.5 text-xs font-medium"
        style={{ color: 'var(--fg-3)' }}
      >
        <span>{expanded ? t('hide_details') : t('how_calculated')}</span>
        <svg className={`w-3 h-3 transition-transform ${expanded ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {expanded && (
        <div className="mt-3 pt-3 border-t space-y-1.5 text-xs">
          <Row label={t('balance_today')} value={fmt(budget.balanceToday)} />
          {budget.incomeThisWeek > 0 && <Row label={`+ ${t('income_this_week')}`} value={fmt(budget.incomeThisWeek)} positive />}
          {budget.billsThisWeek > 0 && <Row label={`− ${t('bills_this_week')}`} value={fmt(budget.billsThisWeek)} negative />}
          {budget.debtThisWeek > 0 && <Row label={`− ${t('debt_this_week')}`} value={fmt(budget.debtThisWeek)} negative />}
          {budget.savingsThisWeek > 0 && <Row label={`− ${t('savings_auto')}`} value={fmt(budget.savingsThisWeek)} negative />}
          {budget.reserveForBigBills > 0 && budget.nextBigBill && (
            <Row
              label={`− ${t('reserve_for')} ${budget.nextBigBill.name}`}
              value={fmt(budget.reserveForBigBills)}
              negative
            />
          )}
          {budget.emergencyBuffer > 0 && <Row label={`− ${t('emergency_buffer')}`} value={fmt(budget.emergencyBuffer)} negative />}
          <div className="border-t pt-1.5 mt-1.5">
            <Row label={`= ${t('safe_to_spend')}`} value={fmt(budget.safeToSpend)} bold />
          </div>
        </div>
      )}
    </section>
  );
}

function Row({ label, value, positive, negative, bold }: { label: string; value: string; positive?: boolean; negative?: boolean; bold?: boolean }) {
  const color = positive ? 'text-[var(--brand-neon)] dark:text-[var(--brand-neon)]' : negative ? 'text-[var(--negative)] dark:text-red-400' : 'text-gray-700 dark:text-gray-200';
  return (
    <div className="flex justify-between items-center">
      <span className={`${bold ? 'font-bold' : ''} text-gray-600 dark:text-gray-300`}>{label}</span>
      <span className={`${bold ? 'font-bold' : 'font-semibold'} ${color}`}>{value}</span>
    </div>
  );
}
