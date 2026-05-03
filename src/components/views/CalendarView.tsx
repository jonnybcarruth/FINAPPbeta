'use client';

import { useState, useMemo } from 'react';
import { format, startOfMonth, endOfMonth, startOfWeek, endOfWeek, addDays, isSameMonth, isToday, addMonths, subMonths } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useApp } from '@/context/AppContext';
import { getEndOfDayBalance } from '@/lib/finance';
import DayDetailsModal from '../modals/DayDetailsModal';
import OneTimeModal from '../modals/OneTimeModal';
import SmartBudgetCard from '../SmartBudgetCard';
import type { OneTimeTransaction, Projection } from '@/lib/types';
import { useT, useFmt, useLocale } from '@/lib/i18n';
import { hapticLight } from '@/lib/haptics';

const DAY_LABELS_EN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const DAY_LABELS_PT = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];

function dotClass(type: Projection['type']): string {
  if (type === 'Savings') return 'savings';
  if (type === 'Debt Payment') return 'bill';
  if (type === 'Recurring') return 'bill';
  if (type === 'One-Time') return 'one';
  return 'bill';
}

function incomeDot(p: Projection): string {
  return p.amount > 0 ? 'income' : dotClass(p.type);
}

export default function CalendarView() {
  const { dailyBalanceMap, dailyTransactionMap, settings, setSettings, saveWithOverrides,
    oneTimeTransactions, setOneTimeTransactions, currentCalendarDate, setCurrentCalendarDate } = useApp();
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const DAY_LABELS = locale === 'pt-BR' ? DAY_LABELS_PT : DAY_LABELS_EN;

  const [selected, setSelected] = useState<string | null>(null);
  const [hoverKey, setHoverKey] = useState<string | null>(null);
  const [showOneTime, setShowOneTime] = useState(false);
  const [editTx, setEditTx] = useState<OneTimeTransaction | null>(null);
  const [defaultDate, setDefaultDate] = useState('');
  const [calAnimKey, setCalAnimKey] = useState(0);
  const [calDir, setCalDir] = useState<'right' | 'left'>('left');

  const monthStart = startOfMonth(currentCalendarDate);
  const gridStart = startOfWeek(monthStart);
  const gridEnd = endOfWeek(endOfMonth(currentCalendarDate));
  const monthLabel = format(currentCalendarDate, 'MMMM yyyy', { locale: dateLocale });

  // Compute EOD range for micro-bars
  const eodValues = useMemo(() => {
    const vals: number[] = [];
    let d = gridStart;
    while (d <= gridEnd) {
      if (isSameMonth(d, monthStart)) {
        const dk = format(d, 'yyyy-MM-dd');
        vals.push(getEndOfDayBalance(dk, dailyBalanceMap, settings.startDate, settings.startingBalance));
      }
      d = addDays(d, 1);
    }
    return { min: Math.min(...vals, 0), max: Math.max(...vals, 1) };
  }, [dailyBalanceMap, gridStart, gridEnd, monthStart, settings]);

  // Month stats
  const monthStats = useMemo(() => {
    let inn = 0, out = 0;
    let d = gridStart;
    while (d <= gridEnd) {
      if (isSameMonth(d, monthStart)) {
        const dk = format(d, 'yyyy-MM-dd');
        (dailyTransactionMap[dk] || []).forEach((p) => {
          if (p.amount > 0) inn += p.amount;
          else out += Math.abs(p.amount);
        });
      }
      d = addDays(d, 1);
    }
    return { inn: Math.round(inn), out: Math.round(out), net: Math.round(inn - out) };
  }, [dailyTransactionMap, gridStart, gridEnd, monthStart]);

  const handleSaveOneTime = (tx: OneTimeTransaction) => {
    const exists = oneTimeTransactions.findIndex((o) => o.id === tx.id);
    const updated = exists >= 0 ? oneTimeTransactions.map((o) => (o.id === tx.id ? tx : o)) : [...oneTimeTransactions, tx];
    setOneTimeTransactions(updated);
    setShowOneTime(false);
    saveWithOverrides(undefined, updated, undefined, undefined, undefined);
  };

  const handleDelete = (id: string) => {
    if (!confirm(settings.language === 'pt' ? 'Excluir esta transação?' : 'Delete this transaction?')) return;
    const updated = oneTimeTransactions.filter((o) => o.id !== id);
    setOneTimeTransactions(updated);
    setSelected(null);
    saveWithOverrides(undefined, updated, undefined, undefined, undefined);
  };

  const handleEdit = (id: string) => {
    const tx = oneTimeTransactions.find((o) => o.id === id);
    if (tx) { setEditTx(tx); setSelected(null); setShowOneTime(true); }
  };

  const move = (delta: number) => {
    setCalDir(delta > 0 ? 'right' : 'left');
    setCalAnimKey((k) => k + 1);
    void hapticLight();
    if (delta > 0) setCurrentCalendarDate(addMonths(currentCalendarDate, 1));
    else setCurrentCalendarDate(subMonths(currentCalendarDate, 1));
  };

  // Build cells
  const cells: { day: number; inMonth: boolean; key: string | null; isToday: boolean; txs: Projection[]; eod: number }[] = [];
  let day = gridStart;
  while (day <= gridEnd) {
    const dk = format(day, 'yyyy-MM-dd');
    const inMonth = isSameMonth(day, monthStart);
    const txs = inMonth ? (dailyTransactionMap[dk] || []) : [];
    const eod = inMonth ? getEndOfDayBalance(dk, dailyBalanceMap, settings.startDate, settings.startingBalance) : 0;
    cells.push({ day: day.getDate(), inMonth, key: inMonth ? dk : null, isToday: isToday(day), txs, eod });
    day = addDays(day, 1);
  }
  while (cells.length < 42) cells.push({ day: 0, inMonth: false, key: null, isToday: false, txs: [], eod: 0 });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {settings.smartBudgetEnabled !== false && <SmartBudgetCard />}

      <div className="dd-card" style={{ padding: 0, overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '20px 20px 14px' }}>
          <div>
            <div className="dd-overline">{t('calendar')}</div>
            <h3 className="dd-h3" style={{ marginTop: 4 }}>{monthLabel}</h3>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="dd-icon-btn" onClick={() => move(-1)} aria-label="Previous month">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
            </button>
            <button className="dd-icon-btn" onClick={() => move(1)} aria-label="Next month">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
            </button>
          </div>
        </div>

        {/* Month stats strip */}
        <div style={{ display: 'flex', padding: '0 20px 14px', borderBottom: '1px solid var(--line)' }}>
          <StatChip label={settings.language === 'pt' ? 'Entrada' : 'In'} value={fmt(monthStats.inn)} />
          <StatChip label={settings.language === 'pt' ? 'Saída' : 'Out'} value={fmt(monthStats.out)} />
          <StatChip label="Net" value={(monthStats.net >= 0 ? '+' : '') + fmt(monthStats.net)} />
        </div>

        {/* Day-of-week header */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 4, padding: '12px 12px 8px' }}>
          {DAY_LABELS.map((d) => (
            <div key={d} className="dd-overline" style={{ textAlign: 'center' }}>{d}</div>
          ))}
        </div>

        {/* Grid */}
        <div style={{ overflow: 'hidden' }}>
          <div key={calAnimKey} className={calDir === 'right' ? 'cal-slide-r' : 'cal-slide-l'}
            style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 4, padding: '0 12px 16px' }}>
            {cells.map((c, i) => {
              const hot = c.txs.length > 0;
              const eodPct = c.inMonth && eodValues.max > eodValues.min ? (c.eod - eodValues.min) / (eodValues.max - eodValues.min) : 0;
              const isHover = c.key === hoverKey;
              const isSel = c.key === selected;
              return (
                <button
                  key={i}
                  disabled={!c.inMonth}
                  onClick={() => { if (c.key) { void hapticLight(); setSelected(c.key); } }}
                  onMouseEnter={() => c.key && setHoverKey(c.key)}
                  onMouseLeave={() => setHoverKey(null)}
                  className={`cal-cell ${c.inMonth ? 'in' : 'out'} ${c.isToday ? 'today' : ''} ${hot ? 'hot' : ''} ${isHover ? 'hover' : ''} ${isSel ? 'sel' : ''}`}
                >
                  <div className="cal-day-num">{c.day || ''}</div>
                  {c.inMonth && c.txs.length > 0 && (
                    <>
                      <div className="cal-bar">
                        <div className="cal-bar-fill" style={{ height: `${Math.max(6, eodPct * 100)}%` }} />
                      </div>
                      <div className="cal-dots">
                        {c.txs.slice(0, 4).map((tx, j) => (
                          <span key={j} className={`cal-dot ${incomeDot(tx)}`} />
                        ))}
                      </div>
                    </>
                  )}
                  {c.inMonth && (c.isToday || isHover) && (
                    <div className="cal-eod">{fmt(c.eod)}</div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', gap: 16, justifyContent: 'center', padding: '12px 20px 18px', borderTop: '1px solid var(--line)', flexWrap: 'wrap' }}>
          <LegendItem cls="income" label={t('income')} />
          <LegendItem cls="bill" label={settings.language === 'pt' ? 'Conta' : 'Bill'} />
          <LegendItem cls="savings" label={t('savings')} />
          <LegendItem cls="one" label="One-time" />
        </div>
      </div>

      {/* Day detail sheet */}
      {selected && (
        <DayDetailsModal
          open={true}
          onClose={() => setSelected(null)}
          dateKey={selected}
          transactions={dailyTransactionMap[selected] || []}
          eodBalance={getEndOfDayBalance(selected, dailyBalanceMap, settings.startDate, settings.startingBalance)}
          onAddOneTime={(date) => { setDefaultDate(date); setEditTx(null); setShowOneTime(true); }}
          onEditOneTime={handleEdit}
          onDeleteOneTime={handleDelete}
        />
      )}
      <OneTimeModal open={showOneTime} onClose={() => setShowOneTime(false)} onSave={handleSaveOneTime} initial={editTx} defaultDate={defaultDate} />
    </div>
  );
}

function StatChip({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ flex: 1, padding: '10px 0' }}>
      <div className="dd-overline">{label}</div>
      <div style={{ fontFamily: 'var(--font-display)', fontSize: 22, fontWeight: 500, letterSpacing: '-0.02em', marginTop: 2, color: 'var(--fg-1)' }}>{value}</div>
    </div>
  );
}

function LegendItem({ cls, label }: { cls: string; label: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span className={`cal-dot ${cls}`} style={{ width: 8, height: 8 }} />
      <span style={{ fontSize: 11, color: 'var(--fg-3)', letterSpacing: '0.04em' }}>{label}</span>
    </div>
  );
}
