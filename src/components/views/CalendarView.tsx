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

const DAY_LABELS_EN = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];
const DAY_LABELS_PT = ['D', 'S', 'T', 'Q', 'Q', 'S', 'S'];

function eventClass(p: Projection): string {
  if (p.amount > 0) return 'income';
  if (p.type === 'Savings') return 'savings';
  if (p.type === 'One-Time') return 'one';
  return 'bill';
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
  const [showOneTime, setShowOneTime] = useState(false);
  const [editTx, setEditTx] = useState<OneTimeTransaction | null>(null);
  const [defaultDate, setDefaultDate] = useState('');
  const [calAnimKey, setCalAnimKey] = useState(0);
  const [calDir, setCalDir] = useState<'right' | 'left'>('left');

  const monthStart = startOfMonth(currentCalendarDate);
  const gridStart = startOfWeek(monthStart);
  const gridEnd = endOfWeek(endOfMonth(currentCalendarDate));
  const monthLabel = format(currentCalendarDate, 'MMMM', { locale: dateLocale });
  const yearLabel = format(currentCalendarDate, 'yyyy');

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
  const cells: { day: number; inMonth: boolean; key: string | null; isToday: boolean; txs: Projection[] }[] = [];
  let day = gridStart;
  while (day <= gridEnd) {
    const dk = format(day, 'yyyy-MM-dd');
    const inMonth = isSameMonth(day, monthStart);
    const txs = inMonth ? (dailyTransactionMap[dk] || []) : [];
    cells.push({ day: day.getDate(), inMonth, key: inMonth ? dk : null, isToday: isToday(day), txs });
    day = addDays(day, 1);
  }
  while (cells.length < 42) cells.push({ day: 0, inMonth: false, key: null, isToday: false, txs: [] });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {settings.smartBudgetEnabled !== false && <SmartBudgetCard />}

      {/* Calendar — edge to edge, no card wrapper */}
      <div>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0 12px', marginBottom: 4 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <h2 style={{ fontFamily: 'var(--font-display)', fontSize: 28, fontWeight: 500, letterSpacing: '-0.02em', margin: 0, color: 'var(--fg-1)' }}>
              {monthLabel}
            </h2>
            <span style={{ fontSize: 14, color: 'var(--fg-3)', fontWeight: 500 }}>{yearLabel}</span>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <button className="dd-icon-btn" onClick={() => move(-1)} aria-label="Previous month">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
            </button>
            <button className="dd-icon-btn" onClick={() => move(1)} aria-label="Next month">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
            </button>
          </div>
        </div>

        {/* Day-of-week header */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', borderBottom: '1px solid var(--line)' }}>
          {DAY_LABELS.map((d, i) => (
            <div key={i} style={{ textAlign: 'center', padding: '6px 0', fontSize: 12, fontWeight: 600, color: 'var(--fg-3)', letterSpacing: '0.04em' }}>{d}</div>
          ))}
        </div>

        {/* Grid */}
        <div style={{ overflow: 'hidden' }}>
          <div key={calAnimKey} className={calDir === 'right' ? 'cal-slide-r' : 'cal-slide-l'}
            style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 3 }}>
            {cells.map((c, i) => {
              const isSel = c.key === selected;
              return (
                <button
                  key={i}
                  disabled={!c.inMonth}
                  onClick={() => { if (c.key) { void hapticLight(); setSelected(c.key); } }}
                  className={`cal-cell ${c.inMonth ? 'in' : 'out'} ${c.isToday ? 'today' : ''} ${isSel ? 'sel' : ''}`}
                  style={{ textAlign: 'left' }}
                >
                  <div className="cal-day-num">{c.day || ''}</div>
                  {c.inMonth && c.txs.slice(0, 3).map((tx, j) => (
                    <div key={j} className={`cal-event ${eventClass(tx)}`}>
                      {tx.name}
                    </div>
                  ))}
                  {c.inMonth && c.txs.length > 3 && (
                    <div style={{ fontSize: 9, color: 'var(--fg-3)', paddingLeft: 3, marginTop: 1 }}>
                      +{c.txs.length - 3}
                    </div>
                  )}
                  {c.inMonth && settings.showEODBalance && c.key && (
                    <div className={`cal-eod ${getEndOfDayBalance(c.key, dailyBalanceMap, settings.startDate, settings.startingBalance) < 0 ? 'neg' : ''}`}>
                      {fmt(getEndOfDayBalance(c.key, dailyBalanceMap, settings.startDate, settings.startingBalance))}
                    </div>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* EOD toggle */}
        <div style={{ display: 'flex', justifyContent: 'center', padding: '12px 0' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 13, color: 'var(--fg-3)', fontWeight: 500 }}>
            <input type="checkbox" checked={settings.showEODBalance} onChange={(e) => {
              void hapticLight();
              const newSettings = { ...settings, showEODBalance: e.target.checked };
              setSettings(newSettings);
              saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
            }} style={{ width: 16, height: 16 }} />
            {t('show_eod_balance')}
          </label>
        </div>
      </div>

      {selected && (
        <DayDetailsModal
          open={true}
          onClose={() => setSelected(null)}
          dateKey={selected}
          transactions={dailyTransactionMap[selected] || []}
          eodBalance={getEndOfDayBalance(selected, dailyBalanceMap, settings.startDate, settings.startingBalance)}
          onAddOneTime={(date) => { setSelected(null); setDefaultDate(date); setEditTx(null); setShowOneTime(true); }}
          onEditOneTime={(id) => { setSelected(null); handleEdit(id); }}
          onDeleteOneTime={handleDelete}
        />
      )}
      <OneTimeModal open={showOneTime} onClose={() => setShowOneTime(false)} onSave={handleSaveOneTime} initial={editTx} defaultDate={defaultDate} />
    </div>
  );
}
