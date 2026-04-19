'use client';

import { useState } from 'react';
import { format, startOfMonth, endOfMonth, startOfWeek, endOfWeek, addDays, isSameMonth, isToday, addMonths, subMonths } from 'date-fns';
import { useApp } from '@/context/AppContext';
import { getEndOfDayBalance } from '@/lib/finance';
import DayDetailsModal from '../modals/DayDetailsModal';
import OneTimeModal from '../modals/OneTimeModal';
import type { OneTimeTransaction } from '@/lib/types';
import { useT, useFmt, useLocale } from '@/lib/i18n';
import { ptBR, enUS } from 'date-fns/locale';

const DAY_LABELS_EN = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const DAY_LABELS_PT = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];

export default function CalendarView() {
  const { dailyBalanceMap, dailyTransactionMap, settings, setSettings, saveWithOverrides,
    oneTimeTransactions, setOneTimeTransactions, currentCalendarDate, setCurrentCalendarDate } = useApp();
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const DAY_LABELS = locale === 'pt-BR' ? DAY_LABELS_PT : DAY_LABELS_EN;
  const [dayKey, setDayKey] = useState('');
  const [showDay, setShowDay] = useState(false);
  const [showOneTime, setShowOneTime] = useState(false);
  const [editTx, setEditTx] = useState<OneTimeTransaction | null>(null);
  const [defaultDate, setDefaultDate] = useState('');
  const [calAnimKey, setCalAnimKey] = useState(0);
  const [calDir, setCalDir] = useState<'right' | 'left'>('left');

  const monthStart = startOfMonth(currentCalendarDate);
  const gridStart = startOfWeek(monthStart);
  const gridEnd = endOfWeek(endOfMonth(currentCalendarDate));

  const handleSaveOneTime = (tx: OneTimeTransaction) => {
    const exists = oneTimeTransactions.findIndex((t) => t.id === tx.id);
    const updated = exists >= 0
      ? oneTimeTransactions.map((t) => (t.id === tx.id ? tx : t))
      : [...oneTimeTransactions, tx];
    setOneTimeTransactions(updated);
    setShowOneTime(false);
    saveWithOverrides(undefined, updated, undefined, undefined, undefined);
  };

  const handleDelete = (id: string) => {
    if (!confirm(settings.language === 'pt' ? 'Excluir esta transação?' : 'Delete this transaction?')) return;
    const updated = oneTimeTransactions.filter((t) => t.id !== id);
    setOneTimeTransactions(updated);
    setShowDay(false);
    saveWithOverrides(undefined, updated, undefined, undefined, undefined);
  };

  const handleEdit = (id: string) => {
    const tx = oneTimeTransactions.find((t) => t.id === id);
    if (tx) { setEditTx(tx); setShowDay(false); setShowOneTime(true); }
  };

  const days: React.ReactNode[] = [];
  DAY_LABELS.forEach((d) => (
    days.push(<div key={d} className="text-center font-semibold text-sm text-gray-600 py-2">{d}</div>)
  ));

  let day = gridStart;
  while (day <= gridEnd) {
    const dk = format(day, 'yyyy-MM-dd');
    const txs = dailyTransactionMap[dk] || [];
    const inMonth = isSameMonth(day, monthStart);
    const today = isToday(day);
    const dayDate = day;
    days.push(
      <div
        key={dk}
        data-date={dk}
        onClick={() => inMonth && (setDayKey(dk), setShowDay(true))}
        className={`calendar-day p-2 border border-gray-200 rounded-md ${!inMonth ? 'bg-gray-50 text-gray-400' : 'bg-white cursor-pointer hover:shadow-lg'} ${today ? 'border-blue-500 border-2' : ''} ${txs.length > 0 && inMonth ? 'bg-blue-50' : ''}`}
      >
        <div className="text-sm font-semibold text-right flex flex-col items-end">
          <span>{format(dayDate, 'd')}</span>
          {settings.showEODBalance && inMonth && (
            <span className={`text-xs font-bold leading-none truncate ${getEndOfDayBalance(dk, dailyBalanceMap, settings.startDate, settings.startingBalance) >= 1000 ? 'text-green-600' : getEndOfDayBalance(dk, dailyBalanceMap, settings.startDate, settings.startingBalance) < 0 ? 'text-red-600' : 'text-gray-500'}`}>
              {(Math.round(getEndOfDayBalance(dk, dailyBalanceMap, settings.startDate, settings.startingBalance) / 100) / 10).toFixed(1)}k
            </span>
          )}
        </div>
        <ul className="mt-1 space-y-1 text-xs overflow-y-auto">
          {txs.map((t, i) => (
            <li key={i} className={`flex items-center rounded px-1 ${t.type === 'Savings' ? 'bg-emerald-100 text-emerald-800 border-l-2 border-emerald-500' : t.type === 'Debt Payment' ? 'bg-pink-100 text-pink-800 border-l-2 border-pink-500' : t.type === 'One-Time' ? 'bg-purple-50 text-purple-800 border-l-2 border-purple-500' : t.amount > 0 ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
              <span className="truncate" title={t.name}>{t.name}</span>
              <span className="font-semibold ml-auto">{fmt(Math.abs(t.amount))}</span>
            </li>
          ))}
        </ul>
      </div>
    );
    day = addDays(day, 1);
  }

  return (
    <div className="space-y-6">
      <section className="bg-white dark:bg-gray-800 py-6 px-0 rounded-2xl shadow-sm">
        <div className="flex flex-col sm:flex-row justify-between items-center mb-6 px-6">
          <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100 mb-4 sm:mb-0">{t('transaction_calendar')}</h2>
          <button onClick={() => { setEditTx(null); setDefaultDate(''); setShowOneTime(true); }} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold text-sm">
            {t('add_event')}
          </button>
        </div>
        <div className="flex justify-between items-center mb-4 px-6">
          <button onClick={() => { setCalDir('right'); setCalAnimKey(k => k + 1); setCurrentCalendarDate(subMonths(currentCalendarDate, 1)); }} aria-label="Previous month" className="w-9 h-9 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
          </button>
          <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-100" style={{ letterSpacing: '-0.01em' }}>{format(currentCalendarDate, 'MMMM yyyy', { locale: dateLocale })}</h3>
          <button onClick={() => { setCalDir('left'); setCalAnimKey(k => k + 1); setCurrentCalendarDate(addMonths(currentCalendarDate, 1)); }} aria-label="Next month" className="w-9 h-9 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          </button>
        </div>
        <div className="overflow-x-auto">
          <div key={calAnimKey} className={calDir === 'left' ? 'cal-slide-from-right' : 'cal-slide-from-left'}>
            <div id="calendar-grid" className="grid grid-cols-7 gap-0 calendar-grid">{days}</div>
          </div>
        </div>
        <div className="flex justify-center mt-6 pt-4 border-t border-gray-200 px-6">
          <label className="flex items-center space-x-2 p-2 bg-gray-100 dark:bg-gray-700 rounded-lg cursor-pointer">
            <input type="checkbox" checked={settings.showEODBalance} onChange={(e) => {
              const newSettings = { ...settings, showEODBalance: e.target.checked };
              setSettings(newSettings);
              saveWithOverrides(undefined, undefined, undefined, undefined, newSettings);
            }} className="w-4 h-4" />
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">{t('show_eod_balance')}</span>
          </label>
        </div>
      </section>

      <DayDetailsModal
        open={showDay} onClose={() => setShowDay(false)} dateKey={dayKey}
        transactions={dailyTransactionMap[dayKey] || []}
        eodBalance={getEndOfDayBalance(dayKey, dailyBalanceMap, settings.startDate, settings.startingBalance)}
        onAddOneTime={(date) => { setDefaultDate(date); setEditTx(null); setShowOneTime(true); }}
        onEditOneTime={handleEdit} onDeleteOneTime={handleDelete}
      />
      <OneTimeModal open={showOneTime} onClose={() => setShowOneTime(false)} onSave={handleSaveOneTime} initial={editTx} defaultDate={defaultDate} />
    </div>
  );
}
