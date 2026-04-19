'use client';

import ModalShell from './ModalShell';
import type { Projection } from '@/lib/types';
import { format, parseISO } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useT, useFmt, useLocale } from '@/lib/i18n';

interface Props {
  open: boolean;
  onClose: () => void;
  dateKey: string;
  transactions: Projection[];
  eodBalance: number;
  onAddOneTime: (date: string) => void;
  onEditOneTime: (id: string) => void;
  onDeleteOneTime: (id: string) => void;
}

function txColor(t: Projection) {
  if (t.type === 'Savings') return 'bg-emerald-50 text-emerald-800 border-emerald-200';
  if (t.type === 'Debt Payment') return 'bg-pink-50 text-pink-800 border-pink-200';
  if (t.type === 'One-Time') return t.amount > 0 ? 'bg-purple-100 text-purple-800 border-purple-200' : 'bg-red-50 text-red-800 border-red-200';
  return t.amount > 0 ? 'bg-green-50 text-green-800 border-green-200' : 'bg-red-50 text-red-800 border-red-200';
}

export default function DayDetailsModal({ open, onClose, dateKey, transactions, eodBalance, onAddOneTime, onEditOneTime, onDeleteOneTime }: Props) {
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const fmtDate = dateKey ? format(parseISO(dateKey), 'EEEE, MMM do', { locale: dateLocale }) : '';

  return (
    <ModalShell open={open} onClose={onClose} title="">
      <div className="mb-4">
        <h3 className="text-lg font-bold text-gray-800 dark:text-gray-100">{fmtDate}</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          {t('end_of_day_balance')}: <span className="font-bold text-blue-600">{fmt(eodBalance)}</span>
        </p>
      </div>

      <div className="space-y-2 max-h-64 overflow-y-auto mb-4">
        {transactions.length === 0 && (
          <p className="text-center text-gray-500 italic">{t('no_transactions_day')}</p>
        )}
        {transactions.map((tx, i) => (
          <div key={i} className={`flex justify-between items-center p-3 rounded-lg border ${txColor(tx)}`}>
            <div className="flex flex-col flex-grow min-w-0">
              <span className="font-medium truncate">{tx.name}</span>
              <span className="text-xs text-gray-500">{tx.type}</span>
            </div>
            <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
              <span className={`font-bold ${tx.amount >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                {tx.amount >= 0 ? '↑' : '↓'} {fmt(Math.abs(tx.amount))}
              </span>
              {tx.type === 'One-Time' && tx.id && (
                <>
                  <button onClick={() => onEditOneTime(tx.id!)} className="text-gray-400 hover:text-purple-600 p-1 transition-colors" aria-label={t('edit')}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                    </svg>
                  </button>
                  <button onClick={() => onDeleteOneTime(tx.id!)} className="text-gray-400 hover:text-red-600 p-1 transition-colors" aria-label={t('delete')}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="3 6 5 6 21 6"/>
                      <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
                      <path d="M10 11v6"/>
                      <path d="M14 11v6"/>
                      <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>
                    </svg>
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-between pt-2 border-t border-gray-200">
        <button onClick={() => { onClose(); onAddOneTime(dateKey); }} className="px-4 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark text-sm font-semibold">
          + {t('add_event')}
        </button>
        <button onClick={onClose} className="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 text-sm">
          {t('close')}
        </button>
      </div>
    </ModalShell>
  );
}
