'use client';

import ModalShell from './ModalShell';
import type { Projection } from '@/lib/types';
import { format, parseISO } from 'date-fns';

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
  if (t.type === 'Debt Payment') return 'bg-pink-50 text-pink-800 border-pink-200';
  if (t.type === 'One-Time') return t.amount > 0 ? 'bg-purple-100 text-purple-800 border-purple-200' : 'bg-red-50 text-red-800 border-red-200';
  return t.amount > 0 ? 'bg-green-50 text-green-800 border-green-200' : 'bg-red-50 text-red-800 border-red-200';
}

export default function DayDetailsModal({ open, onClose, dateKey, transactions, eodBalance, onAddOneTime, onEditOneTime, onDeleteOneTime }: Props) {
  const fmtDate = dateKey ? format(parseISO(dateKey), 'EEEE, MMM do') : '';
  const fmtBalance = eodBalance.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <ModalShell open={open} onClose={onClose} title="">
      <div className="mb-4">
        <h3 className="text-lg font-bold text-gray-800 dark:text-gray-100">{fmtDate}</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          End of Day Balance: <span className="font-bold text-blue-600">{fmtBalance}</span>
        </p>
      </div>

      <div className="space-y-2 max-h-64 overflow-y-auto mb-4">
        {transactions.length === 0 && (
          <p className="text-center text-gray-500 italic">No scheduled transactions for this day.</p>
        )}
        {transactions.map((t, i) => (
          <div key={i} className={`flex justify-between items-center p-3 rounded-lg border ${txColor(t)}`}>
            <div className="flex flex-col flex-grow min-w-0">
              <span className="font-medium truncate">{t.name}</span>
              <span className="text-xs text-gray-500">{t.type}</span>
            </div>
            <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
              <span className={`font-bold ${t.amount >= 0 ? 'text-green-600' : 'text-red-600'}`}>
                {t.amount >= 0 ? '↑' : '↓'} ${Math.abs(t.amount).toFixed(2)}
              </span>
              {t.type === 'One-Time' && t.id && (
                <>
                  <button onClick={() => onEditOneTime(t.id!)} className="text-gray-400 hover:text-purple-600 p-1">✏️</button>
                  <button onClick={() => onDeleteOneTime(t.id!)} className="text-gray-400 hover:text-red-600 p-1">🗑️</button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="flex justify-between pt-2 border-t border-gray-200">
        <button onClick={() => { onClose(); onAddOneTime(dateKey); }} className="px-4 py-2 bg-dindin-green text-white rounded-lg hover:bg-dindin-green-dark text-sm font-medium">
          + Add Event
        </button>
        <button onClick={onClose} className="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 text-sm">
          Close
        </button>
      </div>
    </ModalShell>
  );
}
