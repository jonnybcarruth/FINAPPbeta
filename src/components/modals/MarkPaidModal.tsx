'use client';

import { useState, useEffect } from 'react';
import ModalShell from './ModalShell';
import type { Projection } from '@/lib/types';
import { useT, useCurrencySymbol } from '@/lib/i18n';
import { useApp } from '@/context/AppContext';
import { hapticSuccess } from '@/lib/haptics';
import { format } from 'date-fns';

interface Props {
  open: boolean;
  onClose: () => void;
  projection: Projection | null;
  onOneTimeSave?: (projection: Projection, actual: number, notes?: string) => void;
}

export default function MarkPaidModal({ open, onClose, projection, onOneTimeSave }: Props) {
  const t = useT();
  const sym = useCurrencySymbol();
  const { logTransaction, settings } = useApp();

  const [amount, setAmount] = useState('');
  const [notes, setNotes] = useState('');

  useEffect(() => {
    if (projection) {
      setAmount(String(Math.abs(projection.amount)));
      setNotes(projection.notes || '');
    }
  }, [projection, open]);

  if (!projection) return null;

  const projectedAbs = Math.abs(projection.projectedAmount);
  const handleSubmit = () => {
    const parsed = parseFloat(amount);
    if (isNaN(parsed) || parsed < 0) return;
    const sign = projection.projectedAmount < 0 ? -1 : 1;
    void hapticSuccess();
    if (projection.type === 'One-Time' && projection.id && onOneTimeSave) {
      onOneTimeSave(projection, parsed, notes.trim() || undefined);
    } else {
      logTransaction({
        projectionKey: projection.projectionKey,
        amount: parsed * sign,
        completed: true,
        notes: notes.trim() || undefined,
        loggedAt: new Date().toISOString(),
      });
    }
    onClose();
  };

  const useProjected = () => {
    setAmount(String(projectedAbs));
  };

  const actualParsed = parseFloat(amount);
  const variance = !isNaN(actualParsed) ? actualParsed - projectedAbs : 0;

  return (
    <ModalShell open={open} onClose={onClose} title={t('mark_as_paid')}>
      <div className="space-y-4">
        <div className="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
          <p className="text-sm font-semibold text-gray-800 dark:text-gray-100 truncate">{projection.name}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
            {format(projection.date, 'EEE, MMM d, yyyy')} · {t('projected')}: {sym}{projectedAbs.toFixed(2)}
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            {t('actual_amount')} ({sym})
          </label>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">{sym}</span>
            <input
              type="number"
              step="0.01"
              min="0"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              className="w-full pl-10 pr-3 py-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600"
              autoFocus
            />
          </div>
          {!isNaN(actualParsed) && (
            <div className="mt-2 flex items-center justify-between">
              <button
                type="button"
                onClick={useProjected}
                className="text-xs text-blue-600 hover:text-blue-700 font-medium"
              >
                {t('same_as_projected')}
              </button>
              {variance !== 0 && (
                <span className={`text-xs font-semibold ${variance > 0 ? 'text-red-600' : 'text-emerald-600'}`}>
                  {variance > 0 ? '+' : ''}{sym}{Math.abs(variance).toFixed(2)} {t('variance_from_projected')}
                </span>
              )}
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            {t('notes_optional')}
          </label>
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder={settings.language === 'pt' ? 'Adicionar uma nota...' : 'Add a note...'}
            className="w-full p-2.5 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600 text-sm"
          />
        </div>

        <div className="flex justify-end space-x-3 pt-2">
          <button type="button" onClick={onClose} className="px-5 py-2.5 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 text-sm">
            {t('cancel')}
          </button>
          <button
            type="button"
            onClick={handleSubmit}
            disabled={isNaN(actualParsed) || actualParsed < 0}
            className="px-5 py-2.5 bg-emerald-600 text-white rounded-xl hover:bg-emerald-700 font-semibold text-sm disabled:opacity-40"
          >
            ✓ {t('mark_as_paid')}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
