'use client';

import { useState } from 'react';
import ModalShell from './ModalShell';
import { useApp } from '@/context/AppContext';
import { useT, useFmt, useCurrencySymbol } from '@/lib/i18n';
import { getEndOfDayBalance } from '@/lib/finance';
import { hapticSuccess } from '@/lib/haptics';
import { format } from 'date-fns';
import type { OneTimeTransaction } from '@/lib/types';

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function UpdateBalanceModal({ open, onClose }: Props) {
  const { settings, dailyBalanceMap, oneTimeTransactions, setOneTimeTransactions, saveWithOverrides } = useApp();
  const t = useT();
  const fmt = useFmt();
  const sym = useCurrencySymbol();
  const [amount, setAmount] = useState('');

  const today = format(new Date(), 'yyyy-MM-dd');
  const currentProjected = getEndOfDayBalance(today, dailyBalanceMap, settings.startDate, settings.startingBalance);

  const handleSubmit = () => {
    const actual = parseFloat(amount);
    if (isNaN(actual)) return;
    const diff = actual - currentProjected;
    if (Math.abs(diff) < 0.01) { onClose(); return; }

    const tx: OneTimeTransaction = {
      id: `ADJ-${Date.now()}`,
      name: settings.language === 'pt' ? 'Ajuste de saldo' : 'Balance adjustment',
      amount: diff,
      date: today,
      category: 'other',
    };

    void hapticSuccess();
    const updated = [...oneTimeTransactions, tx];
    setOneTimeTransactions(updated);
    saveWithOverrides(undefined, updated, undefined, undefined, undefined);
    setAmount('');
    onClose();
  };

  const parsed = parseFloat(amount);
  const diff = !isNaN(parsed) ? parsed - currentProjected : 0;

  return (
    <ModalShell open={open} onClose={onClose} title={settings.language === 'pt' ? 'Atualizar Saldo' : 'Update Balance'}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ padding: 16, background: 'var(--surface-2)', borderRadius: 'var(--radius)', textAlign: 'center' }}>
          <div style={{ fontSize: 12, color: 'var(--fg-3)', marginBottom: 4 }}>
            {settings.language === 'pt' ? 'Saldo projetado hoje' : 'Projected balance today'}
          </div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: 32, fontWeight: 500, color: 'var(--fg-1)' }}>
            {fmt(currentProjected)}
          </div>
        </div>

        <div>
          <label style={{ display: 'block', fontSize: 13, fontWeight: 600, color: 'var(--fg-2)', marginBottom: 6 }}>
            {settings.language === 'pt' ? 'Quanto você tem na conta agora?' : 'How much do you actually have?'}
          </label>
          <div style={{ position: 'relative' }}>
            <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--fg-3)', fontSize: 16 }}>{sym}</span>
            <input
              type="number"
              step="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              autoFocus
              placeholder="0.00"
              style={{
                width: '100%', padding: '12px 12px 12px 36px', fontSize: 18, fontWeight: 600,
                border: '1px solid var(--line)', borderRadius: 'var(--radius)',
                background: 'var(--surface)', color: 'var(--fg-1)',
                fontFamily: 'var(--font-ui)', outline: 'none',
                fontVariantNumeric: 'tabular-nums',
              }}
            />
          </div>
        </div>

        {!isNaN(parsed) && Math.abs(diff) > 0.01 && (
          <div style={{
            padding: 12, borderRadius: 'var(--radius)',
            background: diff > 0 ? 'var(--brand-neon-soft)' : 'var(--negative-bg)',
            textAlign: 'center',
          }}>
            <div style={{ fontSize: 12, color: 'var(--fg-3)', marginBottom: 2 }}>
              {settings.language === 'pt' ? 'Diferença' : 'Difference'}
            </div>
            <div style={{ fontSize: 18, fontWeight: 700, color: diff > 0 ? '#3d5a0f' : 'var(--negative)' }}>
              {diff > 0 ? '+' : ''}{fmt(diff)}
            </div>
            <div style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 4 }}>
              {diff > 0
                ? (settings.language === 'pt' ? 'Receita avulsa será adicionada' : 'One-time income will be added')
                : (settings.language === 'pt' ? 'Despesa avulsa será adicionada' : 'One-time expense will be added')
              }
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={onClose} className="dd-btn-secondary" style={{ flex: 1, padding: '12px 16px' }}>
            {t('cancel')}
          </button>
          <button
            onClick={handleSubmit}
            className="dd-btn-primary"
            style={{ flex: 2, padding: '12px 16px' }}
            disabled={isNaN(parsed)}
          >
            {settings.language === 'pt' ? 'Atualizar' : 'Update'}
          </button>
        </div>
      </div>
    </ModalShell>
  );
}
