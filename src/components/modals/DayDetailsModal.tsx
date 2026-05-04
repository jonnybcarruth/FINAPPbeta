'use client';

import { useState } from 'react';
import MarkPaidModal from './MarkPaidModal';
import type { Projection, OneTimeTransaction } from '@/lib/types';
import { format, parseISO } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useT, useFmt, useLocale } from '@/lib/i18n';
import { useApp } from '@/context/AppContext';
import { hapticLight } from '@/lib/haptics';
import { Ticker } from '@/components/LogoMark';

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

function dotClass(p: Projection): string {
  if (p.amount > 0) return 'income';
  if (p.type === 'Savings') return 'savings';
  return 'bill';
}

export default function DayDetailsModal({ open, onClose, dateKey, transactions, eodBalance, onAddOneTime, onEditOneTime, onDeleteOneTime }: Props) {
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;
  const fmtDate = dateKey ? format(parseISO(dateKey), 'EEEE, MMMM d', { locale: dateLocale }) : '';
  const { removeLog, oneTimeTransactions, setOneTimeTransactions, saveWithOverrides, settings } = useApp();
  const [markingPaid, setMarkingPaid] = useState<Projection | null>(null);

  if (!open) return null;

  const handleUnpay = (projection: Projection) => {
    void hapticLight();
    if (projection.type === 'One-Time' && projection.id) {
      const tx = oneTimeTransactions.find((o) => o.id === projection.id);
      if (tx) {
        const updated: OneTimeTransaction = { ...tx, completed: false, actual: undefined };
        const list = oneTimeTransactions.map((o) => o.id === tx.id ? updated : o);
        setOneTimeTransactions(list);
        saveWithOverrides(undefined, list, undefined, undefined, undefined);
      }
    } else {
      removeLog(projection.projectionKey);
    }
  };

  const handleMarkPaidOneTime = (projection: Projection, actual: number, notes?: string) => {
    if (projection.type !== 'One-Time' || !projection.id) return;
    const tx = oneTimeTransactions.find((o) => o.id === projection.id);
    if (!tx) return;
    const sign = tx.amount < 0 ? -1 : 1;
    const updated: OneTimeTransaction = { ...tx, completed: true, actual: actual * sign };
    const list = oneTimeTransactions.map((o) => o.id === tx.id ? updated : o);
    setOneTimeTransactions(list);
    saveWithOverrides(undefined, list, undefined, undefined, undefined);
  };

  // Hide day detail when mark-paid is open to prevent stacking
  if (markingPaid) {
    return (
      <MarkPaidModal
        open={true}
        onClose={() => setMarkingPaid(null)}
        projection={markingPaid}
        onOneTimeSave={handleMarkPaidOneTime}
      />
    );
  }

  return (
    <>
      <div className="cal-sheet-scrim" onClick={onClose} style={{ animation: 'fadeIn 0.18s var(--ease) both' }}>
        <div className="cal-sheet" onClick={(e) => e.stopPropagation()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
            <div>
              <div className="dd-overline">{settings.language === 'pt' ? 'Detalhe do dia' : 'Day detail'}</div>
              <h3 className="dd-h3" style={{ marginTop: 4 }}>{fmtDate}</h3>
            </div>
            <button className="dd-icon-btn" onClick={onClose} aria-label="Close">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>
            </button>
          </div>

          <div style={{ marginBottom: 16 }}>
            <div className="dd-overline">{t('end_of_day_balance')}</div>
            <div style={{ fontFamily: 'var(--font-display)', fontSize: 44, fontWeight: 500, letterSpacing: '-0.025em', lineHeight: 1, marginTop: 4 }}>
              <Ticker value={eodBalance} />
            </div>
          </div>

          {transactions.length === 0 ? (
            <div style={{ color: 'var(--fg-3)', fontSize: 14, padding: '24px 0', textAlign: 'center' }}>
              {t('no_transactions_day')}
            </div>
          ) : (
            <div style={{ maxHeight: 280, overflowY: 'auto', marginBottom: 16 }}>
              {transactions.map((tx, i) => {
                const variance = tx.completed ? tx.amount - tx.projectedAmount : 0;
                return (
                  <div key={i} className="dd-row">
                    <span className={`dd-dot ${dotClass(tx)}`} />
                    <div style={{ flex: 1 }}>
                      <div className="dd-row-name" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        {tx.completed && <span style={{ color: 'var(--brand-neon)', fontSize: 12 }}>✓</span>}
                        <span style={tx.completed ? { opacity: 0.7 } : {}}>{tx.name}</span>
                      </div>
                      <div className="dd-row-sub">
                        {tx.type} {tx.completed && `· ${t('paid')}`}
                        {tx.completed && variance !== 0 && (
                          <span style={{ color: variance > 0 ? 'var(--negative)' : 'var(--brand-neon)', marginLeft: 4 }}>
                            ({variance > 0 ? '+' : ''}{fmt(variance)})
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="dd-row-amount" style={{ color: tx.amount > 0 ? 'var(--brand-neon)' : 'var(--fg-1)' }}>
                      {tx.amount > 0 ? '+' : ''}{fmt(tx.amount)}
                    </div>
                    <div style={{ display: 'flex', gap: 6, marginLeft: 8, flexShrink: 0 }}>
                      {tx.type !== 'One-Time' && (
                        tx.completed ? (
                          <button onClick={() => handleUnpay(tx)} className="dd-btn-secondary" style={{ padding: '4px 10px', fontSize: 11, borderRadius: 8 }}>↺ {t('undo_payment')}</button>
                        ) : (
                          <button onClick={() => { void hapticLight(); setMarkingPaid(tx); }} className="dd-btn-secondary" style={{ padding: '4px 10px', fontSize: 11, borderRadius: 8 }}>✓ {t('paid')}</button>
                        )
                      )}
                      {tx.type === 'One-Time' && tx.id && (
                        <>
                          <button onClick={() => onEditOneTime(tx.id!)} className="dd-btn-secondary" style={{ padding: '4px 8px', fontSize: 11, borderRadius: 8 }}>✎</button>
                          <button onClick={() => onDeleteOneTime(tx.id!)} className="dd-btn-secondary" style={{ padding: '4px 8px', fontSize: 11, borderRadius: 8, color: 'var(--negative)' }}>✕</button>
                        </>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <button className="dd-btn-primary" onClick={() => { onClose(); onAddOneTime(dateKey); }} style={{ width: '100%' }}>
            + {t('add_event')}
          </button>
        </div>
      </div>

    </>
  );
}
