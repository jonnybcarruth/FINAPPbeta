'use client';

import { useState, useEffect } from 'react';
import ModalShell from './ModalShell';
import type { DebtPlan } from '@/lib/types';
import { hapticSuccess, hapticLight } from '@/lib/haptics';
import { format } from 'date-fns';
import { useT, useCurrencySymbol } from '@/lib/i18n';
import { useApp } from '@/context/AppContext';

interface Props {
  open: boolean;
  onClose: () => void;
  onSave: (d: DebtPlan) => void;
  initial?: DebtPlan | null;
}

export default function DebtPlanModal({ open, onClose, onSave, initial }: Props) {
  const { settings } = useApp();
  const t = useT();
  const sym = useCurrencySymbol();
  const [name, setName] = useState('');
  const [totalAmount, setTotalAmount] = useState('');
  const [payoffMonths, setPayoffMonths] = useState('12');
  const [startDate, setStartDate] = useState(format(new Date(), 'yyyy-MM-dd'));
  const [payDay, setPayDay] = useState('1');
  const [debtType, setDebtType] = useState<'fixed' | 'revolving'>('fixed');
  const [interestRate, setInterestRate] = useState('');
  const [minimumPayment, setMinimumPayment] = useState('');

  useEffect(() => {
    if (initial) {
      setName(initial.name);
      setTotalAmount(String(initial.totalAmount));
      setPayoffMonths(String(initial.payoffMonths));
      setStartDate(initial.startDate);
      setPayDay(String(initial.payDay));
      setDebtType(initial.debtType || 'fixed');
      setInterestRate(initial.interestRate ? String(initial.interestRate) : '');
      setMinimumPayment(initial.minimumPayment ? String(initial.minimumPayment) : '');
    } else {
      setName(''); setTotalAmount(''); setPayoffMonths('12');
      setStartDate(format(new Date(), 'yyyy-MM-dd')); setPayDay('1');
      setDebtType('fixed'); setInterestRate(''); setMinimumPayment('');
    }
  }, [initial, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const total = parseFloat(totalAmount);
    const months = debtType === 'fixed' ? parseInt(payoffMonths) : 999;
    void hapticSuccess();
    onSave({
      id: initial?.id || `DEBT-${Date.now()}`,
      name, totalAmount: total,
      payoffMonths: months,
      monthlyPayment: debtType === 'fixed' ? total / months : parseFloat(minimumPayment) || 0,
      payDay: parseInt(payDay), startDate, enabled: true,
      debtType,
      ...(debtType === 'revolving' ? {
        interestRate: parseFloat(interestRate) || 0,
        minimumPayment: parseFloat(minimumPayment) || 0,
      } : {}),
    });
  };

  const fixedLabel = settings.language === 'pt' ? 'Prazo Fixo' : 'Fixed Term';
  const revolvingLabel = settings.language === 'pt' ? 'Cartão / Rotativo' : 'Credit Card / Revolving';

  return (
    <ModalShell open={open} onClose={onClose} title={initial ? t('edit') + ' ' + t('debt') : t('add_debt_plan')}>
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Debt type toggle */}
        <div className="flex bg-gray-100 dark:bg-gray-800 rounded-lg p-1">
          <button type="button" onClick={() => { void hapticLight(); setDebtType('fixed'); }}
            className={`flex-1 py-2 text-sm font-semibold rounded-md transition ${debtType === 'fixed' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
            {fixedLabel}
          </button>
          <button type="button" onClick={() => { void hapticLight(); setDebtType('revolving'); }}
            className={`flex-1 py-2 text-sm font-semibold rounded-md transition ${debtType === 'revolving' ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
            {revolvingLabel}
          </button>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('name')}</label>
          <input required value={name} onChange={(e) => setName(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            {debtType === 'revolving'
              ? (settings.language === 'pt' ? 'Saldo atual' : 'Current balance')
              : t('amount')} ({sym})
          </label>
          <input type="number" step="0.01" required value={totalAmount} onChange={(e) => setTotalAmount(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>

        {debtType === 'fixed' ? (
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('months')}</label>
            <input type="number" min="1" required value={payoffMonths} onChange={(e) => setPayoffMonths(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
          </div>
        ) : (
          <>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                {settings.language === 'pt' ? 'Taxa de juros anual (%)' : 'Annual interest rate (%)'}
              </label>
              <input type="number" step="0.1" min="0" required value={interestRate} onChange={(e) => setInterestRate(e.target.value)}
                placeholder="24.99" className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                {settings.language === 'pt' ? 'Pagamento mensal' : 'Monthly payment'} ({sym})
              </label>
              <input type="number" step="0.01" min="0" required value={minimumPayment} onChange={(e) => setMinimumPayment(e.target.value)}
                className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
            </div>
          </>
        )}

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('start_date')}</label>
          <input type="date" required value={startDate} onChange={(e) => setStartDate(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{t('day_of_month')}</label>
          <input type="number" min="1" max="31" required value={payDay} onChange={(e) => setPayDay(e.target.value)} className="w-full p-2 border rounded-lg dark:bg-gray-700 dark:text-white dark:border-gray-600" />
        </div>
        <div className="flex justify-end space-x-3 pt-4">
          <button type="button" onClick={onClose} className="px-5 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300">{t('cancel')}</button>
          <button type="submit" className="px-5 py-2 bg-ios-blue text-white rounded-xl hover:bg-ios-blue-dark font-semibold">{t('save')}</button>
        </div>
      </form>
    </ModalShell>
  );
}
