'use client';

import { useState } from 'react';
import { useApp } from '@/context/AppContext';
import { useT, useCurrencySymbol } from '@/lib/i18n';
import { hapticLight, hapticSuccess } from '@/lib/haptics';
import { format } from 'date-fns';
import type { RecurringSchedule } from '@/lib/types';

export default function Onboarding() {
  const { settings, setSettings, recurringSchedules, setRecurringSchedules, saveWithOverrides } = useApp();
  const t = useT();
  const sym = useCurrencySymbol();
  const [step, setStep] = useState(0);
  const [balance, setBalance] = useState('');
  const [income, setIncome] = useState('');
  const [rent, setRent] = useState('');
  const [payFreq, setPayFreq] = useState<'monthly' | 'biweekly' | 'weekly'>('monthly');

  const finish = () => {
    void hapticSuccess();
    const updates: { settings: typeof settings; schedules: RecurringSchedule[] } = {
      settings: { ...settings, hasOnboarded: true, payFrequency: payFreq },
      schedules: [],
    };

    if (balance) {
      updates.settings.startingBalance = parseFloat(balance) || updates.settings.startingBalance;
    }

    const today = format(new Date(), 'yyyy-MM-dd');
    if (income && parseFloat(income) > 0) {
      const freqMap = { monthly: 'Monthly', biweekly: 'BiWeekly', weekly: 'Weekly' } as const;
      updates.schedules.push({
        id: `SCH-${Date.now()}-inc`,
        name: t('sugg_salary'),
        amount: parseFloat(income),
        startDate: today,
        frequency: freqMap[payFreq],
        dayValue: payFreq === 'monthly' ? 1 : 'Friday',
        enabled: true,
        category: 'salary',
      });
    }
    if (rent && parseFloat(rent) > 0) {
      updates.schedules.push({
        id: `SCH-${Date.now()}-rent`,
        name: t('sugg_rent'),
        amount: -parseFloat(rent),
        startDate: today,
        frequency: 'Monthly',
        dayValue: 1,
        enabled: true,
      });
    }

    // Replace defaults if user provided their own
    const newSchedules = updates.schedules.length > 0 ? updates.schedules : recurringSchedules;
    setRecurringSchedules(newSchedules);
    setSettings(updates.settings);
    saveWithOverrides(newSchedules, undefined, undefined, undefined, updates.settings, undefined);
  };

  const skip = () => {
    void hapticLight();
    const newSettings = { ...settings, hasOnboarded: true };
    setSettings(newSettings);
    saveWithOverrides(undefined, undefined, undefined, undefined, newSettings, undefined);
  };

  const next = () => {
    void hapticLight();
    setStep(s => s + 1);
  };

  return (
    <div className="fixed inset-0 z-[60] bg-white dark:bg-gray-950 flex items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-6">
        {step === 0 && (
          <div className="text-center space-y-5">
            <div className="text-6xl">💰</div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{t('welcome')}</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('welcome_desc')}</p>
            <div className="space-y-2 pt-3">
              <button onClick={next} className="w-full py-3 bg-ios-blue text-white rounded-xl font-semibold">{t('get_started')}</button>
              <button onClick={skip} className="w-full py-2 text-sm text-gray-500 hover:text-gray-700">{t('skip')}</button>
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="space-y-5">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">{t('starting_balance_q')}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('starting_balance_help')}</p>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-lg">{sym}</span>
              <input
                type="number"
                value={balance}
                onChange={(e) => setBalance(e.target.value)}
                placeholder="5000"
                className="w-full pl-10 pr-3 py-3 text-lg border border-gray-300 dark:border-gray-700 dark:bg-gray-900 dark:text-white rounded-xl focus:border-blue-500 focus:outline-none"
                autoFocus
              />
            </div>
            <div className="flex space-x-2">
              <button onClick={skip} className="flex-1 py-3 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-200 rounded-xl font-semibold text-sm">{t('skip')}</button>
              <button onClick={next} className="flex-[2] py-3 bg-ios-blue text-white rounded-xl font-semibold">{t('next')}</button>
            </div>
            <Dots step={step} total={4} />
          </div>
        )}

        {step === 2 && (
          <div className="space-y-5">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">{t('monthly_income_q')}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('monthly_income_help')}</p>
            {/* Pay frequency selector */}
            <div className="flex bg-gray-100 dark:bg-gray-800 rounded-xl p-1">
              {(['weekly', 'biweekly', 'monthly'] as const).map((f) => (
                <button key={f} type="button" onClick={() => { void hapticLight(); setPayFreq(f); }}
                  className={`flex-1 py-2 text-xs font-semibold rounded-lg transition ${payFreq === f ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow' : 'text-gray-500'}`}>
                  {f === 'weekly' ? t('weekly') : f === 'biweekly' ? t('biweekly') : t('monthly')}
                </button>
              ))}
            </div>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-lg">{sym}</span>
              <input
                type="number"
                value={income}
                onChange={(e) => setIncome(e.target.value)}
                placeholder={payFreq === 'monthly' ? '3000' : payFreq === 'biweekly' ? '1500' : '750'}
                className="w-full pl-10 pr-3 py-3 text-lg border border-gray-300 dark:border-gray-700 dark:bg-gray-900 dark:text-white rounded-xl focus:border-blue-500 focus:outline-none"
                autoFocus
              />
            </div>
            <div className="flex space-x-2">
              <button onClick={skip} className="flex-1 py-3 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-200 rounded-xl font-semibold text-sm">{t('skip')}</button>
              <button onClick={next} className="flex-[2] py-3 bg-ios-blue text-white rounded-xl font-semibold">{t('next')}</button>
            </div>
            <Dots step={step} total={4} />
          </div>
        )}

        {step === 3 && (
          <div className="space-y-5">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">{t('monthly_rent_q')}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{t('monthly_rent_help')}</p>
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 text-lg">{sym}</span>
              <input
                type="number"
                value={rent}
                onChange={(e) => setRent(e.target.value)}
                placeholder="1000"
                className="w-full pl-10 pr-3 py-3 text-lg border border-gray-300 dark:border-gray-700 dark:bg-gray-900 dark:text-white rounded-xl focus:border-blue-500 focus:outline-none"
                autoFocus
              />
            </div>
            <button onClick={finish} className="w-full py-3 bg-ios-blue text-white rounded-xl font-semibold">{t('finish_setup')}</button>
            <Dots step={step} total={4} />
          </div>
        )}
      </div>
    </div>
  );
}

function Dots({ step, total }: { step: number; total: number }) {
  return (
    <div className="flex justify-center space-x-1.5">
      {Array.from({ length: total }).map((_, i) => (
        <div key={i} className={`h-1.5 rounded-full transition-all ${i === step ? 'w-6 bg-ios-blue' : 'w-1.5 bg-gray-300 dark:bg-gray-700'}`} />
      ))}
    </div>
  );
}
