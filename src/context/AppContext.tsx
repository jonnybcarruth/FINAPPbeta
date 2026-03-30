'use client';

import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import type { RecurringSchedule, OneTimeTransaction, DebtPlan, AppSettings, SpendingCategory, ViewId, Projection, DailyBalanceMap, DailyTransactionMap } from '@/lib/types';
import { loadFromStorage, saveToStorage } from '@/lib/storage';
import { generateProjections, calculateDailyBalances, computeMetrics } from '@/lib/finance';
import { format } from 'date-fns';

interface AppContextType {
  recurringSchedules: RecurringSchedule[];
  setRecurringSchedules: (s: RecurringSchedule[]) => void;
  oneTimeTransactions: OneTimeTransaction[];
  setOneTimeTransactions: (t: OneTimeTransaction[]) => void;
  debtPlans: DebtPlan[];
  setDebtPlans: (d: DebtPlan[]) => void;
  activeSpendingCategories: SpendingCategory[];
  setActiveSpendingCategories: (c: SpendingCategory[]) => void;
  settings: AppSettings;
  setSettings: (s: AppSettings) => void;
  activeView: ViewId;
  setActiveView: (v: ViewId) => void;
  currentCalendarDate: Date;
  setCurrentCalendarDate: (d: Date) => void;
  projections: Projection[];
  dailyBalanceMap: DailyBalanceMap;
  dailyTransactionMap: DailyTransactionMap;
  metrics: ReturnType<typeof computeMetrics>;
  statusMessage: { text: string; colorClass: string } | null;
  showStatus: (msg: string, cls: string) => void;
  saveAndRefresh: () => void;
  saveWithOverrides: (
    rs?: RecurringSchedule[],
    ot?: OneTimeTransaction[],
    dp?: DebtPlan[],
    cats?: SpendingCategory[],
    s?: AppSettings
  ) => void;
}

const AppContext = createContext<AppContextType | null>(null);

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [recurringSchedules, setRecurringSchedules] = useState<RecurringSchedule[]>([]);
  const [oneTimeTransactions, setOneTimeTransactions] = useState<OneTimeTransaction[]>([]);
  const [debtPlans, setDebtPlans] = useState<DebtPlan[]>([]);
  const [activeSpendingCategories, setActiveSpendingCategories] = useState<SpendingCategory[]>([]);
  const [settings, setSettings] = useState<AppSettings>({
    startDate: format(new Date(), 'yyyy-MM-dd'),
    projectionMonths: 12,
    startingBalance: 5000,
    calendarSize: 'large',
    showEODBalance: false,
    darkMode: false,
    savedAmount: 0,
  });
  const [activeView, setActiveView] = useState<ViewId>('calendar');
  const [currentCalendarDate, setCurrentCalendarDate] = useState(new Date());
  const [projections, setProjections] = useState<Projection[]>([]);
  const [dailyBalanceMap, setDailyBalanceMap] = useState<DailyBalanceMap>({});
  const [dailyTransactionMap, setDailyTransactionMap] = useState<DailyTransactionMap>({});
  const [metrics, setMetrics] = useState({ totalIncome: 0, totalExpenses: 0, endBalance: 0, startingBalance: 0 });
  const [statusMessage, setStatusMessage] = useState<{ text: string; colorClass: string } | null>(null);

  const showStatus = useCallback((text: string, colorClass: string) => {
    setStatusMessage({ text, colorClass });
    setTimeout(() => setStatusMessage(null), 3000);
  }, []);

  const recompute = useCallback(
    (rs: RecurringSchedule[], ot: OneTimeTransaction[], dp: DebtPlan[], s: AppSettings) => {
      const proj = generateProjections(s.startDate, s.projectionMonths, rs, ot, dp);
      const balMap = calculateDailyBalances(proj, s.startingBalance);
      const txMap: DailyTransactionMap = {};
      proj.forEach((p) => {
        const k = format(p.date, 'yyyy-MM-dd');
        if (!txMap[k]) txMap[k] = [];
        txMap[k].push(p);
      });
      setProjections(proj);
      setDailyBalanceMap(balMap);
      setDailyTransactionMap(txMap);
      setMetrics(computeMetrics(proj, s.startingBalance));
    },
    []
  );

  const saveAndRefresh = useCallback(() => {
    saveToStorage(recurringSchedules, oneTimeTransactions, debtPlans, activeSpendingCategories, settings);
    recompute(recurringSchedules, oneTimeTransactions, debtPlans, settings);
    showStatus('Saved!', 'bg-blue-100 text-blue-700');
  }, [recurringSchedules, oneTimeTransactions, debtPlans, activeSpendingCategories, settings, recompute, showStatus]);

  const saveWithOverrides = useCallback((
    rs: RecurringSchedule[] = recurringSchedules,
    ot: OneTimeTransaction[] = oneTimeTransactions,
    dp: DebtPlan[] = debtPlans,
    cats: SpendingCategory[] = activeSpendingCategories,
    s: AppSettings = settings
  ) => {
    saveToStorage(rs, ot, dp, cats, s);
    recompute(rs, ot, dp, s);
    showStatus('Saved!', 'bg-blue-100 text-blue-700');
  }, [recurringSchedules, oneTimeTransactions, debtPlans, activeSpendingCategories, settings, recompute, showStatus]);

  // Load on mount
  useEffect(() => {
    const data = loadFromStorage();
    setRecurringSchedules(data.recurringSchedules);
    setOneTimeTransactions(data.oneTimeTransactions);
    setDebtPlans(data.debtPlans);
    setActiveSpendingCategories(data.activeSpendingCategories);
    setSettings(data.settings);
    if (data.settings.darkMode) document.documentElement.classList.add('dark');
    recompute(data.recurringSchedules, data.oneTimeTransactions, data.debtPlans, data.settings);
  }, [recompute]);

  return (
    <AppContext.Provider value={{
      recurringSchedules, setRecurringSchedules,
      oneTimeTransactions, setOneTimeTransactions,
      debtPlans, setDebtPlans,
      activeSpendingCategories, setActiveSpendingCategories,
      settings, setSettings,
      activeView, setActiveView,
      currentCalendarDate, setCurrentCalendarDate,
      projections, dailyBalanceMap, dailyTransactionMap, metrics,
      statusMessage, showStatus, saveAndRefresh, saveWithOverrides,
    }}>
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
