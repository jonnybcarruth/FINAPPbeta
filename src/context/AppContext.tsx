'use client';

import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import type {
  RecurringSchedule,
  OneTimeTransaction,
  DebtPlan,
  AppSettings,
  SpendingCategory,
  ViewId,
  Projection,
  DailyBalanceMap,
  DailyTransactionMap,
} from '@/lib/types';
import {
  loadFromCloud,
  saveToCloud,
  loadFromLocalStorage,
  saveToLocalStorage,
  migrateLocalToCloudIfNeeded,
  defaultData,
  type AppData,
} from '@/lib/storage';
import { generateProjections, calculateDailyBalances, computeMetrics } from '@/lib/finance';
import { format } from 'date-fns';
import { useAuth } from '@/context/AuthContext';

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
  viewSlideDir: 'left' | 'right';
  setViewSlideDir: (d: 'left' | 'right') => void;
  currentCalendarDate: Date;
  setCurrentCalendarDate: (d: Date) => void;
  projections: Projection[];
  dailyBalanceMap: DailyBalanceMap;
  dailyTransactionMap: DailyTransactionMap;
  metrics: ReturnType<typeof computeMetrics>;
  statusMessage: { text: string; colorClass: string } | null;
  showStatus: (msg: string, cls: string) => void;
  dataLoading: boolean;
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
  const { user, loading: authLoading } = useAuth();

  const initial = defaultData();
  const [recurringSchedules, setRecurringSchedules] = useState<RecurringSchedule[]>(initial.recurringSchedules);
  const [oneTimeTransactions, setOneTimeTransactions] = useState<OneTimeTransaction[]>(initial.oneTimeTransactions);
  const [debtPlans, setDebtPlans] = useState<DebtPlan[]>(initial.debtPlans);
  const [activeSpendingCategories, setActiveSpendingCategories] = useState<SpendingCategory[]>(
    initial.activeSpendingCategories
  );
  const [settings, setSettings] = useState<AppSettings>(initial.settings);
  const [activeView, setActiveView] = useState<ViewId>('calendar');
  const [viewSlideDir, setViewSlideDir] = useState<'left' | 'right'>('right');
  const [currentCalendarDate, setCurrentCalendarDate] = useState(new Date());
  const [projections, setProjections] = useState<Projection[]>([]);
  const [dailyBalanceMap, setDailyBalanceMap] = useState<DailyBalanceMap>({});
  const [dailyTransactionMap, setDailyTransactionMap] = useState<DailyTransactionMap>({});
  const [metrics, setMetrics] = useState({ totalIncome: 0, totalExpenses: 0, endBalance: 0, startingBalance: 0 });
  const [statusMessage, setStatusMessage] = useState<{ text: string; colorClass: string } | null>(null);
  const [dataLoading, setDataLoading] = useState(true);

  // Track whether the current in-memory state originated from a load (so we don't
  // immediately overwrite the cloud with the default state during the initial render).
  const hasLoadedRef = useRef(false);

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

  const applyData = useCallback(
    (data: AppData) => {
      setRecurringSchedules(data.recurringSchedules);
      setOneTimeTransactions(data.oneTimeTransactions);
      setDebtPlans(data.debtPlans);
      setActiveSpendingCategories(data.activeSpendingCategories);
      setSettings(data.settings);
      if (data.settings.darkMode) document.documentElement.classList.add('dark');
      else document.documentElement.classList.remove('dark');
      recompute(data.recurringSchedules, data.oneTimeTransactions, data.debtPlans, data.settings);
    },
    [recompute]
  );

  // Load data whenever the user changes (login, logout, initial mount).
  useEffect(() => {
    if (authLoading) return;
    let cancelled = false;

    async function run() {
      setDataLoading(true);
      hasLoadedRef.current = false;
      try {
        if (user) {
          // Authenticated: pull from cloud, migrate local if needed.
          const migrated = await migrateLocalToCloudIfNeeded(user.id);
          const cloud = migrated ?? (await loadFromCloud(user.id));
          const data = cloud ?? defaultData();
          if (cancelled) return;
          applyData(data);
        } else {
          // Not logged in — render a blank default so the UI doesn't flicker.
          // (AuthGate redirects to /login, so this path is rarely visible.)
          const local = loadFromLocalStorage();
          if (cancelled) return;
          applyData(local);
        }
      } catch (e) {
        console.error('[AppContext] failed to load data', e);
        if (!cancelled) applyData(defaultData());
      } finally {
        if (!cancelled) {
          hasLoadedRef.current = true;
          setDataLoading(false);
        }
      }
    }

    run();
    return () => {
      cancelled = true;
    };
  }, [user, authLoading, applyData]);

  const persist = useCallback(
    async (data: AppData) => {
      // Always keep a local copy as offline cache
      saveToLocalStorage(data);
      if (user) {
        try {
          await saveToCloud(user.id, data);
        } catch (e) {
          console.error('[AppContext] cloud save failed', e);
          showStatus('Saved locally — cloud sync failed', 'bg-yellow-100 text-yellow-800');
          return;
        }
      }
      showStatus('Saved!', 'bg-blue-100 text-blue-700');
    },
    [user, showStatus]
  );

  const saveAndRefresh = useCallback(() => {
    const data: AppData = {
      recurringSchedules,
      oneTimeTransactions,
      debtPlans,
      activeSpendingCategories,
      settings,
    };
    recompute(recurringSchedules, oneTimeTransactions, debtPlans, settings);
    void persist(data);
  }, [recurringSchedules, oneTimeTransactions, debtPlans, activeSpendingCategories, settings, recompute, persist]);

  const saveWithOverrides = useCallback(
    (
      rs: RecurringSchedule[] = recurringSchedules,
      ot: OneTimeTransaction[] = oneTimeTransactions,
      dp: DebtPlan[] = debtPlans,
      cats: SpendingCategory[] = activeSpendingCategories,
      s: AppSettings = settings
    ) => {
      const data: AppData = {
        recurringSchedules: rs,
        oneTimeTransactions: ot,
        debtPlans: dp,
        activeSpendingCategories: cats,
        settings: s,
      };
      recompute(rs, ot, dp, s);
      void persist(data);
    },
    [recurringSchedules, oneTimeTransactions, debtPlans, activeSpendingCategories, settings, recompute, persist]
  );

  return (
    <AppContext.Provider
      value={{
        recurringSchedules,
        setRecurringSchedules,
        oneTimeTransactions,
        setOneTimeTransactions,
        debtPlans,
        setDebtPlans,
        activeSpendingCategories,
        setActiveSpendingCategories,
        settings,
        setSettings,
        activeView,
        setActiveView,
        viewSlideDir,
        setViewSlideDir,
        currentCalendarDate,
        setCurrentCalendarDate,
        projections,
        dailyBalanceMap,
        dailyTransactionMap,
        metrics,
        statusMessage,
        showStatus,
        dataLoading,
        saveAndRefresh,
        saveWithOverrides,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
