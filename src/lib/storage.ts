import type {
  RecurringSchedule,
  OneTimeTransaction,
  DebtPlan,
  SavingsPlan,
  AppSettings,
  SpendingCategory,
} from './types';
import { DEFAULT_SCHEDULES, SPENDING_CATEGORIES } from './constants';
import { format } from 'date-fns';
import { supabase } from './supabase';

export interface AppData {
  recurringSchedules: RecurringSchedule[];
  oneTimeTransactions: OneTimeTransaction[];
  debtPlans: DebtPlan[];
  savingsPlans: SavingsPlan[];
  activeSpendingCategories: SpendingCategory[];
  settings: AppSettings;
}

function defaultData(): AppData {
  return {
    recurringSchedules: DEFAULT_SCHEDULES,
    oneTimeTransactions: [],
    debtPlans: [],
    savingsPlans: [],
    activeSpendingCategories: SPENDING_CATEGORIES.map((c) => ({ ...c, enabled: c.defaultEnabled })),
    settings: {
      startDate: format(new Date(), 'yyyy-MM-dd'),
      projectionMonths: 12,
      startingBalance: 5000,
      calendarSize: 'large',
      showEODBalance: false,
      darkMode: false,
      savedAmount: 0,
      hapticsEnabled: true,
      soundsEnabled: true,
      currency: 'USD',
      language: 'en',
    },
  };
}

// ---------- Local storage (pre-auth fallback + offline cache) ----------

const LOCAL_KEYS = [
  'recurringSchedules',
  'oneTimeTransactions',
  'debtPlans',
  'savingsPlans',
  'activeSpendingCategories',
  'startDate',
  'projectionMonths',
  'startingBalance',
  'calendarSize',
  'showEODBalance',
  'darkMode',
  'savedAmount',
];

export function loadFromLocalStorage(): AppData {
  if (typeof window === 'undefined') return defaultData();

  const recurringSchedules: RecurringSchedule[] =
    JSON.parse(localStorage.getItem('recurringSchedules') || 'null') ?? DEFAULT_SCHEDULES;

  const oneTimeTransactions: OneTimeTransaction[] = JSON.parse(
    localStorage.getItem('oneTimeTransactions') || '[]'
  );

  const debtPlans: DebtPlan[] = JSON.parse(localStorage.getItem('debtPlans') || '[]');

  const savingsPlans: SavingsPlan[] = JSON.parse(localStorage.getItem('savingsPlans') || '[]');

  const activeSpendingCategories: SpendingCategory[] =
    JSON.parse(localStorage.getItem('activeSpendingCategories') || 'null') ??
    SPENDING_CATEGORIES.map((c) => ({ ...c, enabled: c.defaultEnabled }));

  const settings: AppSettings = {
    startDate: localStorage.getItem('startDate') || format(new Date(), 'yyyy-MM-dd'),
    projectionMonths: parseInt(localStorage.getItem('projectionMonths') || '12'),
    startingBalance: parseFloat(localStorage.getItem('startingBalance') || '5000'),
    calendarSize: (localStorage.getItem('calendarSize') as AppSettings['calendarSize']) || 'large',
    showEODBalance: localStorage.getItem('showEODBalance') === 'true',
    darkMode: localStorage.getItem('darkMode') === 'true',
    savedAmount: parseFloat(localStorage.getItem('savedAmount') || '0'),
    hapticsEnabled: localStorage.getItem('hapticsEnabled') !== 'false',
    soundsEnabled: localStorage.getItem('soundsEnabled') !== 'false',
    currency: (localStorage.getItem('currency') as AppSettings['currency']) || 'USD',
    language: (localStorage.getItem('language') as AppSettings['language']) || 'en',
  };

  return { recurringSchedules, oneTimeTransactions, debtPlans, savingsPlans, activeSpendingCategories, settings };
}

export function saveToLocalStorage(data: AppData) {
  if (typeof window === 'undefined') return;
  localStorage.setItem('recurringSchedules', JSON.stringify(data.recurringSchedules));
  localStorage.setItem('oneTimeTransactions', JSON.stringify(data.oneTimeTransactions));
  localStorage.setItem('debtPlans', JSON.stringify(data.debtPlans));
  localStorage.setItem('savingsPlans', JSON.stringify(data.savingsPlans));
  localStorage.setItem('activeSpendingCategories', JSON.stringify(data.activeSpendingCategories));
  localStorage.setItem('startDate', data.settings.startDate);
  localStorage.setItem('projectionMonths', String(data.settings.projectionMonths));
  localStorage.setItem('startingBalance', String(data.settings.startingBalance));
  localStorage.setItem('calendarSize', data.settings.calendarSize);
  localStorage.setItem('showEODBalance', String(data.settings.showEODBalance));
  localStorage.setItem('darkMode', String(data.settings.darkMode));
  localStorage.setItem('savedAmount', data.settings.savedAmount.toFixed(2));
  localStorage.setItem('hapticsEnabled', String(data.settings.hapticsEnabled));
  localStorage.setItem('soundsEnabled', String(data.settings.soundsEnabled));
  localStorage.setItem('currency', data.settings.currency);
  localStorage.setItem('language', data.settings.language);
}

export function hasLocalData(): boolean {
  if (typeof window === 'undefined') return false;
  return LOCAL_KEYS.some((k) => localStorage.getItem(k) !== null);
}

export function clearLocalData() {
  if (typeof window === 'undefined') return;
  LOCAL_KEYS.forEach((k) => localStorage.removeItem(k));
}

// ---------- Cloud storage (Supabase) ----------

/**
 * Load the authenticated user's data from Supabase.
 * Returns null if the user has no row yet.
 * All rows are protected by Row-Level Security so users can only
 * ever read their own records (see supabase/schema.sql).
 */
export async function loadFromCloud(userId: string): Promise<AppData | null> {
  const { data, error } = await supabase
    .from('user_data')
    .select('data')
    .eq('user_id', userId)
    .maybeSingle();

  if (error) {
    console.error('[storage] loadFromCloud error', error);
    throw error;
  }
  if (!data?.data) return null;

  const defaults = defaultData();
  const cloud = data.data as Partial<AppData>;
  const merged: AppData = {
    ...defaults,
    ...cloud,
    settings: { ...defaults.settings, ...(cloud.settings || {}) },
  };
  return merged;
}

export async function saveToCloud(userId: string, data: AppData): Promise<void> {
  const { error } = await supabase
    .from('user_data')
    .upsert(
      {
        user_id: userId,
        data,
        updated_at: new Date().toISOString(),
      },
      { onConflict: 'user_id' }
    );

  if (error) {
    console.error('[storage] saveToCloud error', error);
    throw error;
  }
}

/**
 * First-login migration: if the user has data stashed in localStorage from
 * a pre-auth session AND their cloud row is empty, push the local data up
 * so they don't lose anything, then clear local copies.
 */
export async function migrateLocalToCloudIfNeeded(userId: string): Promise<AppData | null> {
  if (!hasLocalData()) return null;
  const existingCloud = await loadFromCloud(userId);
  if (existingCloud) return existingCloud; // cloud wins if both exist
  const local = loadFromLocalStorage();
  await saveToCloud(userId, local);
  clearLocalData();
  return local;
}

export { defaultData };
