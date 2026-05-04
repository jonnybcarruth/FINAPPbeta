import type { CategoryId } from './categories';

export interface RecurringSchedule {
  id: string;
  name: string;
  amount: number;
  startDate: string;
  endDate?: string;
  frequency: 'Monthly' | 'Weekly' | 'BiWeekly';
  dayValue: number | string;
  enabled: boolean;
  category?: CategoryId;
}

export interface OneTimeTransaction {
  id: string;
  name: string;
  amount: number;
  date: string;
  type?: string;
  category?: CategoryId;
  actual?: number;
  completed?: boolean;
}

export interface DebtPlan {
  id: string;
  name: string;
  totalAmount: number;
  payoffMonths: number;
  monthlyPayment: number;
  payDay: number;
  startDate: string;
  enabled: boolean;
  category?: CategoryId;
  debtType?: 'fixed' | 'revolving';
  interestRate?: number;
  minimumPayment?: number;
}

export interface SavingsPlan {
  id: string;
  name: string;
  amount: number;
  frequency: 'Weekly' | 'BiWeekly' | 'Monthly';
  dayValue: number | string;
  startDate: string;
  endDate?: string;
  goalAmount?: number;
  enabled: boolean;
  isPercentOfIncome?: boolean;
  percentValue?: number;
}

export interface SpendingCategory {
  name: string;
  percentage: number;
  fixedWeeklyAmount: number;
  defaultEnabled: boolean;
  enabled: boolean;
}

export interface AppSettings {
  startDate: string;
  projectionMonths: number;
  startingBalance: number;
  calendarSize: 'small' | 'large';
  showEODBalance: boolean;
  darkMode: boolean;
  savedAmount: number;
  hapticsEnabled: boolean;
  soundsEnabled: boolean;
  currency: 'USD' | 'BRL';
  language: 'en' | 'pt';
  hasOnboarded: boolean;
  payFrequency?: 'weekly' | 'biweekly' | 'monthly';
  smartBudgetEnabled?: boolean;
  customCategories?: { id: string; en: string; pt: string }[];
}

export interface Projection {
  date: Date;
  name: string;
  amount: number;
  type: 'Recurring' | 'One-Time' | 'Debt Payment' | 'Savings';
  id?: string;
  category?: CategoryId;
  projectionKey: string;
  projectedAmount: number;
  completed?: boolean;
  notes?: string;
}

export interface TransactionLog {
  projectionKey: string;
  amount: number;
  completed: boolean;
  notes?: string;
  loggedAt: string;
}

export type ViewId = 'calendar' | 'dashboard' | 'bills' | 'plan' | 'savings';

export interface DailyBalanceMap {
  [dateKey: string]: number;
}

export interface DailyTransactionMap {
  [dateKey: string]: Projection[];
}
