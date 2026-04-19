export interface RecurringSchedule {
  id: string;
  name: string;
  amount: number;
  startDate: string;
  endDate?: string;
  frequency: 'Monthly' | 'Weekly' | 'BiWeekly';
  dayValue: number | string;
  enabled: boolean;
}

export interface OneTimeTransaction {
  id: string;
  name: string;
  amount: number;
  date: string;
  type?: string;
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
}

export interface Projection {
  date: Date;
  name: string;
  amount: number;
  type: 'Recurring' | 'One-Time' | 'Debt Payment' | 'Savings';
  id?: string;
}

export type ViewId = 'calendar' | 'dashboard' | 'bills' | 'plan' | 'savings';

export interface DailyBalanceMap {
  [dateKey: string]: number;
}

export interface DailyTransactionMap {
  [dateKey: string]: Projection[];
}
