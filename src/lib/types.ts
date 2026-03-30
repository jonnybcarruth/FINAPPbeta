export interface RecurringSchedule {
  id: string;
  name: string;
  amount: number;
  startDate: string;
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
  calendarSize: 'small' | 'medium' | 'large';
  showEODBalance: boolean;
  darkMode: boolean;
  savedAmount: number;
}

export interface Projection {
  date: Date;
  name: string;
  amount: number;
  type: 'Recurring' | 'One-Time' | 'Debt Payment';
  id?: string;
}

export type ViewId = 'calendar' | 'dashboard' | 'debt' | 'schedules' | 'plan' | 'log';

export interface DailyBalanceMap {
  [dateKey: string]: number;
}

export interface DailyTransactionMap {
  [dateKey: string]: Projection[];
}
