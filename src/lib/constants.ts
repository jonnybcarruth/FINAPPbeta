import type { RecurringSchedule, SpendingCategory } from './types';

export const DEFAULT_SCHEDULES: RecurringSchedule[] = [
  {
    id: 'RENT-01',
    name: 'Monthly Rent Payment',
    amount: -1010.0,
    startDate: '2024-01-03',
    frequency: 'Monthly',
    dayValue: 3,
    enabled: true,
  },
  {
    id: 'SALARY-01',
    name: 'Weekly Salary',
    amount: 1000.0,
    startDate: '2024-01-04',
    frequency: 'Weekly',
    dayValue: 'Thursday',
    enabled: true,
  },
];

export const SPENDING_CATEGORIES: SpendingCategory[] = [
  { name: 'Groceries', percentage: 40, fixedWeeklyAmount: 0, defaultEnabled: true, enabled: true },
  { name: 'Gas/Fuel', percentage: 30, fixedWeeklyAmount: 0, defaultEnabled: true, enabled: true },
  { name: 'Misc. Spending', percentage: 30, fixedWeeklyAmount: 0, defaultEnabled: true, enabled: true },
  { name: 'Transportation', percentage: 0, fixedWeeklyAmount: 50.0, defaultEnabled: false, enabled: false },
];

export const WEEKLY_DAY_MAP: Record<string, number> = {
  Sunday: 0,
  Monday: 1,
  Tuesday: 2,
  Wednesday: 3,
  Thursday: 4,
  Friday: 5,
  Saturday: 6,
};

export const CALENDAR_SIZES: Record<string, string> = {
  small: '320px',
  large: '600px',
};
