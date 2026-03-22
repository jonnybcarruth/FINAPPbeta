import type { RecurringSchedule, OneTimeTransaction, DebtPlan, AppSettings, SpendingCategory } from './types';
import { DEFAULT_SCHEDULES, SPENDING_CATEGORIES } from './constants';
import { format } from 'date-fns';

export function loadFromStorage() {
  const recurringSchedules: RecurringSchedule[] = JSON.parse(
    localStorage.getItem('recurringSchedules') || 'null'
  ) ?? DEFAULT_SCHEDULES;

  const oneTimeTransactions: OneTimeTransaction[] = JSON.parse(
    localStorage.getItem('oneTimeTransactions') || '[]'
  );

  const debtPlans: DebtPlan[] = JSON.parse(
    localStorage.getItem('debtPlans') || '[]'
  );

  const activeSpendingCategories: SpendingCategory[] = JSON.parse(
    localStorage.getItem('activeSpendingCategories') || 'null'
  ) ?? SPENDING_CATEGORIES.map((c) => ({ ...c, enabled: c.defaultEnabled }));

  const settings: AppSettings = {
    startDate: localStorage.getItem('startDate') || format(new Date(), 'yyyy-MM-dd'),
    projectionMonths: parseInt(localStorage.getItem('projectionMonths') || '12'),
    startingBalance: parseFloat(localStorage.getItem('startingBalance') || '5000'),
    calendarSize: (localStorage.getItem('calendarSize') as AppSettings['calendarSize']) || 'large',
    showEODBalance: localStorage.getItem('showEODBalance') === 'true',
    darkMode: localStorage.getItem('darkMode') === 'true',
    savedAmount: parseFloat(localStorage.getItem('savedAmount') || '0'),
  };

  return { recurringSchedules, oneTimeTransactions, debtPlans, activeSpendingCategories, settings };
}

export function saveToStorage(
  recurringSchedules: RecurringSchedule[],
  oneTimeTransactions: OneTimeTransaction[],
  debtPlans: DebtPlan[],
  activeSpendingCategories: SpendingCategory[],
  settings: AppSettings
) {
  localStorage.setItem('recurringSchedules', JSON.stringify(recurringSchedules));
  localStorage.setItem('oneTimeTransactions', JSON.stringify(oneTimeTransactions));
  localStorage.setItem('debtPlans', JSON.stringify(debtPlans));
  localStorage.setItem('activeSpendingCategories', JSON.stringify(activeSpendingCategories));
  localStorage.setItem('startDate', settings.startDate);
  localStorage.setItem('projectionMonths', String(settings.projectionMonths));
  localStorage.setItem('startingBalance', String(settings.startingBalance));
  localStorage.setItem('calendarSize', settings.calendarSize);
  localStorage.setItem('showEODBalance', String(settings.showEODBalance));
  localStorage.setItem('darkMode', String(settings.darkMode));
  localStorage.setItem('savedAmount', settings.savedAmount.toFixed(2));
}
