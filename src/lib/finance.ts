import {
  addMonths, eachDayOfInterval, format, getDay, getDate,
  startOfMonth, addDays, parseISO, isBefore, isSameDay,
  differenceInDays, startOfISOWeek,
} from 'date-fns';
import type { RecurringSchedule, OneTimeTransaction, DebtPlan, Projection, DailyBalanceMap } from './types';
import { WEEKLY_DAY_MAP } from './constants';

export function generateProjections(
  startDateStr: string,
  projectionMonths: number,
  recurringSchedules: RecurringSchedule[],
  oneTimeTransactions: OneTimeTransaction[],
  debtPlans: DebtPlan[]
): Projection[] {
  const startDate = new Date(startDateStr + 'T00:00:00');
  const endDate = addMonths(startDate, projectionMonths);
  const activeSchedules = recurringSchedules.filter((s) => s.enabled);
  const projections: Projection[] = [];

  // 1. Recurring
  eachDayOfInterval({ start: startDate, end: endDate }).forEach((day) => {
    activeSchedules.forEach((schedule) => {
      if (day < new Date(schedule.startDate + 'T00:00:00')) return;
      const scheduleStart = parseISO(schedule.startDate);
      let shouldPay = false;

      if (schedule.frequency === 'Monthly' && getDate(day) === schedule.dayValue) {
        shouldPay = true;
      } else if (schedule.frequency === 'Weekly' && getDay(day) === WEEKLY_DAY_MAP[schedule.dayValue as string]) {
        shouldPay = true;
      } else if (schedule.frequency === 'BiWeekly' && getDay(day) === WEEKLY_DAY_MAP[schedule.dayValue as string]) {
        const daysSinceStart = differenceInDays(day, scheduleStart);
        if (daysSinceStart >= 0) {
          const targetDow = WEEKLY_DAY_MAP[schedule.dayValue as string];
          const startDow = getDay(scheduleStart);
          let offset = targetDow - startDow;
          if (offset < 0) offset += 7;
          const rel = daysSinceStart - offset;
          if (rel >= 0 && rel % 14 === 0) shouldPay = true;
        }
      }

      if (shouldPay) {
        projections.push({ date: day, name: schedule.name, amount: schedule.amount, type: 'Recurring' });
      }
    });
  });

  // 2. Debt payments
  debtPlans.forEach((plan) => {
    let paymentsMade = 0;
    let currentMonth = startOfMonth(startDate);
    while (currentMonth <= endDate && paymentsMade < plan.payoffMonths) {
      const day = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), plan.payDay);
      if (day >= startDate && day <= endDate && day >= parseISO(plan.startDate)) {
        projections.push({ date: day, name: `Debt Payment: ${plan.name}`, amount: -plan.monthlyPayment, type: 'Debt Payment' });
        paymentsMade++;
      }
      currentMonth = addMonths(currentMonth, 1);
    }
  });

  // 3. One-time transactions
  oneTimeTransactions.forEach((t) => {
    const tDate = new Date(t.date + 'T00:00:00');
    if (tDate >= startDate && tDate <= endDate) {
      projections.push({ date: tDate, name: t.name, amount: t.amount, type: 'One-Time', id: t.id });
    }
  });

  return projections.sort((a, b) => a.date.getTime() - b.date.getTime());
}

export function calculateDailyBalances(projections: Projection[], startingBalance: number): DailyBalanceMap {
  let running = startingBalance;
  const map: DailyBalanceMap = {};
  projections.forEach((t) => {
    running += t.amount;
    map[format(t.date, 'yyyy-MM-dd')] = running;
  });
  return map;
}

export function getEndOfDayBalance(
  dateKey: string,
  dailyBalanceMap: DailyBalanceMap,
  startDateStr: string,
  startingBalance: number
): number {
  if (dailyBalanceMap[dateKey] !== undefined) return dailyBalanceMap[dateKey];
  let lookBack = addDays(parseISO(dateKey), -1);
  const projStart = parseISO(startDateStr);
  while (lookBack >= projStart) {
    const key = format(lookBack, 'yyyy-MM-dd');
    if (dailyBalanceMap[key] !== undefined) return dailyBalanceMap[key];
    lookBack = addDays(lookBack, -1);
  }
  return startingBalance;
}

export function calculateTotalWeeks(startDate: string, projectionMonths: number): number {
  const start = parseISO(startDate);
  const end = addMonths(start, projectionMonths);
  let weeks = 0;
  let cur = startOfISOWeek(start);
  while (isBefore(cur, end)) { weeks++; cur = addDays(cur, 7); }
  return weeks;
}

export function computeMetrics(projections: Projection[], startingBalance: number) {
  let totalIncome = 0, totalExpenses = 0;
  projections.forEach((p) => {
    if (p.amount > 0) totalIncome += p.amount;
    else totalExpenses += p.amount;
  });
  return { totalIncome, totalExpenses, endBalance: startingBalance + totalIncome + totalExpenses, startingBalance };
}
