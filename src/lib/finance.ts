import {
  addMonths, eachDayOfInterval, format, getDay, getDate,
  startOfMonth, addDays, parseISO, isBefore,
  differenceInDays, startOfISOWeek,
} from 'date-fns';
import type { RecurringSchedule, OneTimeTransaction, DebtPlan, SavingsPlan, Projection, DailyBalanceMap, TransactionLog } from './types';
import { WEEKLY_DAY_MAP } from './constants';

export function generateProjections(
  startDateStr: string,
  projectionMonths: number,
  recurringSchedules: RecurringSchedule[],
  oneTimeTransactions: OneTimeTransaction[],
  debtPlans: DebtPlan[],
  savingsPlans: SavingsPlan[] = [],
  transactionLogs: TransactionLog[] = []
): Projection[] {
  const startDate = new Date(startDateStr + 'T00:00:00');
  const endDate = addMonths(startDate, projectionMonths);
  const activeSchedules = recurringSchedules.filter((s) => s.enabled);
  const projections: Projection[] = [];

  // Build log lookup by projectionKey
  const logMap = new Map<string, TransactionLog>();
  transactionLogs.forEach((l) => logMap.set(l.projectionKey, l));

  const applyLog = (p: Projection): Projection => {
    const log = logMap.get(p.projectionKey);
    if (log) {
      return { ...p, amount: log.amount, completed: log.completed, notes: log.notes };
    }
    return p;
  };

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
        if (schedule.endDate && day > new Date(schedule.endDate + 'T00:00:00')) return;
        const dateStr = format(day, 'yyyy-MM-dd');
        const key = `rec:${schedule.id}:${dateStr}`;
        projections.push(applyLog({
          date: day, name: schedule.name, amount: schedule.amount,
          projectedAmount: schedule.amount,
          type: 'Recurring', category: schedule.category,
          projectionKey: key,
        }));
      }
    });
  });

  // 2. Debt payments
  debtPlans.filter((p) => p.enabled).forEach((plan) => {
    if (plan.debtType === 'revolving' && plan.interestRate && plan.minimumPayment) {
      let balance = plan.totalAmount;
      const monthlyRate = plan.interestRate / 100 / 12;
      let currentMonth = startOfMonth(startDate);
      while (currentMonth <= endDate && balance > 0.01) {
        const daysInMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 0).getDate();
        const clampedPayDay = Math.min(plan.payDay, daysInMonth);
        const day = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), clampedPayDay);
        if (day >= startDate && day <= endDate && day >= parseISO(plan.startDate)) {
          const interest = balance * monthlyRate;
          const payment = Math.min(balance + interest, plan.minimumPayment);
          balance = balance + interest - payment;
          const dateStr = format(day, 'yyyy-MM-dd');
          const key = `debt:${plan.id}:${dateStr}`;
          projections.push(applyLog({
            date: day, name: `Debt: ${plan.name}`, amount: -payment,
            projectedAmount: -payment,
            type: 'Debt Payment', category: plan.category || 'debt',
            projectionKey: key,
          }));
        }
        currentMonth = addMonths(currentMonth, 1);
      }
    } else {
      let paymentsMade = 0;
      let currentMonth = startOfMonth(startDate);
      while (currentMonth <= endDate && paymentsMade < plan.payoffMonths) {
        const daysInMonth = new Date(currentMonth.getFullYear(), currentMonth.getMonth() + 1, 0).getDate();
        const clampedPayDay = Math.min(plan.payDay, daysInMonth);
        const day = new Date(currentMonth.getFullYear(), currentMonth.getMonth(), clampedPayDay);
        if (day >= startDate && day <= endDate && day >= parseISO(plan.startDate)) {
          const dateStr = format(day, 'yyyy-MM-dd');
          const key = `debt:${plan.id}:${dateStr}`;
          projections.push(applyLog({
            date: day, name: `Debt: ${plan.name}`, amount: -plan.monthlyPayment,
            projectedAmount: -plan.monthlyPayment,
            type: 'Debt Payment', category: plan.category || 'debt',
            projectionKey: key,
          }));
          paymentsMade++;
        }
        currentMonth = addMonths(currentMonth, 1);
      }
    }
  });

  // 3. Savings plans
  const activeSavings = savingsPlans.filter((s) => s.enabled);
  const monthlyIncome = activeSchedules
    .filter((s) => s.amount > 0)
    .reduce((sum, s) => {
      if (s.frequency === 'Monthly') return sum + s.amount;
      if (s.frequency === 'Weekly') return sum + s.amount * 4.33;
      return sum + s.amount * 2.167;
    }, 0);

  eachDayOfInterval({ start: startDate, end: endDate }).forEach((day) => {
    activeSavings.forEach((plan) => {
      if (day < new Date(plan.startDate + 'T00:00:00')) return;
      if (plan.endDate && day > new Date(plan.endDate + 'T00:00:00')) return;
      const planStart = parseISO(plan.startDate);
      let shouldSave = false;

      if (plan.frequency === 'Monthly' && getDate(day) === plan.dayValue) {
        shouldSave = true;
      } else if (plan.frequency === 'Weekly' && getDay(day) === WEEKLY_DAY_MAP[plan.dayValue as string]) {
        shouldSave = true;
      } else if (plan.frequency === 'BiWeekly' && getDay(day) === WEEKLY_DAY_MAP[plan.dayValue as string]) {
        const daysSinceStart = differenceInDays(day, planStart);
        if (daysSinceStart >= 0) {
          const targetDow = WEEKLY_DAY_MAP[plan.dayValue as string];
          const startDow = getDay(planStart);
          let offset = targetDow - startDow;
          if (offset < 0) offset += 7;
          const rel = daysSinceStart - offset;
          if (rel >= 0 && rel % 14 === 0) shouldSave = true;
        }
      }

      if (shouldSave) {
        let amount = plan.amount;
        if (plan.isPercentOfIncome && plan.percentValue) {
          amount = monthlyIncome * (plan.percentValue / 100);
          if (plan.frequency === 'Weekly') amount /= 4.33;
          else if (plan.frequency === 'BiWeekly') amount /= 2.167;
        }
        const dateStr = format(day, 'yyyy-MM-dd');
        const key = `sav:${plan.id}:${dateStr}`;
        projections.push(applyLog({
          date: day, name: `Savings: ${plan.name}`, amount: -amount,
          projectedAmount: -amount,
          type: 'Savings', category: 'savings',
          projectionKey: key,
        }));
      }
    });
  });

  // 4. One-time transactions
  oneTimeTransactions.forEach((t) => {
    const tDate = new Date(t.date + 'T00:00:00');
    if (tDate >= startDate && tDate <= endDate) {
      const actualAmount = t.actual ?? t.amount;
      projections.push({
        date: tDate, name: t.name, amount: actualAmount,
        projectedAmount: t.amount,
        type: 'One-Time', id: t.id, category: t.category,
        projectionKey: `one:${t.id}`,
        completed: t.completed,
      });
    }
  });

  return projections.sort((a, b) => a.date.getTime() - b.date.getTime());
}

export function calculateDailyBalances(projections: Projection[], startingBalance: number): DailyBalanceMap {
  let runningCents = Math.round(startingBalance * 100);
  const map: DailyBalanceMap = {};
  projections.forEach((t) => {
    runningCents += Math.round(t.amount * 100);
    map[format(t.date, 'yyyy-MM-dd')] = runningCents / 100;
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
  let incomeCents = 0, expenseCents = 0;
  projections.forEach((p) => {
    if (p.amount > 0) incomeCents += Math.round(p.amount * 100);
    else expenseCents += Math.round(p.amount * 100);
  });
  const totalIncome = incomeCents / 100;
  const totalExpenses = expenseCents / 100;
  return { totalIncome, totalExpenses, endBalance: (Math.round(startingBalance * 100) + incomeCents + expenseCents) / 100, startingBalance };
}

// Find which transaction causes the first negative balance
export function findNegativeCause(projections: Projection[], startingBalance: number): { projection: Projection; balance: number } | null {
  let balCents = Math.round(startingBalance * 100);
  for (const p of projections) {
    balCents += Math.round(p.amount * 100);
    if (balCents < 0) return { projection: p, balance: balCents / 100 };
  }
  return null;
}

// 50/30/20 rule analysis
export function compute503020(projections: Projection[], totalIncome: number) {
  let needsCents = 0, wantsCents = 0, savingsCents = 0;
  const needsCats = new Set(['housing', 'groceries', 'transport', 'utilities', 'phone', 'health', 'insurance', 'childcare', 'debt', 'education']);
  const savingsCats = new Set(['savings', 'investment']);

  projections.forEach((p) => {
    if (p.amount >= 0) return;
    const cents = Math.abs(Math.round(p.amount * 100));
    if (p.type === 'Savings') { savingsCents += cents; return; }
    if (p.type === 'Debt Payment') { needsCents += cents; return; }
    if (p.category && needsCats.has(p.category)) { needsCents += cents; return; }
    if (p.category && savingsCats.has(p.category)) { savingsCents += cents; return; }
    wantsCents += cents;
  });

  const total = needsCents + wantsCents + savingsCents;
  return {
    needs: needsCents / 100,
    wants: wantsCents / 100,
    savings: savingsCents / 100,
    needsPct: total > 0 ? Math.round((needsCents / total) * 100) : 0,
    wantsPct: total > 0 ? Math.round((wantsCents / total) * 100) : 0,
    savingsPct: total > 0 ? Math.round((savingsCents / total) * 100) : 0,
  };
}

// Compute projected vs actual for a given date range
export function computeActualVsProjected(projections: Projection[], startDate: string, endDate: string) {
  const start = parseISO(startDate);
  const end = parseISO(endDate);
  let projectedIn = 0, projectedOut = 0;
  let actualIn = 0, actualOut = 0;
  let completedCount = 0;
  let totalCount = 0;

  projections.forEach((p) => {
    if (p.date < start || p.date > end) return;
    totalCount++;
    if (p.projectedAmount > 0) projectedIn += p.projectedAmount;
    else projectedOut += Math.abs(p.projectedAmount);

    if (p.completed) {
      completedCount++;
      if (p.amount > 0) actualIn += p.amount;
      else actualOut += Math.abs(p.amount);
    }
  });

  return {
    projectedIn, projectedOut,
    actualIn, actualOut,
    completedCount, totalCount,
    varianceIn: actualIn - projectedIn,
    varianceOut: actualOut - projectedOut,
  };
}
