import { addDays, addMonths, parseISO, isBefore, isSameDay, format, startOfISOWeek } from 'date-fns';
import type { SpendingCategory, OneTimeTransaction } from './types';
import { calculateTotalWeeks } from './finance';

export interface PlanDefinition {
  name: string;
  margin: number;
  buttonClass: string;
}

export const PLAN_DEFINITIONS: PlanDefinition[] = [
  { name: 'Aggressive Spending (100% Budget)', margin: 1.0, buttonClass: 'bg-red-600 hover:bg-red-700' },
  { name: 'Balanced Spending (75% Budget)', margin: 0.75, buttonClass: 'bg-blue-600 hover:bg-blue-700' },
  { name: 'Conservative Spending (50% Budget)', margin: 0.50, buttonClass: 'bg-green-600 hover:bg-green-700' },
];

export interface CategoryBreakdown {
  name: string;
  amount: number;
}

export function computePlanBreakdown(
  categories: SpendingCategory[],
  baseWeeklyBudget: number,
  margin: number
): CategoryBreakdown[] {
  const enabled = categories.filter((c) => c.enabled);
  const totalFixed = enabled.filter((c) => c.fixedWeeklyAmount > 0).reduce((s, c) => s + c.fixedWeeklyAmount, 0);
  const varCats = enabled.filter((c) => c.fixedWeeklyAmount === 0);
  const totalVarPct = varCats.reduce((s, c) => s + c.percentage, 0);
  const varBudget = (baseWeeklyBudget * margin) - totalFixed;

  return enabled.map((cat) => {
    let amount: number;
    if (cat.fixedWeeklyAmount > 0) {
      amount = cat.fixedWeeklyAmount;
    } else {
      amount = varBudget > 0 && totalVarPct > 0 ? varBudget * (cat.percentage / totalVarPct) : 0;
      if (cat.name === 'Gas/Fuel') { if (amount > 100) amount = 100; if (amount < 30) amount = 30; }
    }
    return { name: cat.name, amount: Math.max(0, amount) };
  });
}

export function applyPlan(
  breakdown: CategoryBreakdown[],
  planName: string,
  startDate: string,
  projectionMonths: number,
  existingTransactions: OneTimeTransaction[]
): OneTimeTransaction[] {
  const filtered = existingTransactions.filter((t) => !t.name.includes('(Planned)'));
  const totalWeeks = calculateTotalWeeks(startDate, projectionMonths);
  let cur = startOfISOWeek(parseISO(startDate));
  const limit = addMonths(parseISO(startDate), projectionMonths);
  const newTxs: OneTimeTransaction[] = [];

  for (let i = 0; i < totalWeeks; i++) {
    const weekDate = addDays(cur, 4);
    if (isBefore(weekDate, limit) || isSameDay(weekDate, limit)) {
      breakdown.forEach((cat) => {
        if (cat.amount > 0.01) {
          newTxs.push({
            id: `PLAN-${Date.now()}-${i}-${cat.name}`,
            name: `${cat.name} (Planned)`,
            amount: -cat.amount,
            date: format(weekDate, 'yyyy-MM-dd'),
            type: 'One-Time',
          });
        }
      });
    }
    cur = addDays(cur, 7);
  }

  return [...filtered, ...newTxs];
}
