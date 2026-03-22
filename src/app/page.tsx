'use client';

import { useApp } from '@/context/AppContext';
import Navigation from '@/components/Navigation';
import StatusMessage from '@/components/StatusMessage';
import SettingsPanel from '@/components/SettingsPanel';
import CalendarView from '@/components/views/CalendarView';
import DashboardView from '@/components/views/DashboardView';
import DebtPlansView from '@/components/views/DebtPlansView';
import RecurringSchedulesView from '@/components/views/RecurringSchedulesView';
import SpendingPlanView from '@/components/views/SpendingPlanView';
import TransactionLogView from '@/components/views/TransactionLogView';

const VIEW_LABELS: Record<string, string> = {
  calendar: 'Calendar',
  dashboard: 'Dashboard',
  debt: 'Debt Plans',
  schedules: 'Recurring Schedules',
  plan: 'Spending Plan',
  log: 'Transaction Log',
};

export default function Home() {
  const { activeView } = useApp();

  return (
    <>
      <StatusMessage />
      <div className="container mx-auto px-0 sm:px-4 md:px-8 pt-4 pb-40">
        <header className="text-center mb-6">
          <h1 className="text-3xl md:text-4xl font-bold text-dindin-green">DinDin</h1>
          <h2 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mt-2">
            {VIEW_LABELS[activeView]}
          </h2>
        </header>

        <main className="space-y-8 md:space-y-12">
          {activeView === 'calendar' && (
            <>
              <CalendarView />
              <SettingsPanel />
            </>
          )}
          {activeView === 'dashboard' && <DashboardView />}
          {activeView === 'debt' && <DebtPlansView />}
          {activeView === 'schedules' && <RecurringSchedulesView />}
          {activeView === 'plan' && <SpendingPlanView />}
          {activeView === 'log' && <TransactionLogView />}
        </main>
      </div>
      <Navigation />
    </>
  );
}
