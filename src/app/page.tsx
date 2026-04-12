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
  schedules: 'Recurring',
  plan: 'Spending Plan',
  log: 'Transactions',
};

export default function Home() {
  const { activeView, viewSlideDir, dataLoading } = useApp();

  if (dataLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-gray-500">Loading your data…</p>
      </div>
    );
  }

  return (
    <>
      <StatusMessage />
      <div className="container mx-auto px-0 sm:px-4 md:px-8 pt-4 pb-40">
        <header className="mb-5 px-4 sm:px-0">
          <p className="text-xs font-semibold uppercase tracking-widest text-ios-gray mb-0.5">DinDin</p>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white" style={{ letterSpacing: '-0.02em' }}>
            {VIEW_LABELS[activeView]}
          </h1>
        </header>

        <main key={activeView} className={`${viewSlideDir === 'left' ? 'view-slide-from-right' : 'view-slide-from-left'} space-y-4 md:space-y-6`}>
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
