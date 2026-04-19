'use client';

import { useState, useEffect } from 'react';
import { useApp } from '@/context/AppContext';
import Navigation from '@/components/Navigation';
import StatusMessage from '@/components/StatusMessage';
import SettingsPanel from '@/components/SettingsPanel';
import SlideMenu from '@/components/SlideMenu';
import CalendarView from '@/components/views/CalendarView';
import DashboardView from '@/components/views/DashboardView';
import DebtPlansView from '@/components/views/DebtPlansView';
import RecurringSchedulesView from '@/components/views/RecurringSchedulesView';
import SpendingPlanView from '@/components/views/SpendingPlanView';
import SavingsView from '@/components/views/SavingsView';
import { setHapticsEnabled } from '@/lib/haptics';
import { useT } from '@/lib/i18n';

export default function Home() {
  const { activeView, viewSlideDir, dataLoading, settings } = useApp();
  const [menuOpen, setMenuOpen] = useState(false);
  const t = useT();

  const VIEW_LABELS: Record<string, string> = {
    calendar: t('calendar'),
    dashboard: t('dashboard'),
    debt: t('debt_plans'),
    schedules: t('recurring'),
    plan: t('spending_plan'),
    savings: t('savings'),
  };

  useEffect(() => {
    setHapticsEnabled(settings.hapticsEnabled);
  }, [settings.hapticsEnabled]);

  if (dataLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 border-3 border-blue-500 border-t-transparent rounded-full animate-spin" />
        <p className="text-sm text-gray-500">{t('loading_data')}</p>
      </div>
    );
  }

  return (
    <>
      <StatusMessage />
      <div className="container mx-auto px-0 sm:px-4 md:px-8 pt-4 pb-40">
        <header className="mb-5 px-4 sm:px-0 flex justify-between items-start">
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-ios-gray mb-0.5">DinDin</p>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white" style={{ letterSpacing: '-0.02em' }}>
              {VIEW_LABELS[activeView]}
            </h1>
          </div>
          <button
            onClick={() => setMenuOpen(true)}
            className="w-10 h-10 flex items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors mt-1"
            aria-label="Open menu"
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>
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
          {activeView === 'savings' && <SavingsView />}
        </main>
      </div>
      <Navigation />
      <SlideMenu open={menuOpen} onClose={() => setMenuOpen(false)} />
    </>
  );
}
