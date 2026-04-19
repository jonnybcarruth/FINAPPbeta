'use client';

import { useState, useEffect, useMemo } from 'react';
import { format } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useApp } from '@/context/AppContext';
import Navigation from '@/components/Navigation';
import StatusMessage from '@/components/StatusMessage';
import SlideMenu from '@/components/SlideMenu';
import Onboarding from '@/components/Onboarding';
import CalendarView from '@/components/views/CalendarView';
import DashboardView from '@/components/views/DashboardView';
import BillsView from '@/components/views/BillsView';
import SpendingPlanView from '@/components/views/SpendingPlanView';
import SavingsView from '@/components/views/SavingsView';
import { setHapticsEnabled } from '@/lib/haptics';
import { useT, useFmt, useLocale } from '@/lib/i18n';

export default function Home() {
  const { activeView, viewSlideDir, dataLoading, settings, syncState, dailyBalanceMap } = useApp();
  const [menuOpen, setMenuOpen] = useState(false);
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;

  const VIEW_LABELS: Record<string, string> = {
    calendar: t('calendar'),
    dashboard: t('dashboard'),
    bills: t('bills'),
    plan: t('spending_plan'),
    savings: t('savings'),
  };

  useEffect(() => {
    setHapticsEnabled(settings.hapticsEnabled);
  }, [settings.hapticsEnabled]);

  // Find first negative balance date for sticky banner
  const negativeAlert = useMemo(() => {
    const dates = Object.keys(dailyBalanceMap).sort();
    for (const dk of dates) {
      if (dailyBalanceMap[dk] < 0) {
        return { date: dk, balance: dailyBalanceMap[dk] };
      }
    }
    return null;
  }, [dailyBalanceMap]);

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
      {!settings.hasOnboarded && <Onboarding />}

      {/* Sticky negative balance banner */}
      {negativeAlert && (
        <div className="sticky top-0 z-30 bg-red-600 text-white px-4 py-2 text-xs font-semibold flex items-center justify-center space-x-2 shadow-md">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <span>{t('sticky_negative')} {fmt(negativeAlert.balance)} {t('sticky_negative_short')} {format(new Date(negativeAlert.date + 'T00:00:00'), 'MMM d', { locale: dateLocale })}</span>
        </div>
      )}

      <div className="container mx-auto px-0 sm:px-4 md:px-8 pt-4 pb-40">
        <header className="mb-5 px-4 sm:px-0 flex items-center justify-between">
          <button
            onClick={() => setMenuOpen(true)}
            className="w-10 h-10 flex items-center justify-center rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors -ml-2"
            aria-label="Open menu"
          >
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>
          <h1 className="text-lg font-bold text-gray-900 dark:text-white" style={{ letterSpacing: '-0.01em' }}>
            {VIEW_LABELS[activeView]}
          </h1>
          <SyncIndicator state={syncState} />
        </header>

        <main key={activeView} className={`${viewSlideDir === 'left' ? 'view-slide-from-right' : 'view-slide-from-left'} space-y-4 md:space-y-6`}>
          {activeView === 'calendar' && <CalendarView />}
          {activeView === 'dashboard' && <DashboardView />}
          {activeView === 'bills' && <BillsView />}
          {activeView === 'plan' && <SpendingPlanView />}
          {activeView === 'savings' && <SavingsView />}
        </main>
      </div>
      <Navigation />
      <SlideMenu open={menuOpen} onClose={() => setMenuOpen(false)} />
    </>
  );
}

function SyncIndicator({ state }: { state: 'idle' | 'syncing' | 'error' }) {
  const t = useT();
  const color = state === 'error' ? 'bg-red-500' : state === 'syncing' ? 'bg-yellow-400' : 'bg-emerald-500';
  const label = state === 'error' ? t('sync_error') : state === 'syncing' ? t('sync_syncing') : t('sync_synced');
  return (
    <div className="w-10 h-10 flex items-center justify-center -mr-2" title={label}>
      <span className={`w-2.5 h-2.5 rounded-full ${color} ${state === 'syncing' ? 'animate-pulse' : ''}`} aria-label={label} />
    </div>
  );
}
