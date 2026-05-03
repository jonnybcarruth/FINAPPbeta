'use client';

import { useState, useEffect, useMemo } from 'react';
import { format } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useApp } from '@/context/AppContext';
import Navigation from '@/components/Navigation';
import StatusMessage from '@/components/StatusMessage';
import SlideMenu from '@/components/SlideMenu';
import Onboarding from '@/components/Onboarding';
import { LogoLockup } from '@/components/LogoMark';
import CalendarView from '@/components/views/CalendarView';
import DashboardView from '@/components/views/DashboardView';
import BillsView from '@/components/views/BillsView';
import SpendingPlanView from '@/components/views/SpendingPlanView';
import SavingsView from '@/components/views/SavingsView';
import { setHapticsEnabled } from '@/lib/haptics';
import { useT, useFmt, useLocale } from '@/lib/i18n';
import { useAuth } from '@/context/AuthContext';

export default function Home() {
  const { activeView, viewSlideDir, dataLoading, settings, syncState, dailyBalanceMap } = useApp();
  const { user } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [logoProgress, setLogoProgress] = useState(0);
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;

  useEffect(() => {
    setHapticsEnabled(settings.hapticsEnabled);
  }, [settings.hapticsEnabled]);

  useEffect(() => {
    setLogoProgress(0);
    const timer = setTimeout(() => setLogoProgress(1), 120);
    return () => clearTimeout(timer);
  }, []);

  // Negative balance alert
  const negativeAlert = useMemo(() => {
    const dates = Object.keys(dailyBalanceMap).sort();
    for (const dk of dates) {
      if (dailyBalanceMap[dk] < 0) return { date: dk, balance: dailyBalanceMap[dk] };
    }
    return null;
  }, [dailyBalanceMap]);

  if (dataLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center space-y-4" style={{ background: 'var(--bg)' }}>
        <LogoLockup height={40} dark={settings.darkMode} progress={logoProgress} />
        <p style={{ color: 'var(--fg-3)', fontSize: 14 }}>{t('loading_data')}</p>
      </div>
    );
  }

  const isDark = settings.darkMode;
  const initial = user?.email?.[0]?.toUpperCase() || 'U';

  return (
    <>
      <StatusMessage />
      {!settings.hasOnboarded && <Onboarding />}

      {/* Sticky negative balance banner */}
      {negativeAlert && (
        <div style={{
          position: 'sticky', top: 0, zIndex: 30,
          background: 'var(--negative)', color: '#fff',
          padding: '8px 16px', fontSize: 12, fontWeight: 600,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
        }}>
          <span>⚠</span>
          <span>{t('sticky_negative')} {fmt(negativeAlert.balance)} {t('sticky_negative_short')} {format(new Date(negativeAlert.date + 'T00:00:00'), 'MMM d', { locale: dateLocale })}</span>
        </div>
      )}

      <div style={{ maxWidth: 1280, margin: '0 auto', paddingBottom: 120 }}>
        {/* Header */}
        <header style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '6px 16px 12px',
        }}>
          <LogoLockup height={28} dark={isDark} progress={logoProgress} />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button className="dd-icon-btn" onClick={() => setMenuOpen(true)} aria-label="Menu">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>
            <div className="dd-avatar">{initial}</div>
          </div>
        </header>

        {/* Content */}
        <div style={{ padding: '0 16px' }}>
          <main key={activeView} className={viewSlideDir === 'left' ? 'view-slide-from-left' : 'view-slide-from-right'} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {activeView === 'calendar' && <CalendarView />}
            {activeView === 'dashboard' && <DashboardView />}
            {activeView === 'bills' && <BillsView />}
            {activeView === 'plan' && <SpendingPlanView />}
            {activeView === 'savings' && <SavingsView />}
          </main>
        </div>
      </div>

      <Navigation />
      <SlideMenu open={menuOpen} onClose={() => setMenuOpen(false)} />
    </>
  );
}
