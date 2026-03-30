'use client';

import type { FC } from 'react';
import { useApp } from '@/context/AppContext';
import type { ViewId } from '@/lib/types';

const CalendarIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="4" width="18" height="18" rx="2.5"/>
    <line x1="16" y1="2" x2="16" y2="6"/>
    <line x1="8" y1="2" x2="8" y2="6"/>
    <line x1="3" y1="10" x2="21" y2="10"/>
  </svg>
);

const DashboardIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="9" rx="1.5"/>
    <rect x="14" y="3" width="7" height="5" rx="1.5"/>
    <rect x="14" y="12" width="7" height="9" rx="1.5"/>
    <rect x="3" y="16" width="7" height="5" rx="1.5"/>
  </svg>
);

const DebtIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <rect x="1" y="5" width="22" height="14" rx="2.5"/>
    <line x1="1" y1="10" x2="23" y2="10"/>
    <line x1="6" y1="15" x2="9" y2="15"/>
    <line x1="12" y1="15" x2="15" y2="15"/>
  </svg>
);

const SchedulesIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="17 2 21 6 17 10"/>
    <path d="M3 11V9a4 4 0 0 1 4-4h14"/>
    <polyline points="7 22 3 18 7 14"/>
    <path d="M21 13v2a4 4 0 0 1-4 4H3"/>
  </svg>
);

const PlanIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <line x1="12" y1="2" x2="12" y2="22"/>
    <path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
  </svg>
);

const LogIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <line x1="9" y1="6" x2="20" y2="6"/>
    <line x1="9" y1="12" x2="20" y2="12"/>
    <line x1="9" y1="18" x2="20" y2="18"/>
    <circle cx="4" cy="6" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="4" cy="12" r="1.5" fill="currentColor" stroke="none"/>
    <circle cx="4" cy="18" r="1.5" fill="currentColor" stroke="none"/>
  </svg>
);

const NAV_ITEMS: { id: ViewId; label: string; Icon: FC }[] = [
  { id: 'calendar', label: 'Calendar', Icon: CalendarIcon },
  { id: 'dashboard', label: 'Dashboard', Icon: DashboardIcon },
  { id: 'debt', label: 'Debt', Icon: DebtIcon },
  { id: 'schedules', label: 'Schedules', Icon: SchedulesIcon },
  { id: 'plan', label: 'Plan', Icon: PlanIcon },
  { id: 'log', label: 'Log', Icon: LogIcon },
];

export default function Navigation() {
  const { activeView, setActiveView } = useApp();
  return (
    <nav id="bottom-nav">
      <div className="flex justify-around items-center h-full max-w-2xl mx-auto px-1">
        {NAV_ITEMS.map(({ id, label, Icon }) => (
          <button
            key={id}
            data-view={id}
            onClick={() => setActiveView(id)}
            className={`nav-btn flex flex-col items-center justify-center flex-1 py-1 gap-0.5 transition-colors ${activeView === id ? 'active-nav' : ''}`}
          >
            <Icon />
            <span style={{ fontSize: '10px', fontWeight: activeView === id ? 600 : 500, letterSpacing: '-0.01em' }}>{label}</span>
          </button>
        ))}
      </div>
    </nav>
  );
}
