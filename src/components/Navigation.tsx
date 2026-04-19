'use client';

import type { FC } from 'react';
import { useApp } from '@/context/AppContext';
import type { ViewId } from '@/lib/types';
import { hapticLight } from '@/lib/haptics';
import { useT } from '@/lib/i18n';

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

const BillsIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 2v20M5 5h11a3 3 0 0 1 0 6H8a3 3 0 0 0 0 6h11"/>
  </svg>
);

const PlanIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 12l4-9 4 9 4-9 4 9 4-9"/>
    <path d="M3 21h18"/>
  </svg>
);

const SavingsIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 21V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v16"/>
    <path d="M3 21h18"/>
    <path d="M12 7v7"/>
    <path d="M9 10l3-3 3 3"/>
  </svg>
);

const NAV_ITEMS: { id: ViewId; labelKey: string; Icon: FC }[] = [
  { id: 'calendar', labelKey: 'calendar', Icon: CalendarIcon },
  { id: 'dashboard', labelKey: 'dashboard', Icon: DashboardIcon },
  { id: 'bills', labelKey: 'bills', Icon: BillsIcon },
  { id: 'savings', labelKey: 'savings', Icon: SavingsIcon },
  { id: 'plan', labelKey: 'plan', Icon: PlanIcon },
];

export default function Navigation() {
  const { activeView, setActiveView, setViewSlideDir } = useApp();
  const t = useT();

  const handleNav = (id: ViewId) => {
    const from = NAV_ITEMS.findIndex((n) => n.id === activeView);
    const to = NAV_ITEMS.findIndex((n) => n.id === id);
    setViewSlideDir(to < from ? 'left' : 'right');
    setActiveView(id);
    void hapticLight();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <nav id="bottom-nav">
      <div className="flex justify-around items-center h-full max-w-2xl mx-auto px-1">
        {NAV_ITEMS.map(({ id, labelKey, Icon }) => (
          <button
            key={id}
            data-view={id}
            onClick={() => handleNav(id)}
            className={`nav-btn flex flex-col items-center justify-center flex-1 py-1 gap-0.5 transition-colors ${activeView === id ? 'active-nav' : ''}`}
          >
            <Icon />
            <span style={{ fontSize: '10px', fontWeight: activeView === id ? 600 : 500, letterSpacing: '-0.01em' }}>{t(labelKey)}</span>
          </button>
        ))}
      </div>
    </nav>
  );
}
