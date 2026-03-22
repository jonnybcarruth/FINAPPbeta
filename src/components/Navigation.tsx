'use client';

import { useApp } from '@/context/AppContext';
import type { ViewId } from '@/lib/types';

const NAV_ITEMS: { id: ViewId; label: string; icon: string }[] = [
  { id: 'calendar', label: 'Calendar', icon: '📅' },
  { id: 'dashboard', label: 'Dashboard', icon: '📊' },
  { id: 'debt', label: 'Debt', icon: '💳' },
  { id: 'schedules', label: 'Schedules', icon: '🔁' },
  { id: 'plan', label: 'Plan', icon: '💰' },
  { id: 'log', label: 'Log', icon: '📋' },
];

export default function Navigation() {
  const { activeView, setActiveView } = useApp();
  return (
    <nav id="bottom-nav">
      <div className="flex justify-around items-center h-full max-w-2xl mx-auto px-2">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            data-view={item.id}
            onClick={() => setActiveView(item.id)}
            className={`nav-btn flex flex-col items-center justify-center px-2 py-1 text-xs transition-colors ${activeView === item.id ? 'active-nav' : 'text-gray-500 hover:text-gray-700'}`}
          >
            <span className="text-lg mb-0.5">{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
      </div>
    </nav>
  );
}
