'use client';

import { useApp } from '@/context/AppContext';
import type { ViewId } from '@/lib/types';
import { hapticLight } from '@/lib/haptics';
import { useT } from '@/lib/i18n';

const NAV_ITEMS: { id: ViewId | 'add'; labelKey: string; icon: string; isAdd?: boolean }[] = [
  { id: 'calendar',  labelKey: 'calendar',  icon: 'M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM3 9h18M8 3v4M16 3v4' },
  { id: 'dashboard', labelKey: 'dashboard', icon: 'M3 20V10M9 20V4M15 20v-7M21 20v-3' },
  { id: 'add',       labelKey: '',          icon: 'M12 5v14M5 12h14', isAdd: true },
  { id: 'bills',     labelKey: 'bills',     icon: 'M12 2v20M5 5h11a3 3 0 0 1 0 6H8a3 3 0 0 0 0 6h11' },
  { id: 'savings',   labelKey: 'savings',   icon: 'M19 21V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v16M3 21h18M12 7v7M9 10l3-3 3 3' },
];

interface Props {
  onAdd?: () => void;
}

export default function Navigation({ onAdd }: Props) {
  const { activeView, setActiveView, setViewSlideDir } = useApp();
  const t = useT();

  const handleNav = (id: string) => {
    if (id === 'add') {
      onAdd?.();
      return;
    }
    const viewId = id as ViewId;
    const fromIdx = NAV_ITEMS.findIndex((n) => n.id === activeView);
    const toIdx = NAV_ITEMS.findIndex((n) => n.id === viewId);
    setViewSlideDir(toIdx < fromIdx ? 'left' : 'right');
    setActiveView(viewId);
    void hapticLight();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <nav id="bottom-nav">
      <div className="flex justify-around items-center h-full max-w-2xl mx-auto px-1">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            onClick={() => handleNav(item.id)}
            className={`dd-tab ${!item.isAdd && activeView === item.id ? 'active' : ''} ${item.isAdd ? 'add' : ''}`}
          >
            {item.isAdd ? (
              <div className="dd-fab">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <path d={item.icon} />
                </svg>
              </div>
            ) : (
              <>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                  <path d={item.icon} />
                </svg>
                <span>{t(item.labelKey)}</span>
              </>
            )}
          </button>
        ))}
      </div>
    </nav>
  );
}
