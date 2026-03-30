'use client';

import { useState, useEffect } from 'react';

interface ModalShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}

export default function ModalShell({ open, onClose, title, children }: ModalShellProps) {
  const [visible, setVisible] = useState(false);
  const [phase, setPhase] = useState<'in' | 'out'>('in');

  useEffect(() => {
    if (open) {
      setPhase('in');
      setVisible(true);
    } else if (visible) {
      setPhase('out');
      const t = setTimeout(() => setVisible(false), 180);
      return () => clearTimeout(t);
    }
  }, [open]);

  if (!visible) return null;

  return (
    <div
      className={`fixed inset-0 overflow-y-auto h-full w-full flex items-end sm:items-center justify-center z-50 ${phase === 'in' ? 'modal-backdrop-in' : 'modal-backdrop-out'}`}
      style={{ background: 'rgba(0,0,0,0.45)', backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className={`relative w-full sm:max-w-md bg-white dark:bg-gray-800 sm:rounded-2xl rounded-t-2xl shadow-2xl p-6 sm:p-8 ${phase === 'in' ? 'modal-panel-in' : 'modal-panel-out'}`}
      >
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100" style={{ letterSpacing: '-0.01em' }}>{title}</h3>
          <button
            onClick={onClose}
            className="w-7 h-7 flex items-center justify-center rounded-full bg-gray-100 dark:bg-gray-700 text-gray-500 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            aria-label="Close"
          >
            <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round">
              <line x1="1" y1="1" x2="13" y2="13"/>
              <line x1="13" y1="1" x2="1" y2="13"/>
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
