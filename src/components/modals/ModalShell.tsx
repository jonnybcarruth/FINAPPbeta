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
      className={`fixed inset-0 flex items-center justify-center z-50 p-4 ${phase === 'in' ? 'modal-backdrop-in' : 'modal-backdrop-out'}`}
      style={{ background: 'rgba(10,10,10,0.5)', backdropFilter: 'blur(4px)', WebkitBackdropFilter: 'blur(4px)' }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className={`relative w-full max-w-md max-h-[85vh] overflow-y-auto ${phase === 'in' ? 'modal-panel-in' : 'modal-panel-out'}`}
        style={{
          background: 'var(--surface)',
          borderRadius: 'var(--radius-lg)',
          border: '1px solid var(--line)',
          boxShadow: 'var(--shadow-lg)',
          padding: 24,
        }}
      >
        {title && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
            <h3 className="dd-h3">{title}</h3>
            <button className="dd-icon-btn" onClick={onClose} aria-label="Close" style={{ width: 28, height: 28 }}>
              <svg width="12" height="12" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round">
                <line x1="1" y1="1" x2="13" y2="13"/>
                <line x1="13" y1="1" x2="1" y2="13"/>
              </svg>
            </button>
          </div>
        )}
        {children}
      </div>
    </div>
  );
}
