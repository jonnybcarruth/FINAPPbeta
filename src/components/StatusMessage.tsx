'use client';

import { useApp } from '@/context/AppContext';

export default function StatusMessage() {
  const { statusMessage } = useApp();
  if (!statusMessage) return null;

  const isSuccess = statusMessage.text.includes('Saved') || statusMessage.text.includes('Salvo');

  return (
    <div
      style={{
        position: 'fixed', top: 12, left: '50%', transform: 'translateX(-50%)',
        zIndex: 60, animation: 'statusIn 0.3s var(--ease) both',
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '10px 20px', borderRadius: 'var(--radius-pill)',
        background: 'var(--fg-1)', color: 'var(--surface)',
        fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-ui)',
        boxShadow: 'var(--shadow-md)',
        pointerEvents: 'none',
      }}
    >
      {isSuccess && (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--brand-neon)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ animation: 'checkPop 0.4s var(--ease) both', animationDelay: '0.1s' }}>
          <polyline points="20 6 9 17 4 12" />
        </svg>
      )}
      <span>{statusMessage.text}</span>
    </div>
  );
}
