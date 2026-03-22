'use client';

import { useApp } from '@/context/AppContext';

export default function StatusMessage() {
  const { statusMessage } = useApp();
  if (!statusMessage) return null;
  return (
    <div className={`fixed top-0 left-0 right-0 p-3 text-center text-sm font-medium shadow-lg z-50 transition duration-300 ${statusMessage.colorClass}`}>
      {statusMessage.text}
    </div>
  );
}
