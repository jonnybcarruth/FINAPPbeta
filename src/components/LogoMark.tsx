'use client';

import { useEffect, useRef, useState } from 'react';

interface LogoMarkProps {
  size?: number;
  progress?: number;
  dark?: boolean;
}

export function LogoMark({ size = 40, progress = 1, dark = false }: LogoMarkProps) {
  const fill = dark ? '#FFFFFF' : '#0A0A0A';
  const accent = '#D8F2A8';
  const slotFill = Math.max(0, Math.min(1, progress));
  const uid = `logo-${size}-${Math.random().toString(36).slice(2, 6)}`;

  return (
    <svg width={size} height={size} viewBox="0 0 64 64" style={{ display: 'block' }}>
      <defs>
        <clipPath id={`slot-${uid}`}>
          <rect x="18" y="26" width="4" height="12" rx="2" />
        </clipPath>
      </defs>
      <rect width="64" height="64" rx="16" fill={fill} />
      <path
        d="M20 16 H32 a16 16 0 0 1 16 16 v0 a16 16 0 0 1 -16 16 H20 z"
        fill="none"
        stroke={accent}
        strokeWidth="4"
        strokeLinejoin="round"
        style={{
          strokeDasharray: 140,
          strokeDashoffset: 140 - 140 * slotFill,
          transition: 'stroke-dashoffset 1.2s cubic-bezier(0.32, 0.72, 0, 1)',
        }}
      />
      <g clipPath={`url(#slot-${uid})`}>
        <rect x="18" y="26" width="4" height="12" fill={fill === '#0A0A0A' ? '#1a1a1a' : '#222'} />
        <rect
          x="18"
          y={26 + 12 * (1 - slotFill)}
          width="4"
          height={12 * slotFill}
          fill={accent}
          style={{ transition: 'all 1s cubic-bezier(0.32, 0.72, 0, 1)' }}
        />
      </g>
    </svg>
  );
}

interface LogoLockupProps {
  height?: number;
  dark?: boolean;
  progress?: number;
}

export function LogoLockup({ height = 32, dark = false, progress = 1 }: LogoLockupProps) {
  const color = dark ? '#FFFFFF' : '#0A0A0A';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <LogoMark size={height} progress={progress} dark={dark} />
      <span style={{
        fontFamily: 'var(--font-display)', fontSize: height * 0.85, fontWeight: 500,
        letterSpacing: '-0.02em', color, lineHeight: 1,
      }}>DinDin</span>
    </div>
  );
}

interface TickerProps {
  value: number;
  format?: (v: number) => string;
}

export function Ticker({ value, format }: TickerProps) {
  const safeValue = value ?? 0;
  const [v, setV] = useState(safeValue);
  const fromRef = useRef(value);
  const startRef = useRef(0);

  useEffect(() => {
    fromRef.current = v;
    startRef.current = performance.now();
    let raf: number;
    const ease = (t: number) => 1 - Math.pow(1 - t, 3);
    const tick = (now: number) => {
      const t = Math.min(1, (now - startRef.current) / 900);
      setV(fromRef.current + (safeValue - fromRef.current) * ease(t));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [safeValue]);

  const defaultFmt = (n: number) => {
    const abs = Math.abs(Math.round(n));
    const s = abs.toLocaleString('en-US');
    return n < 0 ? `−$${s}` : `$${s}`;
  };

  return <span>{(format || defaultFmt)(v)}</span>;
}
