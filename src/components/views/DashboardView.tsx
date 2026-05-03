'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { format, startOfMonth, endOfMonth } from 'date-fns';
import { ptBR, enUS } from 'date-fns/locale';
import { useApp } from '@/context/AppContext';
import { useT, useFmt, useLocale } from '@/lib/i18n';
import { compute503020, findNegativeCause, computeActualVsProjected } from '@/lib/finance';
import { Ticker } from '@/components/LogoMark';

export default function DashboardView() {
  const { metrics, projections, settings } = useApp();
  const t = useT();
  const fmt = useFmt();
  const locale = useLocale();
  const dateLocale = locale === 'pt-BR' ? ptBR : enUS;

  const totalSaved = useMemo(() =>
    projections.filter((p) => p.type === 'Savings').reduce((s, p) => s + Math.abs(p.amount), 0),
  [projections]);

  // Projection data points for SVG chart
  const projData = useMemo(() => {
    let bal = Math.round(settings.startingBalance * 100);
    const pts = [{ date: new Date(settings.startDate + 'T00:00:00'), val: bal / 100 }];
    projections.forEach((p) => {
      bal += Math.round(p.amount * 100);
      pts.push({ date: p.date, val: bal / 100 });
    });
    return pts;
  }, [projections, settings]);

  const minBal = useMemo(() => Math.min(...projData.map(p => p.val)), [projData]);
  const maxBal = useMemo(() => Math.max(...projData.map(p => p.val)), [projData]);

  // Negative balance
  const negativeCause = useMemo(() => findNegativeCause(projections, settings.startingBalance), [projections, settings]);
  const minBalance = useMemo(() => {
    let min = settings.startingBalance;
    let minDate = '';
    let bal = Math.round(settings.startingBalance * 100);
    projections.forEach((p) => {
      bal += Math.round(p.amount * 100);
      if (bal / 100 < min) { min = bal / 100; minDate = format(p.date, 'MMM d', { locale: dateLocale }); }
    });
    return { min, minDate };
  }, [projections, settings, dateLocale]);

  // 50/30/20
  const rule = useMemo(() => compute503020(projections, metrics.totalIncome), [projections, metrics]);

  const netSavings = metrics.totalIncome + metrics.totalExpenses;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Hero card */}
      <div className="dd-card" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span className="dd-overline">{t('end_balance')}</span>
            {netSavings > 0 && <span className="dd-pill">+{Math.round((netSavings / settings.startingBalance) * 100)}%</span>}
          </div>
          <div className="dd-display" style={{ fontVariantNumeric: 'tabular-nums' }}>
            <Ticker value={metrics.endBalance} />
          </div>
          <div style={{ marginTop: 8, color: 'var(--fg-2)', fontSize: 14 }}>
            <span style={{ color: 'var(--fg-1)', fontWeight: 600 }}>{netSavings >= 0 ? '+' : ''}{fmt(netSavings)}</span>
            {' '}{settings.language === 'pt' ? 'este mês' : 'this month'}
          </div>
        </div>

        {/* Inline projection chart */}
        <div style={{ marginTop: 24, position: 'relative', zIndex: 1 }}>
          <ProjectionChart data={projData} height={140} />
        </div>
      </div>

      {/* Stat tiles — 2 on mobile, 4 on desktop */}
      <div className="dd-stat-grid">
        <StatTile label={t('total_income')} value={fmt(metrics.totalIncome)} accent />
        <StatTile label={t('total_expenses')} value={fmt(Math.abs(metrics.totalExpenses))} />
        {totalSaved > 0 && <StatTile label={t('total_saved')} value={fmt(totalSaved)} accent />}
        <StatTile label={t('lowest_balance')} value={fmt(minBalance.min)} sub={minBalance.minDate} negative={minBalance.min < 0} />
      </div>

      {/* Negative balance warning */}
      {minBalance.min < 0 && negativeCause && (
        <div className="dd-card" style={{ padding: 16, borderLeft: '4px solid var(--negative)', background: 'var(--negative-bg)' }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--negative)', marginBottom: 4 }}>
            {t('projected_negative_balance')}
          </div>
          <div style={{ fontSize: 12, color: 'var(--fg-2)' }}>
            {settings.language === 'pt' ? 'Causado por' : 'Caused by'}: <strong>{negativeCause.projection.name}</strong> ({fmt(negativeCause.projection.amount)})
          </div>
        </div>
      )}

      {/* Lower cards — side by side on desktop */}
      <div className="dd-desktop-2col">

      {/* 50/30/20 Benchmark */}
      {metrics.totalIncome > 0 && (
        <div className="dd-card">
          <div className="dd-overline" style={{ marginBottom: 12 }}>
            {settings.language === 'pt' ? 'Regra 50/30/20' : '50/30/20 Rule'}
          </div>
          <BenchmarkBar label={settings.language === 'pt' ? 'Necessidades' : 'Needs'} pct={rule.needsPct} target={50} color="var(--fg-1)" />
          <BenchmarkBar label={settings.language === 'pt' ? 'Desejos' : 'Wants'} pct={rule.wantsPct} target={30} color="var(--fg-3)" />
          <BenchmarkBar label={t('savings')} pct={rule.savingsPct} target={20} color="var(--brand-neon)" />
        </div>
      )}

      {/* Projected vs Actual */}
      {(() => {
        const ms = format(startOfMonth(new Date()), 'yyyy-MM-dd');
        const me = format(endOfMonth(new Date()), 'yyyy-MM-dd');
        const pva = computeActualVsProjected(projections, ms, me);
        if (pva.totalCount === 0) return null;
        return (
          <div className="dd-card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div className="dd-overline">{t('projected_vs_actual')}</div>
              <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>{pva.completedCount}/{pva.totalCount} {t('bills_paid')}</span>
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, color: 'var(--fg-3)' }}>{t('projected')}</div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, fontWeight: 500 }}>{fmt(pva.projectedOut)}</div>
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 11, color: 'var(--fg-3)' }}>{t('actual')}</div>
                <div style={{ fontFamily: 'var(--font-display)', fontSize: 24, fontWeight: 500, color: pva.actualOut > pva.projectedOut ? 'var(--negative)' : 'var(--fg-1)' }}>{fmt(pva.actualOut)}</div>
              </div>
            </div>
          </div>
        );
      })()}

      </div>{/* end dd-desktop-2col */}

      {/* Upcoming transactions */}
      <div className="dd-card">
        <div className="dd-overline" style={{ marginBottom: 12 }}>
          {settings.language === 'pt' ? 'Próximos' : 'Upcoming'}
        </div>
        {projections.filter(p => p.date > new Date()).slice(0, 5).map((p, i, arr) => (
          <div key={i} className="dd-row" style={i === arr.length - 1 ? { borderBottom: 'none' } : {}}>
            <span className={`dd-dot ${incomeDot(p)}`} />
            <div style={{ flex: 1 }}>
              <div className="dd-row-name">{p.name}</div>
              <div className="dd-row-sub">{format(p.date, 'EEE, MMM d', { locale: dateLocale })}</div>
            </div>
            <div className="dd-row-amount" style={{ color: p.amount > 0 ? 'var(--brand-neon)' : 'var(--fg-1)' }}>
              {p.amount > 0 ? '+' : ''}{fmt(p.amount)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function incomeDot(p: { amount: number; type: string }) {
  if (p.amount > 0) return 'income';
  if (p.type === 'Savings') return 'savings';
  return 'bill';
}

function StatTile({ label, value, sub, accent, negative }: { label: string; value: string; sub?: string; accent?: boolean; negative?: boolean }) {
  return (
    <div className="dd-card dd-stat" style={{ padding: 16 }}>
      <div className="dd-overline">{label}</div>
      <div className="dd-stat-val" style={{ color: negative ? 'var(--negative)' : accent ? 'var(--fg-1)' : 'var(--fg-1)' }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--fg-3)' }}>{sub}</div>}
    </div>
  );
}

function BenchmarkBar({ label, pct, target, color }: { label: string; pct: number; target: number; color: string }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
        <span style={{ fontWeight: 600, color: 'var(--fg-1)' }}>{label}</span>
        <span style={{ color: 'var(--fg-3)' }}>{pct}%</span>
      </div>
      <div style={{ position: 'relative', height: 6, background: 'var(--surface-2)', borderRadius: 3 }}>
        <div style={{ height: 6, borderRadius: 3, background: color, width: `${Math.min(100, pct)}%`, transition: 'width 0.6s var(--ease)' }} />
        <div style={{ position: 'absolute', top: 0, height: 6, width: 1, background: 'var(--fg-4)', left: `${target}%` }} />
      </div>
    </div>
  );
}

function ProjectionChart({ data, height = 140 }: { data: { date: Date; val: number }[]; height?: number }) {
  const ref = useRef<SVGSVGElement>(null);
  const [hover, setHover] = useState<number | null>(null);

  if (data.length < 2) return null;

  const W = 600, H = height;
  const pad = { l: 8, r: 8, t: 16, b: 22 };
  const innerW = W - pad.l - pad.r;
  const innerH = H - pad.t - pad.b;

  const min = Math.min(...data.map(d => d.val)) - 200;
  const max = Math.max(...data.map(d => d.val)) + 200;
  const xs = data.map((_, i) => pad.l + (i / (data.length - 1)) * innerW);
  const ys = data.map((d) => pad.t + (1 - (d.val - min) / (max - min)) * innerH);

  let linePath = `M ${xs[0]},${ys[0]}`;
  for (let i = 1; i < xs.length; i++) {
    const cx = (xs[i - 1] + xs[i]) / 2;
    linePath += ` Q ${cx},${ys[i - 1]} ${cx},${(ys[i - 1] + ys[i]) / 2}`;
    linePath += ` T ${xs[i]},${ys[i]}`;
  }
  const areaPath = `${linePath} L ${xs[xs.length - 1]},${pad.t + innerH} L ${xs[0]},${pad.t + innerH} Z`;

  const onMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect) return;
    const x = (e.clientX - rect.left) / rect.width;
    setHover(Math.max(0, Math.min(data.length - 1, Math.round(x * (data.length - 1)))));
  };

  return (
    <div style={{ width: '100%', position: 'relative' }}>
      <svg ref={ref} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none"
        style={{ width: '100%', height, display: 'block', cursor: 'crosshair' }}
        onMouseMove={onMove} onMouseLeave={() => setHover(null)}>
        <defs>
          <linearGradient id="proj-grad" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="#D8F2A8" stopOpacity="0.55" />
            <stop offset="60%" stopColor="#D8F2A8" stopOpacity="0.05" />
            <stop offset="100%" stopColor="#D8F2A8" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((p) => (
          <line key={p} x1={pad.l} x2={W - pad.r} y1={pad.t + p * innerH} y2={pad.t + p * innerH}
            stroke="var(--line)" strokeDasharray="2 4" />
        ))}
        <path d={areaPath} fill="url(#proj-grad)" className="proj-area" />
        <path d={linePath} fill="none" stroke="var(--fg-1)" strokeWidth="2" strokeLinecap="round" className="proj-line" />
        <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r="4" fill="#D8F2A8" stroke="var(--fg-1)" strokeWidth="2" />
        {hover != null && (
          <g>
            <line x1={xs[hover]} x2={xs[hover]} y1={pad.t} y2={pad.t + innerH} stroke="var(--fg-1)" strokeOpacity="0.3" strokeDasharray="2 3" />
            <circle cx={xs[hover]} cy={ys[hover]} r="6" fill="var(--fg-1)" stroke="var(--surface)" strokeWidth="2" />
          </g>
        )}
      </svg>
      {hover != null && data[hover] && (
        <div style={{
          position: 'absolute', left: `calc(${(xs[hover] / W) * 100}% - 60px)`, top: 0,
          width: 120, textAlign: 'center', pointerEvents: 'none',
        }}>
          <div style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            {format(data[hover].date, 'MMM d')}
          </div>
          <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--fg-1)', fontVariantNumeric: 'tabular-nums' }}>
            ${Math.round(data[hover].val).toLocaleString()}
          </div>
        </div>
      )}
    </div>
  );
}
