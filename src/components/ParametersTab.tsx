import { Check, Minus, TriangleAlert, X } from 'lucide-react';
import { compare, type Row, type RowStatus } from '../lib/compare';
import type { Site } from '../lib/types';
import { cn } from '../utils/cn';
import { SiteBadge } from './ui';

const ICON: Record<RowStatus, { icon: typeof Check; cls: string; word: string }> = {
  match: { icon: Check, cls: 'bg-ok/15 text-ok', word: 'match' },
  mismatch: { icon: X, cls: 'bg-bad text-ink', word: 'mismatch' },
  warn: { icon: TriangleAlert, cls: 'bg-warn/20 text-warn', word: 'differs, not fatal' },
  na: { icon: Minus, cls: 'bg-raised text-mute', word: 'not applicable' },
};

const COLS = 'grid grid-cols-[minmax(0,1fr)_24px_minmax(0,1fr)] gap-x-2 sm:grid-cols-[172px_minmax(0,1fr)_24px_minmax(0,1fr)] sm:gap-x-3';

function RowView({ r }: { r: Row }) {
  const s = ICON[r.status];
  const bad = r.status === 'mismatch';
  return (
    <li className={cn(COLS, 'items-center px-3 py-2', bad && 'bg-bad/[0.06]')}>
      <div className="col-span-3 mb-0.5 text-[11.5px] text-mute sm:col-span-1 sm:mb-0 sm:text-[12.5px]">{r.label}</div>
      <div className={cn('font-mono text-[12.5px] leading-snug [overflow-wrap:anywhere]', bad ? 'text-fg' : 'text-fg/85')}>{r.a}</div>
      <div className={cn('grid h-5 w-5 place-items-center justify-self-center rounded-full', s.cls)}>
        <s.icon className="h-3 w-3" strokeWidth={3} aria-hidden />
        <span className="sr-only">{s.word}</span>
      </div>
      <div className={cn('font-mono text-[12.5px] leading-snug [overflow-wrap:anywhere]', bad ? 'text-fg' : 'text-fg/85')}>{r.b}</div>
      {r.note && <div className="col-span-3 mt-0.5 text-[11.5px] leading-snug text-mute sm:col-span-3 sm:col-start-2">{r.note}</div>}
    </li>
  );
}

export function ParametersTab({ a, b }: { a: Site; b: Site }) {
  const rows = compare(a, b);
  const groups = ['Reachability', 'Phase 1 · IKE', 'Phase 2 · IPsec'] as const;
  const count = (s: RowStatus) => rows.filter((r) => r.status === s).length;

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12.5px]">
        <span className="text-mute">Pre-flight check of both configurations, updated as you type.</span>
        <span className="ml-auto flex gap-3 font-mono text-[12px]">
          <span className="text-ok">{count('match')} match</span>
          <span className={count('mismatch') ? 'text-bad' : 'text-mute'}>{count('mismatch')} mismatch</span>
          <span className={count('warn') ? 'text-warn' : 'text-mute'}>{count('warn')} differ</span>
        </span>
      </div>

      <div className="overflow-hidden rounded-lg border border-line bg-well/60">
        <div className={cn(COLS, 'items-center border-b border-line px-3 py-2.5')}>
          <div className="hidden sm:block" />
          <div className="flex min-w-0 items-center gap-1.5">
            <SiteBadge site="A" />
            <span className="truncate text-[13px] font-medium">{a.name}</span>
          </div>
          <div />
          <div className="flex min-w-0 items-center gap-1.5">
            <SiteBadge site="B" />
            <span className="truncate text-[13px] font-medium">{b.name}</span>
          </div>
        </div>
        {groups.map((g) => (
          <section key={g} aria-label={g}>
            <h3 className="border-b border-t border-line bg-raised/50 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] text-mute first:border-t-0">{g}</h3>
            <ul className="divide-y divide-line/60">
              {rows.filter((r) => r.group === g).map((r) => (
                <RowView key={r.label} r={r} />
              ))}
            </ul>
          </section>
        ))}
      </div>
    </div>
  );
}
