import { Play, X } from 'lucide-react';
import { useEffect, useMemo, useRef } from 'react';
import { rejectedBy, type SaState, type SimResult, type Step, type StepStatus } from '../lib/simulate';
import type { Site, SiteKey, VendorId } from '../lib/types';
import { VENDORS } from '../lib/vendors';
import { cn } from '../utils/cn';
import { Chip, EmptyState, PrimaryButton, SiteBadge } from './ui';

const LOG_SOURCE: Record<VendorId, (v2: boolean) => string> = {
  'cisco-ios': (v2) => (v2 ? 'debug crypto ikev2' : 'debug crypto isakmp'),
  'cisco-asa': () => 'show logging (level debugging)',
  fortigate: () => 'diagnose debug application ike -1',
  paloalto: () => 'System log, subtype vpn',
  'juniper-srx': () => 'show log kmd',
  mikrotik: () => '/log print where topics~"ipsec"',
  strongswan: () => 'swanctl --log',
  azure: () => 'Azure Log Analytics · IKEDiagnosticLog',
};

function Arrow({ ltr, status, atReceiver }: { ltr: boolean; status: StepStatus; atReceiver: boolean }) {
  const ok = status === 'ok';
  return (
    <div className={cn('relative my-1.5 h-4', !ltr && '-scale-x-100')} aria-hidden>
      {status === 'lost' ? (
        <>
          <div className="absolute left-0 top-1/2 w-1/2 -translate-y-1/2 border-t border-dashed border-bad" />
          <span className="absolute left-1/2 top-1/2 grid h-4 w-4 -translate-x-1/2 -translate-y-1/2 place-items-center rounded-full bg-bad text-ink">
            <X className="h-3 w-3" strokeWidth={3} />
          </span>
        </>
      ) : (
        <>
          <div className={cn('absolute left-0 right-2 top-1/2 h-px -translate-y-1/2', ok ? 'bg-fg/45' : 'bg-bad')} />
          {!ok && atReceiver ? (
            <span className="absolute right-0 top-1/2 grid h-4 w-4 -translate-y-1/2 place-items-center rounded-full bg-bad text-ink">
              <X className="h-3 w-3" strokeWidth={3} />
            </span>
          ) : (
            <span
              className={cn(
                'absolute right-0 top-1/2 h-0 w-0 -translate-y-1/2 border-y-[5px] border-l-[8px] border-y-transparent',
                ok ? 'border-l-fg/60' : 'border-l-bad',
              )}
            />
          )}
        </>
      )}
    </div>
  );
}

function Row({ step, a, b }: { step: Step; a: Site; b: Site }) {
  const ltr = step.from === 'A';
  const bad = step.status !== 'ok';
  const from = step.from === 'A' ? a : b;
  const to = step.from === 'A' ? b : a;
  const who = step.status === 'fail' ? rejectedBy(step) : null;
  return (
    <li className="animate-rise px-3 py-3 sm:px-6">
      <div className="flex flex-wrap items-baseline justify-center gap-x-2 gap-y-0.5 text-center">
        <span className={cn('font-mono text-[13px] font-medium', bad ? 'text-bad' : 'text-fg')}>{step.name}</span>
        <span className="text-[12.5px] text-mute">{step.title}</span>
        <Chip>UDP {step.port}</Chip>
      </div>
      <span className="sr-only">
        {from.name} to {to.name}, {step.status === 'ok' ? 'delivered' : step.status === 'lost' ? 'lost in transit' : 'rejected'}.
      </span>
      <Arrow ltr={ltr} status={step.status} atReceiver={who !== null && who !== step.from} />
      <p className="mx-auto max-w-[64ch] break-words text-center font-mono text-[11px] leading-snug text-dim">{step.payload}</p>
      <p className={cn('mx-auto mt-1 max-w-[64ch] text-center text-[12.5px] leading-snug', bad ? 'text-bad' : 'text-mute')}>{step.note}</p>
    </li>
  );
}

const SLOW = /retrans|timeout|timed out|time up|giving up|not responding|peer table|PeerTblEntry|deleting|expiring|killing/i;

function stamp(stepIdx: number, lineIdx: number, text: string): string {
  const ms = (14 * 3600 + 2 * 60 + 7) * 1000 + 240 + stepIdx * 310 + lineIdx * 9 + (SLOW.test(text) ? 30000 + lineIdx * 8000 : 0);
  const p = (n: number, l = 2) => String(n).padStart(l, '0');
  const s = Math.floor(ms / 1000);
  return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}.${p(ms % 1000, 3)}`;
}

function LogPane({ site, steps, running }: { site: Site; steps: Step[]; running: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  const lines = useMemo(
    () =>
      steps.flatMap((st, i) =>
        st.logs.filter((l) => l.site === site.key).map((l, j) => ({ ...l, t: stamp(i, j, l.text) })),
      ),
    [steps, site.key],
  );
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines.length]);

  return (
    <div className="min-w-0 overflow-hidden rounded-lg border border-line bg-term">
      <div className="flex items-center gap-2 border-b border-line px-3 py-2">
        <SiteBadge site={site.key} />
        <span className="truncate text-[12.5px] font-medium">{site.name}</span>
        <span className="ml-auto truncate font-mono text-[11px] text-mute">{LOG_SOURCE[site.vendor](site.ikeVersion === 'ikev2')}</span>
      </div>
      <div ref={ref} className="thin-scroll max-h-[260px] min-h-[76px] overflow-y-auto px-3 py-2 font-mono text-[11.5px] leading-[1.55]" tabIndex={0} role="log" aria-label={`${site.name} log output`}>
        {lines.length === 0 ? (
          <p className="text-mute">
            {running ? 'Waiting for output…' : 'No output. Nothing reached this device, which is itself a clue: look at reachability and the peer address.'}
          </p>
        ) : (
          lines.map((l, i) => (
            <div key={i} className={cn('animate-rise whitespace-pre-wrap [overflow-wrap:anywhere]', l.level === 'error' ? 'text-bad' : 'text-fg/85')}>
              <span className="select-none text-dim">{l.t} </span>
              {l.text}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

const WORD: Record<SaState, string> = { up: 'up', negotiating: 'negotiating', failed: 'failed', down: 'down' };

export function NegotiationTab({
  a, b, sim, visible, status, onRun,
}: { a: Site; b: Site; sim: SimResult; visible: Step[]; status: 'idle' | 'running' | 'done'; onRun: () => void }) {
  if (status === 'idle')
    return (
      <EmptyState
        title="The tunnel is down"
        text="Bring it up to watch every IKE message cross the wire, and read what each gateway logs along the way."
        action={
          <PrimaryButton onClick={onRun}>
            <Play className="h-4 w-4" aria-hidden /> Bring tunnel up
          </PrimaryButton>
        }
      />
    );

  const head = (k: SiteKey) => {
    const s = k === 'A' ? a : b;
    return (
      <div className={cn('flex min-w-0 items-center gap-1.5', k === 'B' && 'flex-row-reverse text-right')}>
        <SiteBadge site={k} />
        <div className="min-w-0">
          <div className="truncate text-[13px] font-medium leading-tight">{s.name}</div>
          <div className="truncate text-[11px] leading-tight text-mute">
            {VENDORS[s.vendor].short} · {sim.initiator === k ? 'initiator' : 'responder'}
          </div>
        </div>
      </div>
    );
  };
  const last = visible[visible.length - 1];

  return (
    <div className="space-y-5">
      <section aria-label="Message exchange">
        <div className="mb-2 flex items-center justify-between gap-3">
          <h3 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Exchange · {sim.exchange}</h3>
          <span className="font-mono text-[11px] text-mute">
            {visible.length}/{sim.steps.length} messages
          </span>
        </div>
        <div className="rounded-lg border border-line bg-well/60">
          <div className="flex items-center justify-between gap-4 border-b border-line px-3 py-2.5">
            {head('A')}
            {head('B')}
          </div>
          <ol className="mx-3 divide-y divide-line/70 border-x-2 border-l-a/45 border-r-b/45 sm:mx-5">
            {visible.map((st, i) => (
              <Row key={i} step={st} a={a} b={b} />
            ))}
          </ol>
          {status === 'done' && last && (
            <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-1 border-t border-line px-3 py-2.5 font-mono text-[11.5px]">
              <span className={sim.p1 === 'up' ? 'text-ok' : 'text-bad'}>IKE SA {WORD[sim.p1]}</span>
              <span className={sim.p2 === 'up' ? 'text-ok' : sim.p2 === 'down' ? 'text-mute' : 'text-bad'}>IPsec SA {sim.p2 === 'down' ? 'not attempted' : WORD[sim.p2]}</span>
            </div>
          )}
        </div>
      </section>

      <section aria-label="Device logs">
        <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">What each gateway logs</h3>
        <div className="grid gap-3">
          <LogPane site={a} steps={visible} running={status === 'running'} />
          <LogPane site={b} steps={visible} running={status === 'running'} />
        </div>
        <p className="mt-2 text-[11.5px] text-mute">Wording is representative of each platform. Exact text varies between software releases.</p>
      </section>
    </div>
  );
}
