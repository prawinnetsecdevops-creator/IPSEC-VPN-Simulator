import { CircleCheck, Info, OctagonX, Play, TriangleAlert, Wrench } from 'lucide-react';
import type { Finding, Fix, SimResult, Stage } from '../lib/simulate';
import type { Site } from '../lib/types';
import { VENDORS, verifyCommands, type CmdStage } from '../lib/vendors';
import { cn } from '../utils/cn';
import { Chip, CopyButton, EmptyState, PrimaryButton, SiteBadge } from './ui';

const CMD_FOCUS: Record<Stage, CmdStage[]> = {
  Reachability: ['traffic', 'ike', 'debug'],
  'Phase 1': ['ike', 'debug'],
  'Phase 2': ['ipsec', 'debug'],
  'Data path': ['ipsec', 'traffic'],
  Advisory: ['ike', 'ipsec'],
};
const CMD_LABEL: Record<CmdStage, string> = { ike: 'Phase 1', ipsec: 'Phase 2', traffic: 'Path', debug: 'Debug' };

function FindingCard({ f, onApply }: { f: Finding; onApply: (fix: Fix) => void }) {
  const tone = f.blocking || f.severity === 'critical' ? 'bad' : f.severity === 'warning' ? 'warn' : 'neutral';
  const Icon = tone === 'bad' ? OctagonX : tone === 'warn' ? TriangleAlert : Info;
  return (
    <li
      className={cn(
        'rounded-lg border bg-well/60 p-3.5 sm:p-4',
        f.blocking ? 'border-bad/60' : 'border-line',
      )}
    >
      <div className="flex items-start gap-3">
        <Icon className={cn('mt-0.5 h-[18px] w-[18px] shrink-0', tone === 'bad' ? 'text-bad' : tone === 'warn' ? 'text-warn' : 'text-mute')} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-1.5">
            <Chip tone={tone}>{f.blocking ? 'Blocking now' : f.severity === 'critical' ? 'Blocks next' : f.severity === 'warning' ? 'Warning' : 'Advisory'}</Chip>
            {f.stage !== 'Advisory' && <Chip>{f.stage}</Chip>}
          </div>
          <h4 className="mt-1.5 text-[14.5px] font-semibold leading-snug text-fg">{f.title}</h4>
          <p className="mt-1 max-w-[70ch] text-[13px] leading-relaxed text-fg/80">{f.detail}</p>
          {f.symptom && (
            <p className="mt-2 max-w-[70ch] border-l-2 border-line-strong pl-3 text-[12.5px] leading-relaxed text-mute">
              <span className="font-medium text-fg/80">What you would see. </span>
              {f.symptom}
            </p>
          )}
          {f.fixes.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {f.fixes.map((fix) => (
                <button
                  key={fix.label}
                  type="button"
                  onClick={() => onApply(fix)}
                  className="inline-flex min-h-10 items-center gap-2 rounded-md border border-line-strong bg-raised px-3 py-1.5 text-left text-[13px] font-medium text-fg transition-colors hover:border-fg/50 hover:bg-raised/70 active:translate-y-px"
                >
                  <Wrench className="h-3.5 w-3.5 shrink-0 text-mute" aria-hidden />
                  {fix.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </li>
  );
}

function Commands({ s, o, focus }: { s: Site; o: Site; focus: CmdStage[] }) {
  const cmds = verifyCommands(s, o)
    .filter((c) => focus.includes(c.stage))
    .sort((x, y) => focus.indexOf(x.stage) - focus.indexOf(y.stage));
  return (
    <div className="min-w-0">
      <div className="mb-2 flex items-center gap-2">
        <SiteBadge site={s.key} />
        <span className="truncate text-[13px] font-medium">{s.name}</span>
        <span className="truncate text-[12px] text-mute">{VENDORS[s.vendor].name}</span>
      </div>
      <ul className="space-y-2">
        {cmds.map((c) => (
          <li key={c.cmd} className="rounded-md border border-line bg-term">
            <div className="flex items-start gap-2 px-2.5 py-2">
              <pre className="min-w-0 flex-1 whitespace-pre-wrap font-mono text-[12px] leading-snug text-fg [overflow-wrap:anywhere]">{c.cmd}</pre>
              <CopyButton text={c.cmd} compact label="Copy command" />
            </div>
            <p className="border-t border-line px-2.5 py-1.5 text-[12px] leading-snug text-mute">
              <span className="mr-1.5 font-mono text-[10.5px] uppercase tracking-[0.04em] text-dim">{CMD_LABEL[c.stage]}</span>
              {c.why}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function DiagnosisTab({
  a, b, sim, status, onApply, onRun,
}: { a: Site; b: Site; sim: SimResult; status: 'idle' | 'running' | 'done'; onApply: (fix: Fix) => void; onRun: () => void }) {
  if (status === 'idle')
    return (
      <EmptyState
        title="Nothing to diagnose yet"
        text="The diagnosis is built from an actual negotiation attempt. Bring the tunnel up first."
        action={
          <PrimaryButton onClick={onRun}>
            <Play className="h-4 w-4" aria-hidden /> Bring tunnel up
          </PrimaryButton>
        }
      />
    );
  if (status === 'running')
    return <EmptyState title="Negotiation in progress" text="The diagnosis appears as soon as the exchange finishes." />;

  const ordered = [...sim.findings].sort((x, y) => Number(!!y.blocking) - Number(!!x.blocking));
  const serious = ordered.filter((f) => f.severity !== 'info');
  const minor = ordered.filter((f) => f.severity === 'info');
  const focusStage: Stage = ordered.find((f) => f.blocking)?.stage ?? serious[0]?.stage ?? 'Advisory';
  const focus = CMD_FOCUS[focusStage];

  return (
    <div className="space-y-6">
      <section aria-label="Findings">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Findings</h3>
          {serious.length > 0 && (
            <span className="text-[12px] text-mute">
              Listed in the order the negotiation will hit them. Fix the first, then re-run.
            </span>
          )}
        </div>

        {serious.length === 0 && (
          <div className="flex items-start gap-3 rounded-lg border border-ok/40 bg-ok/5 p-4">
            <CircleCheck className="mt-0.5 h-[18px] w-[18px] shrink-0 text-ok" aria-hidden />
            <div>
              <h4 className="text-[14.5px] font-semibold text-fg">{sim.trafficOk ? 'Both gateways agree on everything that matters' : 'No configuration fault found'}</h4>
              <p className="mt-1 text-[13px] text-fg/80">
                Both phases negotiate, selectors mirror each other and the data path is clear in both directions.
                {minor.length > 0 && ' The advisories below do not affect connectivity.'}
              </p>
            </div>
          </div>
        )}

        <ul className="space-y-2.5">
          {serious.map((f) => (
            <FindingCard key={f.code} f={f} onApply={onApply} />
          ))}
        </ul>

        {minor.length > 0 && (
          <>
            <h3 className="mb-2 mt-5 text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Advisories</h3>
            <ul className="space-y-2.5">
              {minor.map((f) => (
                <FindingCard key={f.code} f={f} onApply={onApply} />
              ))}
            </ul>
          </>
        )}
      </section>

      <section aria-label="Verification commands">
        <h3 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Confirm it on the real devices</h3>
        <p className="mb-3 mt-1 text-[12.5px] text-mute">
          Commands for each platform, chosen for the {focusStage === 'Advisory' ? 'current state' : `${focusStage.toLowerCase()} stage`}. The full list is on the Configuration tab.
        </p>
        <div className="grid gap-5 lg:grid-cols-2">
          <Commands s={a} o={b} focus={focus} />
          <Commands s={b} o={a} focus={focus} />
        </div>
      </section>
    </div>
  );
}
