import { ArrowLeft, ArrowRight, Cloud, Network, Router, X } from 'lucide-react';
import { rejectedBy, type Finding, type SaState, type Step } from '../lib/simulate';
import type { Site, SiteKey } from '../lib/types';
import { VENDORS } from '../lib/vendors';
import { cn } from '../utils/cn';
import { ACCENT, Chip } from './ui';

export interface SubnetIssue {
  hasError: boolean;
  label?: string;
  detail?: string;
  code?: string;
}

/** Determines if there is a problem with the protected subnet on this site. */
export function getSubnetIssue(
  siteKey: SiteKey,
  findings: Finding[] | undefined,
  done: boolean,
): SubnetIssue {
  if (!findings || findings.length === 0) return { hasError: false };

  // Check subnet overlap (affects both sides)
  const overlap = findings.find((f) => f.code === 'OVERLAP');
  if (overlap) {
    return { hasError: true, label: 'Subnet Overlap', detail: overlap.detail, code: 'OVERLAP' };
  }

  // Check invalid CIDR on this site
  const addr = findings.find((f) => f.code === `ADDR:${siteKey}`);
  if (addr && addr.fields.some((x) => x.field === 'lan' || x.field === 'remoteLan')) {
    return { hasError: true, label: 'Invalid CIDR', detail: addr.detail, code: addr.code };
  }

  // Check Traffic Selector / Proxy-ID mismatch
  const ts = findings.find((f) => f.code === 'TS');
  if (ts) {
    return { hasError: true, label: 'Selector Mismatch', detail: ts.detail, code: 'TS' };
  }

  // Only consider post-phase-1 data path issues if negotiation has been evaluated or run
  const route = findings.find((f) => f.code === `ROUTE:${siteKey}` || f.code === `ROUTE_NET:${siteKey}`);
  if (route && (done || route.blocking)) {
    return { hasError: true, label: 'Route Missing', detail: route.detail, code: route.code };
  }

  const policy = findings.find((f) => f.code === `POLICY:${siteKey}`);
  if (policy && (done || policy.blocking)) {
    return { hasError: true, label: 'Policy Drop', detail: policy.detail, code: policy.code };
  }

  const natExempt = findings.find((f) => f.code === `NAT_EXEMPT:${siteKey}`);
  const dnatFail = findings.find((f) => f.code === `DNAT_FAIL:${siteKey}`);

  if (natExempt && dnatFail && (done || natExempt.blocking || dnatFail.blocking)) {
    return { hasError: true, label: 'SNAT & DNAT', detail: `${natExempt.detail} Also: ${dnatFail.detail}`, code: 'NAT_BOTH' };
  }
  if (natExempt && (done || natExempt.blocking)) {
    return { hasError: true, label: 'Subnet SNATed', detail: natExempt.detail, code: natExempt.code };
  }
  if (dnatFail && (done || dnatFail.blocking)) {
    return { hasError: true, label: 'Subnet DNATed', detail: dnatFail.detail, code: dnatFail.code };
  }

  return { hasError: false };
}

/** Circular node representing a Protected LAN Subnet behind a VPN peer */
function SubnetNode({
  s,
  issue,
  tunnelUp,
}: {
  s: Site;
  issue: SubnetIssue;
  tunnelUp: boolean;
}) {
  const isA = s.key === 'A';
  const hasErr = issue.hasError;

  return (
    <div className="flex shrink-0 flex-col items-center text-center">
      {/* Circle node */}
      <div
        className={cn(
          'relative grid h-9 w-9 place-items-center rounded-full border-2 transition-all duration-300 sm:h-14 sm:w-14 md:h-16 md:w-16',
          hasErr
            ? 'border-bad bg-bad/15 text-bad shadow-[0_0_12px_rgba(255,118,118,0.45)] ring-1 ring-bad/40 sm:ring-2'
            : tunnelUp
              ? isA
                ? 'border-a bg-a/10 text-a shadow-[0_0_10px_rgba(98,185,255,0.3)]'
                : 'border-b bg-b/10 text-b shadow-[0_0_10px_rgba(200,166,255,0.3)]'
              : 'border-line-strong bg-raised/80 text-mute',
        )}
        title={hasErr ? `Protected Subnet issue: ${issue.label} — ${issue.detail}` : `Protected LAN: ${s.lan}`}
      >
        <Network className={cn('h-4 w-4 sm:h-5 sm:w-5 md:h-6 md:w-6', hasErr ? 'text-bad' : isA ? 'text-a' : 'text-b')} />
        {hasErr && (
          <span className="absolute -right-1 -top-1 grid h-3.5 w-3.5 place-items-center rounded-full bg-bad text-[9px] font-bold text-ink sm:h-5 sm:w-5 sm:text-[10px]">
            !
          </span>
        )}
      </div>

      {/* Label and Subnet CIDR below */}
      <div className="mt-1 max-w-[58px] sm:max-w-[110px]">
        <div className="flex items-center justify-center font-mono text-[9px] font-semibold uppercase tracking-wider text-dim sm:text-[11px]">
          <span>LAN {s.key}</span>
        </div>
        <div
          className={cn(
            'truncate font-mono text-[9px] font-medium sm:text-[11.5px]',
            hasErr ? 'font-semibold text-bad' : 'text-fg',
          )}
          title={s.lan}
        >
          {s.lan || '—'}
        </div>
        {hasErr ? (
          <span className="mt-0.5 inline-block max-w-full truncate rounded bg-bad/20 px-1 py-px font-mono text-[8px] font-semibold uppercase tracking-wider text-bad sm:text-[10px]">
            {issue.label}
          </span>
        ) : (
          <span className="hidden text-[10px] text-dim sm:inline-block">Protected</span>
        )}
      </div>
    </div>
  );
}

/** Connecting line between the Protected Subnet Circle and the VPN Gateway Circle */
function SubnetLink({
  issue,
  tunnelUp,
}: {
  issue: SubnetIssue;
  tunnelUp: boolean;
}) {
  const hasErr = issue.hasError;

  return (
    <div className="relative flex flex-1 items-center justify-center px-1">
      {/* The connector line */}
      <div
        className={cn(
          'h-[3px] w-full rounded-full transition-all duration-300',
          hasErr
            ? 'animate-pulse bg-bad shadow-[0_0_8px_rgba(255,118,118,0.8)]'
            : tunnelUp
              ? 'bg-ok/80 shadow-[0_0_6px_rgba(69,214,160,0.5)]'
              : 'bg-line-strong',
        )}
      />

      {/* If error: red badge on the line */}
      {hasErr && (
        <div
          className="absolute top-1/2 grid h-4 w-4 -translate-y-1/2 place-items-center rounded-full bg-bad text-ink shadow-[0_0_6px_rgba(255,118,118,0.9)]"
          title={issue.detail ?? issue.label}
        >
          <X className="h-3 w-3 stroke-[3]" />
        </div>
      )}

      {/* Status indicator note when line is in error */}
      {hasErr && (
        <span className="sr-only">
          Protected subnet connection problem: {issue.label}
        </span>
      )}
    </div>
  );
}

/** Circular node representing a VPN Peer Gateway (Site A or Site B) */
function GatewayNode({ s }: { s: Site }) {
  const v = VENDORS[s.vendor];
  const isA = s.key === 'A';

  return (
    <div className="flex shrink-0 flex-col items-center text-center">
      {/* Circle Node */}
      <div
        className={cn(
          'relative grid h-11 w-11 place-items-center rounded-full border-2 bg-raised transition-all duration-300 sm:h-18 sm:w-18 md:h-20 md:w-20',
          isA
            ? 'border-a shadow-[0_0_12px_rgba(98,185,255,0.25)]'
            : 'border-b shadow-[0_0_12px_rgba(200,166,255,0.25)]',
        )}
      >
        {/* Site badge inside top of circle */}
        <span
          className={cn(
            'absolute -top-1 grid h-4 w-4 place-items-center rounded-full font-mono text-[9px] font-bold text-ink sm:-top-2 sm:h-6 sm:w-6 sm:text-[11px]',
            ACCENT[s.key].bg,
          )}
        >
          {s.key}
        </span>

        {/* Router / Gateway icon */}
        <Router className={cn('h-5 w-5 sm:h-7 sm:w-7 md:h-8 md:w-8', isA ? 'text-a' : 'text-b')} />
      </div>

      {/* Name and details below circle */}
      <div className="mt-1 max-w-[62px] sm:max-w-[124px]">
        <div className="truncate text-[11px] font-semibold text-fg sm:text-[13px]" title={s.name}>
          {s.name || `Site ${s.key}`}
        </div>
        <div className="truncate text-[9.5px] text-mute sm:text-[11.5px]" title={v.name}>
          {v.short}
        </div>
        <div className="mt-0.5 truncate font-mono text-[8.5px] text-dim sm:text-[11px]" title={s.wanIp}>
          {s.wanIp || '—'}
        </div>
        {s.behindNat && (
          <Chip tone="warn" className="mt-1 text-[8px] sm:text-[9px]">
            NAT
          </Chip>
        )}
      </div>
    </div>
  );
}

const STATE_TONE: Record<SaState, string> = {
  up: 'border-ok/45 bg-ok/10 text-ok',
  negotiating: 'border-warn/45 bg-warn/10 text-warn',
  failed: 'border-bad/45 bg-bad/10 text-bad',
  down: 'border-line text-mute',
};
const STATE_WORD: Record<SaState, string> = { up: 'up', negotiating: 'negotiating', failed: 'failed', down: 'down' };

function StatePill({ label, state }: { label: string; state: SaState }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 font-mono text-[10.5px]', STATE_TONE[state])}>
      <span className="text-fg/80">{label}</span>
      <span className="font-medium">{STATE_WORD[state]}</span>
    </span>
  );
}

export function Topology({
  a,
  b,
  p1,
  p2,
  float,
  step,
  stepIndex,
  running,
  done,
  findings,
}: {
  a: Site;
  b: Site;
  p1: SaState;
  p2: SaState;
  float: boolean;
  step?: Step;
  stepIndex: number;
  running: boolean;
  done: boolean;
  findings?: Finding[];
}) {
  const tube =
    p2 === 'up'
      ? 'border-ok/60 tube-flow animate-flow'
      : p2 === 'negotiating'
        ? 'border-warn/50 bg-warn/5 animate-pulse-soft'
        : p2 === 'failed'
          ? 'border-dashed border-bad/55 bg-bad/5'
          : 'border-dashed border-line-strong';
  const ike =
    p1 === 'up'
      ? 'bg-ok'
      : p1 === 'negotiating'
        ? 'bg-warn animate-pulse-soft'
        : p1 === 'failed'
          ? 'bg-bad/70'
          : 'bg-line-strong';

  const ltr = step?.from === 'A';
  const died = step && step.status !== 'ok' ? (step.status === 'lost' ? 'path' : rejectedBy(step)) : null;
  const diedLeft = died === 'path' ? '50%' : died === 'A' ? '0%' : '100%';
  const pktTone = !step || step.status === 'ok' ? 'bg-fg ring-fg/20' : 'bg-bad ring-bad/25';

  const issueA = getSubnetIssue('A', findings, done);
  const issueB = getSubnetIssue('B', findings, done);
  const tunnelUp = p2 === 'up';

  const pills = (
    <>
      <StatePill label="IKE SA" state={p1} />
      <StatePill label="IPsec SA" state={p2} />
    </>
  );

  const caption = (
    <>
      {running && step ? (
        <>
          {!ltr && <ArrowLeft className="h-3 w-3 shrink-0" aria-hidden />}
          <span className="truncate">
            {step.name} · UDP {step.port}
          </span>
          {ltr && <ArrowRight className="h-3 w-3 shrink-0" aria-hidden />}
        </>
      ) : p2 === 'up' ? (
        <span>{float ? 'ESP in UDP 4500 (NAT-T)' : 'ESP · IP protocol 50'}</span>
      ) : done && died ? (
        <span className="text-bad">
          {died === 'path' ? 'lost in transit' : `rejected by ${(died === 'A' ? a : b).name}`}
        </span>
      ) : (
        <span>UDP 500 · UDP 4500 · ESP</span>
      )}
    </>
  );

  return (
    <div>
      {/* 5-part circular layout: Subnet A (circle) -- line -- Gateway A (circle) == Tunnel == Gateway B (circle) -- line -- Subnet B (circle) */}
      <div className="flex items-center justify-between gap-1 sm:gap-2">
        {/* Protected Subnet A (Circle) */}
        <SubnetNode s={a} issue={issueA} tunnelUp={tunnelUp} />

        {/* Connection Line: Subnet A <-> Gateway A (turns RED on error) */}
        <SubnetLink issue={issueA} tunnelUp={tunnelUp} />

        {/* VPN Gateway Peer A (Circle) */}
        <GatewayNode s={a} />

        {/* Center: Internet & IPsec Tunnel */}
        <div className="flex min-w-[48px] flex-1 flex-col justify-center gap-1.5 py-1 sm:min-w-[120px]">
          <div className="flex items-center justify-center gap-1 font-mono text-[9.5px] uppercase tracking-[0.14em] text-dim sm:text-[10px]">
            <Cloud className="h-3 w-3 sm:h-3.5 sm:w-3.5" aria-hidden />
            <span>Internet</span>
          </div>

          <div className="relative h-7 sm:h-8" aria-hidden>
            <div className={cn('absolute inset-x-0 top-1/2 h-3.5 -translate-y-1/2 rounded-full border transition-colors duration-300 sm:h-4', tube)} />
            <div className={cn('absolute inset-x-2 top-1/2 h-[2px] -translate-y-1/2 rounded-full transition-colors duration-300', ike)} />
            <div className="absolute inset-x-2 inset-y-0">
              {running && step && (
                <span
                  key={stepIndex}
                  className={cn(
                    'pkt',
                    step.status === 'lost'
                      ? ltr
                        ? 'pkt-ltr-lost'
                        : 'pkt-rtl-lost'
                      : ltr
                        ? 'pkt-ltr'
                        : 'pkt-rtl',
                  )}
                >
                  <span className={cn('block h-2 w-2 rounded-full ring-4 sm:h-2.5 sm:w-2.5', pktTone)} />
                </span>
              )}
              {done && died && (
                <span
                  className="absolute top-1/2 grid h-4 w-4 -translate-x-1/2 -translate-y-1/2 animate-rise place-items-center rounded-full bg-bad text-ink sm:h-5 sm:w-5"
                  style={{ left: diedLeft }}
                >
                  <X className="h-3 w-3 stroke-[3]" />
                </span>
              )}
            </div>
          </div>

          <div className="hidden flex-wrap items-center justify-center gap-1 sm:flex">{pills}</div>
          <div className="hidden min-h-4 items-center justify-center gap-1 text-center font-mono text-[10.5px] leading-tight text-mute sm:flex">
            {caption}
          </div>
        </div>

        {/* VPN Gateway Peer B (Circle) */}
        <GatewayNode s={b} />

        {/* Connection Line: Gateway B <-> Subnet B (turns RED on error) */}
        <SubnetLink issue={issueB} tunnelUp={tunnelUp} />

        {/* Protected Subnet B (Circle) */}
        <SubnetNode s={b} issue={issueB} tunnelUp={tunnelUp} />
      </div>

      {/* Narrow screens: state and caption get the full width below the diagram */}
      <div className="mt-3 flex flex-col items-center gap-1.5 sm:hidden">
        <div className="flex flex-wrap justify-center gap-1.5">{pills}</div>
        <div className="flex min-h-4 items-center justify-center gap-1 text-center font-mono text-[11px] leading-tight text-mute">
          {caption}
        </div>
      </div>
    </div>
  );
}
