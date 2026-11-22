import {
  ArrowRight,
  ChevronDown,
  CircleCheck,
  CircleDashed,
  Download,
  FastForward,
  Layers,
  LoaderCircle,
  Maximize2,
  Minimize2,
  OctagonX,
  Play,
  RotateCcw,
  TriangleAlert,
} from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ConfigTab } from './components/ConfigTab';
import { DiagnosisTab } from './components/DiagnosisTab';
import { NegotiationTab } from './components/NegotiationTab';
import { ParametersTab } from './components/ParametersTab';
import { SitePanel } from './components/SitePanel';
import { Topology } from './components/Topology';
import { TrafficTab } from './components/TrafficTab';
import { PrimaryButton, Segmented } from './components/ui';
import { SCENARIOS, baseSites } from './lib/scenarios';
import { simulate, type Fix, type SaState, type Severity } from './lib/simulate';
import type { Site, SiteKey, Sites } from './lib/types';
import { parseUrlState, updateBrowserUrl } from './lib/urlState';
import { VENDORS, coerce } from './lib/vendors';
import { cn } from './utils/cn';

type Status = 'idle' | 'running' | 'done';
type TabId = 'negotiation' | 'diagnosis' | 'compare' | 'traffic' | 'config';

const TABS: { id: TabId; label: string; short: string }[] = [
  { id: 'negotiation', label: 'Negotiation', short: 'Exchange' },
  { id: 'diagnosis', label: 'Diagnosis', short: 'Diagnose' },
  { id: 'compare', label: 'Compare', short: 'Compare' },
  { id: 'traffic', label: 'Traffic test', short: 'Traffic' },
  { id: 'config', label: 'Configuration', short: 'Config' },
];

const STORAGE = 'tunnellab:v1';
const STEP_MS = 520;

interface Persisted {
  sites: Sites;
  initiator: SiteKey;
  scenarioId: string;
}

function load(): Persisted | null {
  try {
    const raw = localStorage.getItem(STORAGE);
    if (!raw) return null;
    const p = JSON.parse(raw) as Partial<Persisted>;
    const base = baseSites();
    if (!p.sites || !(p.sites.A?.vendor in VENDORS) || !(p.sites.B?.vendor in VENDORS)) return null;
    return {
      sites: { A: coerce({ ...base.A, ...p.sites.A, key: 'A' }), B: coerce({ ...base.B, ...p.sites.B, key: 'B' }) },
      initiator: p.initiator === 'B' ? 'B' : 'A',
      scenarioId: SCENARIOS.some((s) => s.id === p.scenarioId) ? p.scenarioId! : 'baseline',
    };
  } catch {
    return null;
  }
}

function Logo() {
  return (
    <svg viewBox="0 0 36 36" className="h-9 w-9 shrink-0" aria-hidden>
      <rect x="0.5" y="0.5" width="35" height="35" rx="8" fill="#0e141b" stroke="#364454" />
      <rect x="6" y="13" width="7" height="10" rx="1.5" fill="#62b9ff" />
      <rect x="23" y="13" width="7" height="10" rx="1.5" fill="#c8a6ff" />
      <rect x="13" y="15.5" width="10" height="5" fill="#45d6a0" opacity="0.35" />
      <path d="M13 18h10" stroke="#45d6a0" strokeWidth="1.6" strokeDasharray="2 2" />
    </svg>
  );
}

const quietButton =
  'inline-flex h-11 items-center justify-center gap-2 rounded-md border border-line bg-panel px-3 text-[13px] font-medium text-fg/90 transition-colors hover:border-line-strong hover:bg-raised active:translate-y-px md:h-9';

export default function App() {
  const urlState = useMemo(() => parseUrlState(), []);

  const [initial] = useState<Persisted>(() => {
    if (urlState.customState) {
      return {
        sites: urlState.customState.sites,
        initiator: urlState.customState.initiator,
        scenarioId: 'baseline',
      };
    }
    if (urlState.scenarioId) {
      const sc = SCENARIOS.find((s) => s.id === urlState.scenarioId);
      if (sc) {
        const built = sc.build();
        let s = built.sites;
        if (urlState.vendorA) s = { ...s, A: coerce({ ...s.A, vendor: urlState.vendorA }) };
        if (urlState.vendorB) s = { ...s, B: coerce({ ...s.B, vendor: urlState.vendorB }) };
        return {
          sites: s,
          initiator: urlState.initiator ?? built.initiator,
          scenarioId: sc.id,
        };
      }
    }
    const saved = load();
    if (saved) {
      let s = saved.sites;
      if (urlState.vendorA) s = { ...s, A: coerce({ ...s.A, vendor: urlState.vendorA }) };
      if (urlState.vendorB) s = { ...s, B: coerce({ ...s.B, vendor: urlState.vendorB }) };
      return {
        ...saved,
        sites: s,
        initiator: urlState.initiator ?? saved.initiator,
      };
    }
    return { ...SCENARIOS[0].build(), scenarioId: 'baseline' };
  });

  const [sites, setSites] = useState<Sites>(initial.sites);
  const [initiator, setInitiator] = useState<SiteKey>(initial.initiator);
  const [scenarioId, setScenarioId] = useState(initial.scenarioId);

  const [status, setStatus] = useState<Status>('idle');
  const [playhead, setPlayhead] = useState(0);
  const [runId, setRunId] = useState(0);
  const [everRan, setEverRan] = useState(false);
  const [tab, setTab] = useState<TabId>(() => urlState.tab ?? 'negotiation');
  const [mobileSite, setMobileSite] = useState<SiteKey>('A');
  const [embedMode, setEmbedMode] = useState<boolean>(() => !!urlState.embed);
  const resultsRef = useRef<HTMLDivElement>(null);

  const sim = useMemo(() => simulate(sites.A, sites.B, initiator), [sites, initiator]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE, JSON.stringify({ sites, initiator, scenarioId } satisfies Persisted));
    } catch {
      /* storage unavailable — the app works without it */
    }
  }, [sites, initiator, scenarioId]);

  // Synchronize URL in browser address bar (enables bookmarking & sharing exact subpage state)
  useEffect(() => {
    updateBrowserUrl({
      scenarioId,
      tab,
      initiator,
      embed: embedMode,
    });
  }, [scenarioId, tab, initiator, embedMode]);

  // Auto-run if requested via URL query (?autorun=1 or ?run=true)
  useEffect(() => {
    if (urlState.autorun) {
      start();
    }
  }, [urlState.autorun]);

  /* ---- run control ---- */
  const stop = useCallback(() => {
    setStatus('idle');
    setPlayhead(0);
    setRunId(0);
  }, []);

  const finish = useCallback(() => {
    setPlayhead(Number.POSITIVE_INFINITY);
    setStatus('done');
    setRunId(0);
  }, []);

  const start = useCallback(() => {
    setEverRan(true);
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      finish();
      return;
    }
    setPlayhead(1);
    setStatus('running');
    setRunId((n) => n + 1);
  }, [finish]);

  useEffect(() => {
    if (!runId) return;
    const total = sim.steps.length;
    let shown = 1;
    const timer = window.setInterval(() => {
      if (shown >= total) {
        window.clearInterval(timer);
        setPlayhead(Number.POSITIVE_INFINITY);
        setStatus('done');
        return;
      }
      shown += 1;
      setPlayhead(shown);
    }, STEP_MS);
    return () => window.clearInterval(timer);
  }, [runId, sim]);

  /* ---- edits ---- */
  const update = useCallback(
    (key: SiteKey, patch: Partial<Site>) => {
      setSites((s) => ({ ...s, [key]: coerce({ ...s[key], ...patch }) }));
      stop();
    },
    [stop],
  );

  const applyFix = useCallback(
    (fix: Fix) => {
      setSites((s) => {
        let next = s;
        for (const p of fix.patches) next = { ...next, [p.site]: coerce({ ...next[p.site], ...p.patch }) };
        return next;
      });
      start();
    },
    [start],
  );

  const loadScenario = useCallback(
    (id: string) => {
      const sc = SCENARIOS.find((s) => s.id === id) ?? SCENARIOS[0];
      const built = sc.build();
      setSites(built.sites);
      setInitiator(built.initiator);
      setScenarioId(sc.id);
      setEverRan(false);
      setTab('negotiation');
      stop();
    },
    [stop],
  );

  /* ---- derived view state ---- */
  const visible = useMemo(() => sim.steps.slice(0, playhead), [sim, playhead]);
  const current = visible[visible.length - 1];
  const p1: SaState = status === 'idle' ? 'down' : (current?.p1 ?? 'down');
  const p2: SaState = status === 'idle' ? 'down' : (current?.p2 ?? 'down');
  const serious = sim.findings.filter((f) => f.severity !== 'info');

  const issues = useMemo(() => {
    const m: Record<SiteKey, Partial<Record<keyof Site, Severity>>> = { A: {}, B: {} };
    if (status !== 'done') return m;
    for (const f of sim.findings) {
      if (f.severity === 'info') continue;
      for (const x of f.fields) if (m[x.site][x.field] !== 'critical') m[x.site][x.field] = f.severity;
    }
    return m;
  }, [sim, status]);

  const openTab = (id: TabId) => {
    setTab(id);
    resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const banner =
    status === 'idle'
      ? {
          tone: 'neutral' as const,
          Icon: CircleDashed,
          title: everRan ? 'Configuration changed' : 'Tunnel is down',
          text: everRan ? 'Bring the tunnel up again to test the new settings.' : 'Nothing has been negotiated yet. Pick the initiator and bring the tunnel up.',
        }
      : status === 'running'
        ? { tone: 'neutral' as const, Icon: LoaderCircle, title: `Negotiating · ${sim.exchange}`, text: current?.note ?? '' }
        : {
            tone: sim.headline.tone,
            Icon: sim.headline.tone === 'ok' ? CircleCheck : sim.headline.tone === 'warn' ? TriangleAlert : OctagonX,
            title: sim.headline.title,
            text: sim.headline.text,
          };
  const bannerTone = {
    neutral: 'border-line bg-well/70',
    ok: 'border-ok/45 bg-ok/[0.07]',
    warn: 'border-warn/45 bg-warn/[0.07]',
    bad: 'border-bad/50 bg-bad/[0.07]',
  }[banner.tone];
  const bannerIcon = { neutral: 'text-mute', ok: 'text-ok', warn: 'text-warn', bad: 'text-bad' }[banner.tone];

  const groups = ['Baseline', 'Tunnel down', 'Phase 2', 'Tunnel up, traffic failing'] as const;

  return (
    <div className="min-h-dvh">
      {embedMode ? (
        <header className="border-b border-line bg-panel/90 px-3 py-1.5 sm:px-4">
          <div className="mx-auto flex max-w-[1680px] flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="flex items-center gap-1.5 rounded bg-a/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-a">
                IPSEC Simulator
              </span>
              <label className="relative block w-[190px] sm:w-[260px]">
                <span className="sr-only">Lab Scenario</span>
                <select
                  value={scenarioId}
                  onChange={(e) => loadScenario(e.target.value)}
                  className="h-8 w-full cursor-pointer appearance-none truncate rounded border border-line bg-well pl-2 pr-7 font-mono text-[11.5px] text-fg hover:border-line-strong"
                >
                  {groups.map((g) => (
                    <optgroup key={g} label={g}>
                      {SCENARIOS.filter((s) => s.group === g).map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.title}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
                <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-mute" aria-hidden />
              </label>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setEmbedMode(false)}
                className="inline-flex h-8 items-center gap-1 rounded border border-line bg-panel px-2 font-mono text-[11px] text-mute hover:border-line-strong hover:text-fg"
                title="Exit Embed Mode"
              >
                <Maximize2 className="h-3.5 w-3.5 text-mute" />
                <span className="hidden sm:inline">Full View</span>
              </button>
            </div>
          </div>
        </header>
      ) : (
        <header className="border-b border-line bg-panel/85">
          <div className="mx-auto flex max-w-[1680px] flex-wrap items-center gap-x-6 gap-y-3 px-3 py-3 sm:px-5">
            <div className="flex min-w-0 items-center gap-3">
              <Logo />
              <div className="min-w-0">
                <h1 className="text-[16px] font-semibold leading-tight tracking-[-0.01em]">IPSEC VPN Simulator</h1>
                <p className="text-[12.5px] leading-tight text-mute">Site-to-site VPN simulator and troubleshooter</p>
              </div>
            </div>

            <div className="flex w-full flex-wrap items-center gap-2.5 sm:gap-3 lg:ml-auto lg:w-auto">
              <div className="flex w-full items-center gap-2 sm:w-auto">
                <span className="flex shrink-0 items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-[0.08em] text-mute">
                  <Layers className="h-3.5 w-3.5 text-a" aria-hidden />
                  <span>Lab Scenarios:</span>
                </span>
                <label className="relative block flex-1 sm:w-[310px]">
                  <span className="sr-only">Lab Scenarios</span>
                  <select
                    value={scenarioId}
                    onChange={(e) => loadScenario(e.target.value)}
                    className="h-11 w-full cursor-pointer appearance-none truncate rounded-md border border-line bg-well pl-3 pr-9 text-base text-fg transition-colors hover:border-line-strong md:h-9 md:text-[13px]"
                  >
                    {groups.map((g) => (
                      <optgroup key={g} label={g}>
                        {SCENARIOS.filter((s) => s.group === g).map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.title}
                          </option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                  <ChevronDown className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" aria-hidden />
                </label>
              </div>
              <button type="button" onClick={() => loadScenario(scenarioId)} className={cn(quietButton, 'flex-1 sm:flex-none')}>
                <RotateCcw className="h-4 w-4 text-mute" aria-hidden /> Reset Lab
              </button>
              <button
                type="button"
                onClick={() => setEmbedMode((e) => !e)}
                className={cn(quietButton, 'flex-1 sm:flex-none', embedMode ? 'border-ok/40 text-ok' : 'text-mute')}
                title={embedMode ? 'Exit Embed Mode' : 'Toggle Embed View (for iframes & subpages)'}
              >
                {embedMode ? <Minimize2 className="h-4 w-4 text-ok" /> : <Maximize2 className="h-4 w-4 text-mute" />}
                <span className="hidden xl:inline">{embedMode ? 'Exit Embed' : 'Embed View'}</span>
              </button>
              <a
                href="ipsec-vpn-simulator.zip"
                download="ipsec-vpn-simulator.zip"
                className={cn(quietButton, 'flex-1 sm:flex-none')}
                title="Download Option B Project Source Code (.zip)"
              >
                <Download className="h-4 w-4 text-mute" aria-hidden /> Download Zip
              </a>
            </div>
          </div>
        </header>
      )}

      <main className="mx-auto max-w-[1680px] px-3 pb-10 pt-4 sm:px-5">
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-[336px_minmax(0,1fr)_336px] xl:grid-rows-[auto_1fr]">
          {/* topology + run control */}
          <section aria-label="Topology and tunnel state" className="min-w-0 rounded-xl border border-line bg-panel p-3 sm:p-4 md:col-span-2 xl:col-span-1 xl:col-start-2 xl:row-start-1">
            <Topology
              a={sites.A}
              b={sites.B}
              p1={p1}
              p2={p2}
              float={sim.float}
              step={current}
              stepIndex={visible.length}
              running={status === 'running'}
              done={status === 'done'}
              findings={sim.findings}
            />

            <div className="mt-4 flex flex-col gap-3 border-t border-line pt-4 sm:flex-row sm:items-end sm:justify-between">
              <div className="min-w-0 sm:w-[340px]">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-[0.06em] text-mute">Who initiates</div>
                <Segmented
                  label="Initiator"
                  value={initiator}
                  onChange={(k) => {
                    setInitiator(k);
                    stop();
                  }}
                  options={[
                    { value: 'A', label: `A · ${sites.A.name}` },
                    { value: 'B', label: `B · ${sites.B.name}` },
                  ]}
                />
              </div>
              <PrimaryButton onClick={status === 'running' ? finish : start} className="w-full sm:w-auto sm:min-w-[190px]">
                {status === 'running' ? (
                  <>
                    <FastForward className="h-4 w-4" aria-hidden /> Skip to result
                  </>
                ) : status === 'done' ? (
                  <>
                    <RotateCcw className="h-4 w-4" aria-hidden /> Run again
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" aria-hidden /> Bring tunnel up
                  </>
                )}
              </PrimaryButton>
            </div>

            <div role="status" aria-live="polite" className={cn('mt-3 flex flex-col gap-3 rounded-lg border px-3.5 py-3 transition-colors sm:flex-row sm:items-center', bannerTone)}>
              <div className="flex min-w-0 flex-1 items-start gap-3">
                <banner.Icon className={cn('mt-0.5 h-[18px] w-[18px] shrink-0', bannerIcon, status === 'running' && 'animate-spin')} aria-hidden />
                <div className="min-w-0">
                  <p className="text-[14.5px] font-semibold leading-snug">{banner.title}</p>
                  {banner.text && <p className="mt-0.5 text-[13px] leading-snug text-fg/80">{banner.text}</p>}
                </div>
              </div>
              {status === 'done' && (
                <button type="button" onClick={() => openTab(serious.length || sim.findings.length ? 'diagnosis' : 'traffic')} className={cn(quietButton, 'shrink-0 bg-transparent')}>
                  {serious.length || sim.findings.length ? 'Open diagnosis' : 'Test traffic'} <ArrowRight className="h-4 w-4 text-mute" aria-hidden />
                </button>
              )}
            </div>
          </section>

          {/* site switcher, small screens only */}
          <div className="md:hidden">
            <Segmented
              label="Site to configure"
              value={mobileSite}
              onChange={setMobileSite}
              options={[
                { value: 'A', label: `Site A · ${sites.A.name}` },
                { value: 'B', label: `Site B · ${sites.B.name}` },
              ]}
            />
          </div>

          <div className={cn('min-w-0 xl:col-start-1 xl:row-span-2 xl:row-start-1', mobileSite === 'A' ? 'block' : 'hidden md:block')}>
            <div className="thin-scroll xl:sticky xl:top-4 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto xl:rounded-xl">
              <SitePanel site={sites.A} peer={sites.B} onChange={(p) => update('A', p)} issues={issues.A} />
            </div>
          </div>
          <div className={cn('min-w-0 xl:col-start-3 xl:row-span-2 xl:row-start-1', mobileSite === 'B' ? 'block' : 'hidden md:block')}>
            <div className="thin-scroll xl:sticky xl:top-4 xl:max-h-[calc(100dvh-2rem)] xl:overflow-y-auto xl:rounded-xl">
              <SitePanel site={sites.B} peer={sites.A} onChange={(p) => update('B', p)} issues={issues.B} />
            </div>
          </div>

          {/* results */}
          <section ref={resultsRef} aria-label="Results" className="min-w-0 scroll-mt-4 rounded-xl border border-line bg-panel md:col-span-2 xl:col-span-1 xl:col-start-2 xl:row-start-2">
            <div role="tablist" aria-label="Result views" className="grid grid-cols-5 border-b border-line">
              {TABS.map((t) => {
                const on = tab === t.id;
                const badge = t.id === 'diagnosis' && status === 'done' ? serious.length : 0;
                return (
                  <button
                    key={t.id}
                    type="button"
                    role="tab"
                    id={`tab-${t.id}`}
                    aria-selected={on}
                    aria-controls={`panel-${t.id}`}
                    onClick={() => setTab(t.id)}
                    className={cn(
                      'relative flex h-12 min-w-0 items-center justify-center gap-1.5 px-1 text-[12px] font-medium transition-colors focus-visible:outline-offset-[-2px] sm:text-[13px]',
                      on ? 'text-fg' : 'text-mute hover:text-fg',
                    )}
                  >
                    <span className="truncate sm:hidden">{t.short}</span>
                    <span className="hidden truncate sm:inline">{t.label}</span>
                    {badge > 0 && (
                      <span className={cn('absolute right-0 top-1 grid h-3.5 min-w-3.5 place-items-center rounded-full px-1 font-mono text-[9px] font-semibold text-ink sm:static sm:h-4 sm:min-w-4 sm:text-[10px]', sim.headline.tone === 'bad' ? 'bg-bad' : 'bg-warn')}>
                        {badge}
                        <span className="sr-only"> findings</span>
                      </span>
                    )}
                    <span className={cn('absolute inset-x-2 bottom-0 h-0.5 rounded-full transition-colors', on ? 'bg-fg' : 'bg-transparent')} aria-hidden />
                  </button>
                );
              })}
            </div>
            <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="p-3 sm:p-4">
              {tab === 'negotiation' && <NegotiationTab a={sites.A} b={sites.B} sim={sim} visible={visible} status={status} onRun={start} />}
              {tab === 'diagnosis' && <DiagnosisTab a={sites.A} b={sites.B} sim={sim} status={status} onApply={applyFix} onRun={start} />}
              {tab === 'compare' && <ParametersTab a={sites.A} b={sites.B} />}
              {tab === 'traffic' && <TrafficTab a={sites.A} b={sites.B} sim={sim} status={status} onRun={start} />}
              {tab === 'config' && <ConfigTab a={sites.A} b={sites.B} />}
            </div>
          </section>
        </div>

        {!embedMode && (
          <footer className="mt-8 max-w-[90ch] text-[12px] leading-relaxed text-mute">
            IPSEC VPN Simulator models IKEv1 and IKEv2 with pre-shared keys, NAT traversal, selector matching and the post-tunnel data path. It runs entirely in your browser; nothing you enter is sent anywhere. Treat generated configuration as a starting point and validate it against your platform's documentation.
          </footer>
        )}
      </main>
    </div>
  );
}
