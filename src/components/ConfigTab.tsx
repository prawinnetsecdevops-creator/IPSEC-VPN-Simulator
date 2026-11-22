import { Download } from 'lucide-react';
import { useMemo, useState } from 'react';
import { generateConfig } from '../lib/config';
import { tok, type Site, type SiteKey } from '../lib/types';
import { VENDORS, verifyCommands, type CmdStage } from '../lib/vendors';
import { cn } from '../utils/cn';
import { CopyButton, Segmented } from './ui';

const STAGE_LABEL: Record<CmdStage, string> = { ike: 'Phase 1', ipsec: 'Phase 2', traffic: 'Path and policy', debug: 'Debug' };

function lineClass(line: string): string {
  if (line.includes('FAULT:')) return 'bg-bad/10 text-bad';
  if (line.includes('UNSUPPORTED:')) return 'bg-warn/10 text-warn';
  const t = line.trim();
  if (t.startsWith('!') || t.startsWith('#')) return 'text-dim';
  return 'text-fg/90';
}

function download(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text + '\n'], { type: 'text/plain' }));
  const el = document.createElement('a');
  el.href = url;
  el.download = name;
  document.body.appendChild(el);
  el.click();
  el.remove();
  URL.revokeObjectURL(url);
}

export function ConfigTab({ a, b }: { a: Site; b: Site }) {
  const [which, setWhich] = useState<SiteKey>('A');
  const s = which === 'A' ? a : b;
  const o = which === 'A' ? b : a;
  const v = VENDORS[s.vendor];
  const text = useMemo(() => generateConfig(s, o), [s, o]);
  const lines = text.split('\n');
  const cmds = verifyCommands(s, o);
  const faults = lines.filter((l) => l.includes('FAULT:')).length;
  const fileName = `${tok(s.name).toLowerCase()}-${v.file}`;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented
          label="Site"
          value={which}
          onChange={setWhich}
          className="w-full sm:w-auto sm:min-w-[300px]"
          options={[
            { value: 'A', label: `A · ${a.name}` },
            { value: 'B', label: `B · ${b.name}` },
          ]}
        />
        <span className="text-[12.5px] text-mute">
          {v.name} · {v.platform}
        </span>
      </div>

      <section aria-label="Generated configuration" className="overflow-hidden rounded-lg border border-line bg-term">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
          <span className="min-w-0 truncate font-mono text-[12px] text-mute">{fileName}</span>
          {faults > 0 && <span className="font-mono text-[11px] text-bad">{faults} fault{faults > 1 ? 's' : ''} marked</span>}
          <span className="ml-auto flex gap-2">
            <CopyButton text={text} />
            <button
              type="button"
              onClick={() => download(fileName, text)}
              className="inline-flex h-10 items-center gap-1.5 rounded-md border border-line px-3 text-[12px] md:h-8 md:px-2.5 font-medium text-mute transition-colors hover:border-line-strong hover:text-fg"
            >
              <Download className="h-3.5 w-3.5" aria-hidden /> Download
            </button>
          </span>
        </div>
        <div className="thin-scroll max-h-[560px] overflow-y-auto py-2 font-mono text-[12px] leading-[1.6]" tabIndex={0} role="region" aria-label={`${s.name} configuration`}>
          {lines.map((l, i) => (
            <div key={i} className={cn('grid grid-cols-[2.75rem_minmax(0,1fr)]', lineClass(l))}>
              <span className="select-none pr-3 text-right text-dim/70" aria-hidden>
                {i + 1}
              </span>
              <span className="whitespace-pre-wrap pr-3 [overflow-wrap:anywhere]">{l || '\u00a0'}</span>
            </div>
          ))}
        </div>
      </section>
      <p className="-mt-3 text-[12px] leading-snug text-mute">
        Generated from this site's own settings, so any fault you configured appears here too. Interface and zone names are placeholders. Review before using on production equipment.
      </p>

      <section aria-label="Verification commands">
        <h3 className="mb-2 text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Verify and debug on {v.short}</h3>
        <ul className="grid gap-2 lg:grid-cols-2">
          {cmds.map((c) => (
            <li key={c.cmd} className="rounded-md border border-line bg-term">
              <div className="flex items-start gap-2 px-2.5 py-2">
                <pre className="min-w-0 flex-1 whitespace-pre-wrap font-mono text-[12px] leading-snug text-fg [overflow-wrap:anywhere]">{c.cmd}</pre>
                <CopyButton text={c.cmd} compact label="Copy command" />
              </div>
              <p className="border-t border-line px-2.5 py-1.5 text-[12px] leading-snug text-mute">
                <span className="mr-1.5 font-mono text-[10.5px] uppercase tracking-[0.04em] text-dim">{STAGE_LABEL[c.stage]}</span>
                {c.why}
              </p>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
