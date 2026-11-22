import { Check, ChevronDown, Copy } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { Severity } from '../lib/simulate';
import type { SiteKey } from '../lib/types';
import { cn } from '../utils/cn';

export const ACCENT: Record<SiteKey, { text: string; bg: string; border: string; soft: string; edge: string }> = {
  A: { text: 'text-a', bg: 'bg-a', border: 'border-a', soft: 'bg-a/10', edge: 'border-a/45' },
  B: { text: 'text-b', bg: 'bg-b', border: 'border-b', soft: 'bg-b/10', edge: 'border-b/45' },
};

export function SiteBadge({ site, className }: { site: SiteKey; className?: string }) {
  return (
    <span
      className={cn('inline-grid h-5 w-5 shrink-0 place-items-center rounded font-mono text-[11px] font-semibold text-ink', ACCENT[site].bg, className)}
      aria-label={`Site ${site}`}
    >
      {site}
    </span>
  );
}

export function IssueDot({ severity }: { severity: Severity }) {
  return (
    <span className="inline-flex items-center" title="Implicated in the diagnosis">
      <span className={cn('h-1.5 w-1.5 rounded-full', severity === 'critical' ? 'bg-bad' : 'bg-warn')} />
      <span className="sr-only">implicated in the diagnosis</span>
    </span>
  );
}

const controlBase =
  'h-11 w-full min-w-0 rounded-md border bg-well px-2.5 text-base text-fg transition-colors placeholder:text-dim hover:border-line-strong focus-visible:border-a focus-visible:outline-offset-0 disabled:opacity-50 md:h-9 md:text-[13px]';

export function Field({
  label, issue, error, children, className, group,
}: { label: string; issue?: Severity; error?: string; children: ReactNode; className?: string; group?: boolean }) {
  // `group` renders a plain container: a <label> around several buttons would forward clicks to the first one.
  const Tag = group ? 'div' : 'label';
  return (
    <Tag className={cn('block min-w-0', className)}>
      <span className="mb-1 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-mute">
        <span className="truncate">{label}</span>
        {issue && <IssueDot severity={issue} />}
      </span>
      {children}
      {error && <span className="mt-1 block text-[11.5px] leading-snug text-bad">{error}</span>}
    </Tag>
  );
}

export function TextInput({
  value, onChange, placeholder, mono = true, invalid, issue, ariaLabel, disabled,
}: {
  value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean; invalid?: boolean; issue?: Severity; ariaLabel?: string; disabled?: boolean;
}) {
  return (
    <input
      type="text"
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      aria-label={ariaLabel}
      aria-invalid={invalid || undefined}
      spellCheck={false}
      autoComplete="off"
      autoCapitalize="off"
      className={cn(
        controlBase,
        mono && 'font-mono',
        disabled && 'opacity-40 bg-raised/30 cursor-not-allowed border-line/50 text-dim placeholder:text-dim/40',
        invalid ? 'border-bad' : issue === 'critical' ? 'border-bad/60' : issue === 'warning' ? 'border-warn/60' : 'border-line',
      )}
    />
  );
}

export interface Option<T> {
  value: T;
  label: string;
  disabled?: boolean;
  title?: string;
}

export function Select<T extends string | number>({
  value, onChange, options, issue, disabled, ariaLabel, className,
}: {
  value: T; onChange: (v: T) => void; options: Option<T>[]; issue?: Severity; disabled?: boolean; ariaLabel?: string; className?: string;
}) {
  return (
    <span className={cn('relative block', className)}>
      <select
        value={String(value)}
        disabled={disabled}
        aria-label={ariaLabel}
        onChange={(e) => {
          const hit = options.find((o) => String(o.value) === e.target.value);
          if (hit) onChange(hit.value);
        }}
        className={cn(
          controlBase,
          'cursor-pointer appearance-none truncate pr-8',
          issue === 'critical' ? 'border-bad/60' : issue === 'warning' ? 'border-warn/60' : 'border-line',
        )}
      >
        {options.map((o) => (
          <option key={String(o.value)} value={String(o.value)} disabled={o.disabled}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" aria-hidden />
    </span>
  );
}

export function Segmented<T extends string>({
  value, onChange, options, label, className,
}: { value: T; onChange: (v: T) => void; options: Option<T>[]; label: string; className?: string }) {
  return (
    <div role="radiogroup" aria-label={label} className={cn('grid auto-cols-fr grid-flow-col gap-0.5 rounded-md border border-line bg-well p-0.5', className)}>
      {options.map((o) => {
        const on = value === o.value;
        return (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={on}
            disabled={o.disabled}
            title={o.title}
            onClick={() => onChange(o.value)}
            className={cn(
              'h-10 min-w-0 truncate rounded px-2 text-[13px] font-medium transition-colors disabled:opacity-40 md:h-8',
              on ? 'bg-raised text-fg shadow-[inset_0_0_0_1px_var(--color-line-strong)]' : 'text-mute hover:bg-raised/50 hover:text-fg',
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

export function ToggleSwitch({
  checked,
  onChange,
  disabled,
  ariaLabel,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="inline-flex shrink-0 items-center justify-center p-0.5"
    >
      <span
        className={cn(
          'relative h-4 w-7 shrink-0 rounded-full border transition-colors',
          checked ? 'border-ok bg-ok' : 'border-line-strong bg-well'
        )}
        aria-hidden
      >
        <span
          className={cn(
            'absolute left-0 top-[1px] h-2.5 w-2.5 rounded-full transition-transform duration-150',
            checked ? 'translate-x-[13px] bg-ink' : 'translate-x-[2px] bg-mute'
          )}
        />
      </span>
    </button>
  );
}

export function Toggle({
  checked, onChange, label, hint, issue, danger, disabled,
}: {
  checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string; issue?: Severity; danger?: boolean; disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className="flex min-h-11 w-full items-center gap-3 rounded-md px-1.5 py-1.5 text-left transition-colors hover:bg-raised/60 disabled:opacity-50 disabled:hover:bg-transparent md:min-h-9"
    >
      <span
        className={cn(
          'relative h-5 w-9 shrink-0 rounded-full border transition-colors',
          checked ? (danger ? 'border-bad bg-bad' : 'border-ok bg-ok') : 'border-line-strong bg-well',
        )}
        aria-hidden
      >
        <span
          className={cn(
            'absolute left-0 top-[2px] h-3.5 w-3.5 rounded-full transition-transform duration-150',
            checked ? 'translate-x-[18px] bg-ink' : 'translate-x-[2px] bg-mute',
          )}
        />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5 text-[13px] leading-snug text-fg">
          {label}
          {issue && <IssueDot severity={issue} />}
        </span>
        {hint && <span className="block text-[11.5px] leading-snug text-mute">{hint}</span>}
      </span>
    </button>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

export function CopyButton({ text, label = 'Copy', compact }: { text: string; label?: string; compact?: boolean }) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <button
      type="button"
      onClick={async () => {
        const ok = await copyText(text);
        setState(ok ? 'ok' : 'fail');
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setState('idle'), 1600);
      }}
      aria-label={compact ? `${label}: ${text.split('\n')[0]}` : undefined}
      className={cn(
        'inline-flex shrink-0 items-center justify-center gap-1.5 rounded-md border border-line text-[12px] font-medium text-mute transition-colors hover:border-line-strong hover:text-fg',
        compact ? 'h-10 w-10 md:h-8 md:w-8' : 'h-10 px-3 md:h-8 md:px-2.5',
      )}
    >
      {state === 'ok' ? <Check className="h-3.5 w-3.5 text-ok" aria-hidden /> : <Copy className="h-3.5 w-3.5" aria-hidden />}
      {!compact && <span aria-live="polite">{state === 'ok' ? 'Copied' : state === 'fail' ? 'Select and copy manually' : label}</span>}
    </button>
  );
}

export function Chip({ children, tone = 'neutral', className }: { children: ReactNode; tone?: 'neutral' | 'ok' | 'warn' | 'bad'; className?: string }) {
  const tones = {
    neutral: 'border-line text-mute',
    ok: 'border-ok/40 bg-ok/10 text-ok',
    warn: 'border-warn/40 bg-warn/10 text-warn',
    bad: 'border-bad/40 bg-bad/10 text-bad',
  };
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-px font-mono text-[10.5px] font-medium uppercase tracking-[0.04em]', tones[tone], className)}>
      {children}
    </span>
  );
}

export function EmptyState({ title, text, action }: { title: string; text: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-line px-5 py-10 text-center">
      <div>
        <p className="text-[15px] font-medium text-fg">{title}</p>
        <p className="mx-auto mt-1 max-w-[46ch] text-[13px] text-mute">{text}</p>
      </div>
      {action}
    </div>
  );
}

export function PrimaryButton({ children, onClick, className }: { children: ReactNode; onClick: () => void; className?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex h-11 items-center justify-center gap-2 rounded-md bg-fg px-4 text-[14px] font-semibold text-ink transition-[background-color,transform] hover:bg-white active:translate-y-px',
        className,
      )}
    >
      {children}
    </button>
  );
}
