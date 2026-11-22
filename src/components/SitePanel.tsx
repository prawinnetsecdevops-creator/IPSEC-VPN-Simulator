import { ChevronDown } from 'lucide-react';
import { useId, useState, type ReactNode } from 'react';
import { isCidr, isIp } from '../lib/net';
import { selectors, type Severity } from '../lib/simulate';
import {
  DH_NAME, HASH_LABEL, P1_ENC_LABEL, P1_LIFETIMES, P2_ENC_LABEL, P2_LIFETIMES, ifaceIp, isGcm, lifeLabel,
  type Hash, type P1Enc, type P2Enc, type Site,
} from '../lib/types';
import {
  VENDORS,
  VENDOR_LIST,
  getVendorDh,
  getVendorP1Enc,
  getVendorP1Hash,
  getVendorP2Auth,
  getVendorP2Enc,
} from '../lib/vendors';
import { cn } from '../utils/cn';
import { ACCENT, Field, IssueDot, Segmented, Select, SiteBadge, TextInput, Toggle, ToggleSwitch } from './ui';

type Issues = Partial<Record<keyof Site, Severity>>;

const dhShort = (g: number) => (g === 0 ? 'Off' : `${g} · ${DH_NAME[g]}`);

function Section({
  title, summary, flag, children,
}: { title: string; summary: string; flag?: Severity; children: ReactNode }) {
  const [open, setOpen] = useState(true);
  const id = useId();
  return (
    <section className="border-t border-line">
      <h3>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={id}
          onClick={() => setOpen((o) => !o)}
          className="flex min-h-11 w-full items-center gap-2 px-4 py-2 text-left transition-colors hover:bg-raised/50"
        >
          <span className="shrink-0 text-[12px] font-semibold uppercase tracking-[0.08em] text-fg">{title}</span>
          {flag && <IssueDot severity={flag} />}
          <span className="ml-auto min-w-0 truncate font-mono text-[11px] text-mute">{open ? '' : summary}</span>
          <ChevronDown className={cn('h-4 w-4 shrink-0 text-mute transition-transform', open && 'rotate-180')} aria-hidden />
        </button>
      </h3>
      {open && (
        <div id={id} className="grid grid-cols-2 gap-x-3 gap-y-3 px-4 pb-4 pt-1">
          {children}
        </div>
      )}
    </section>
  );
}

const worst = (issues: Issues, keys: (keyof Site)[]): Severity | undefined => {
  const found = keys.map((k) => issues[k]).filter(Boolean) as Severity[];
  return found.includes('critical') ? 'critical' : found[0];
};

export function SitePanel({
  site: s, peer, onChange, issues, className,
}: { site: Site; peer: Site; onChange: (patch: Partial<Site>) => void; issues: Issues; className?: string }) {
  const v = VENDORS[s.vendor];
  const v2 = s.ikeVersion === 'ikev2';
  const sel = selectors(s);
  const gcm = isGcm(s.p2Enc);
  const set = <K extends keyof Site>(k: K) => (value: Site[K]) => onChange({ [k]: value } as Partial<Site>);
  const ipErr = (val: string) => (val.trim() && !isIp(val) ? 'Not a valid IPv4 address' : !val.trim() ? 'Required' : undefined);
  const netErr = (val: string) => (isCidr(val) ? undefined : 'Use CIDR notation, e.g. 10.10.0.0/24');
  const natMappedErr = (val: string) =>
    val.trim() && !isIp(val) && !isCidr(val) ? 'Enter a valid IPv4 address or CIDR subnet' : undefined;

  const p1EncOptions = Array.from(new Set([...getVendorP1Enc(s.vendor, v2), s.p1Enc])).map((val) => ({
    value: val,
    label: P1_ENC_LABEL[val] || val,
  }));
  const p1HashOptions = Array.from(new Set([...getVendorP1Hash(s.vendor, v2), s.p1Hash])).map((val) => ({
    value: val,
    label: HASH_LABEL[val] || val,
  }));
  const p2EncOptions = Array.from(new Set([...getVendorP2Enc(s.vendor), s.p2Enc])).map((val) => ({
    value: val,
    label: P2_ENC_LABEL[val] || val,
  }));
  const p2AuthOptions = Array.from(new Set([...getVendorP2Auth(s.vendor), s.p2Auth])).map((val) => ({
    value: val,
    label: HASH_LABEL[val] || val,
  }));
  const dhOptions = Array.from(new Set([...getVendorDh(s.vendor), s.dh])).map((g) => ({
    value: g,
    label: dhShort(g),
  }));
  const pfsOptions = Array.from(new Set([0, ...getVendorDh(s.vendor), s.pfs])).map((g) => ({
    value: g,
    label: dhShort(g),
  }));

  return (
    <div className={cn('overflow-hidden rounded-xl border border-line bg-panel', className)}>
      <div className={cn('border-t-2 px-4 pb-4 pt-3', ACCENT[s.key].border)}>
        <div className="flex items-center gap-2">
          <SiteBadge site={s.key} className="h-6 w-6 text-[12px]" />
          <h2 className="text-[12px] font-semibold uppercase tracking-[0.08em] text-mute">Site {s.key}</h2>
        </div>
        <div className="mt-3 grid grid-cols-[minmax(0,2fr)_minmax(0,3fr)] gap-3">
          <Field label="Name">
            <TextInput value={s.name} onChange={set('name')} mono={false} placeholder={`Site ${s.key}`} />
          </Field>
          <Field label="Platform">
            <Select value={s.vendor} onChange={set('vendor')} options={VENDOR_LIST.map((x) => ({ value: x.id, label: x.name }))} />
          </Field>
        </div>
        <p className="mt-2 text-[11.5px] text-mute">
          {v.platform}
          {v.tunnelTypes.length === 1 && ` · ${v.tunnelTypes[0] === 'route' ? 'route-based only' : 'policy-based only'}`}
        </p>
      </div>

      <Section
        title="Addressing"
        summary={`${s.wanIp} → ${s.peerIp}${s.snat || s.dnat ? ` · ${[s.snat && 'SNAT', s.dnat && 'DNAT'].filter(Boolean).join('+')}` : ''}`}
        flag={worst(issues, ['wanIp', 'peerIp', 'lan', 'remoteLan', 'natInsideIp', 'snat', 'snatIp', 'dnat', 'dnatIp'])}
      >
        <Field label="Public IP" error={ipErr(s.wanIp)}>
          <TextInput
            value={s.wanIp}
            onChange={(val) => {
              const patch: Partial<Site> = { wanIp: val };
              // When public WAN IP changes, if localId was unset or equal to previous WAN IP, update localId default
              if (!s.behindNat && (!s.localId.trim() || s.localId === s.wanIp)) {
                patch.localId = val;
              }
              onChange(patch);
            }}
            invalid={!!ipErr(s.wanIp)}
            issue={issues.wanIp}
          />
        </Field>
        <Field label="Peer address" issue={issues.peerIp} error={ipErr(s.peerIp)}>
          <TextInput
            value={s.peerIp}
            onChange={(val) => {
              const patch: Partial<Site> = { peerIp: val };
              // When peer address changes, if remoteId was unset or equal to previous peerIp, update remoteId default
              if (!s.remoteId.trim() || s.remoteId === s.peerIp) {
                patch.remoteId = val;
              }
              onChange(patch);
            }}
            invalid={!!ipErr(s.peerIp)}
            issue={issues.peerIp}
          />
        </Field>
        <div className="col-span-2">
          <Toggle
            checked={s.behindNat}
            onChange={set('behindNat')}
            label="Gateway sits behind NAT"
            hint="An upstream router translates its private WAN address"
          />
        </div>
        {s.behindNat && (
          <Field label="Private WAN address" className="col-span-2" error={ipErr(s.natInsideIp)}>
            <TextInput value={s.natInsideIp} onChange={set('natInsideIp')} invalid={!!ipErr(s.natInsideIp)} />
          </Field>
        )}
        <Field label="Local network" issue={issues.lan} error={netErr(s.lan)}>
          <TextInput value={s.lan} onChange={set('lan')} invalid={!!netErr(s.lan)} issue={issues.lan} />
        </Field>
        <Field label="Remote network" issue={issues.remoteLan} error={netErr(s.remoteLan)}>
          <TextInput value={s.remoteLan} onChange={set('remoteLan')} invalid={!!netErr(s.remoteLan)} issue={issues.remoteLan} />
        </Field>
        {/* SNAT (col 1) and DNAT (col 2) side-by-side matching Local / Remote Network layout */}
        <div className="col-span-1 min-w-0">
          <div className="mb-1 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-mute">
              <span>SNAT</span>
              {issues.snat && <IssueDot severity={issues.snat} />}
            </span>
            <ToggleSwitch
              checked={s.snat}
              onChange={(checked) => onChange({ snat: checked, natExempt: !checked })}
              ariaLabel="Toggle SNAT"
            />
          </div>
          <TextInput
            value={s.snat ? s.snatIp : ''}
            onChange={set('snatIp')}
            disabled={!s.snat}
            placeholder={s.snat ? 'e.g. 192.168.50.1/24' : 'Disabled'}
            invalid={s.snat && !!natMappedErr(s.snatIp)}
            issue={issues.snatIp}
          />
          {s.snat && natMappedErr(s.snatIp) && (
            <span className="mt-1 block text-[11.5px] leading-snug text-bad">{natMappedErr(s.snatIp)}</span>
          )}
        </div>

        <div className="col-span-1 min-w-0">
          <div className="mb-1 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-mute">
              <span>DNAT</span>
              {issues.dnat && <IssueDot severity={issues.dnat} />}
            </span>
            <ToggleSwitch
              checked={s.dnat}
              onChange={(checked) => onChange({ dnat: checked })}
              ariaLabel="Toggle DNAT"
            />
          </div>
          <TextInput
            value={s.dnat ? s.dnatIp : ''}
            onChange={set('dnatIp')}
            disabled={!s.dnat}
            placeholder={s.dnat ? 'e.g. 10.10.0.100/32' : 'Disabled'}
            invalid={s.dnat && !!natMappedErr(s.dnatIp)}
            issue={issues.dnatIp}
          />
          {s.dnat && natMappedErr(s.dnatIp) && (
            <span className="mt-1 block text-[11.5px] leading-snug text-bad">{natMappedErr(s.dnatIp)}</span>
          )}
        </div>
      </Section>

      <Section
        title="Phase 1 · IKE"
        summary={`${v2 ? 'v2' : 'v1'} · ${P1_ENC_LABEL[s.p1Enc]} · ${HASH_LABEL[s.p1Hash]} · DH${s.dh}`}
        flag={worst(issues, ['ikeVersion', 'mode', 'p1Enc', 'p1Hash', 'dh', 'psk', 'localId', 'remoteId', 'natT', 'p1Life', 'dpd'])}
      >
        <Field group label="IKE version" issue={issues.ikeVersion} className={v2 ? 'col-span-2' : ''}>
          <Segmented
            label="IKE version"
            value={s.ikeVersion}
            onChange={set('ikeVersion')}
            options={[{ value: 'ikev1', label: 'IKEv1' }, { value: 'ikev2', label: 'IKEv2' }]}
          />
        </Field>
        {!v2 && (
          <Field group label="Exchange mode" issue={issues.mode}>
            <Segmented
              label="Exchange mode"
              value={s.mode}
              onChange={set('mode')}
              options={[{ value: 'main', label: 'Main' }, { value: 'aggressive', label: 'Aggr.', title: 'Aggressive mode' }]}
            />
          </Field>
        )}
        <Field label="Encryption" issue={issues.p1Enc}>
          <Select<P1Enc> value={s.p1Enc} onChange={set('p1Enc')} options={p1EncOptions} issue={issues.p1Enc} />
        </Field>
        <Field label={v2 ? 'Integrity / PRF' : 'Hash'} issue={issues.p1Hash}>
          <Select<Hash> value={s.p1Hash} onChange={set('p1Hash')} options={p1HashOptions} issue={issues.p1Hash} />
        </Field>
        <Field label="DH group" issue={issues.dh}>
          <Select<number> value={s.dh} onChange={set('dh')} options={dhOptions} issue={issues.dh} />
        </Field>
        <Field label="Lifetime" issue={issues.p1Life}>
          <Select<number> value={s.p1Life} onChange={set('p1Life')} options={P1_LIFETIMES.map((t) => ({ value: t, label: lifeLabel(t) }))} />
        </Field>
        <Field label="Pre-shared key" issue={issues.psk} className="col-span-2" error={s.psk ? undefined : 'Required'}>
          <TextInput value={s.psk} onChange={set('psk')} issue={issues.psk} invalid={!s.psk} />
        </Field>
        <Field label="Local ID" issue={issues.localId}>
          <TextInput value={s.localId} onChange={set('localId')} placeholder={ifaceIp(s) || 'local IP'} issue={issues.localId} />
        </Field>
        <Field label="Remote ID" issue={issues.remoteId}>
          <TextInput value={s.remoteId} onChange={set('remoteId')} placeholder={s.peerIp || peer.wanIp || 'peer IP'} issue={issues.remoteId} />
        </Field>
        <div className="col-span-2 -mt-1 text-[11.5px] leading-snug text-mute">
          Local ID defaults to this gateway's address and Remote ID to the peer address. Type any in Remote ID to accept any identity.
        </div>
        <div className="col-span-2 grid grid-cols-2 gap-x-3">
          <Toggle checked={s.natT} onChange={set('natT')} label="NAT-T" issue={issues.natT} />
          <Toggle checked={s.dpd} onChange={set('dpd')} label="DPD" issue={issues.dpd} />
        </div>
      </Section>

      <Section
        title="Phase 2 · IPsec"
        summary={`${s.tunnelType} · ${P2_ENC_LABEL[s.p2Enc]}${s.pfs ? ` · PFS${s.pfs}` : ''}`}
        flag={worst(issues, ['tunnelType', 'specificSelectors', 'p2Enc', 'p2Auth', 'pfs', 'p2Life'])}
      >
        <Field group label="Tunnel model" issue={issues.tunnelType} className="col-span-2">
          <Segmented
            label="Tunnel model"
            value={s.tunnelType}
            onChange={set('tunnelType')}
            options={[
              { value: 'route', label: 'Route-based', disabled: !v.tunnelTypes.includes('route'), title: v.tunnelTypes.includes('route') ? undefined : `${v.short} has no native route-based IPsec` },
              { value: 'policy', label: 'Policy-based', disabled: !v.tunnelTypes.includes('policy'), title: v.tunnelTypes.includes('policy') ? undefined : `${v.short} VPNs are always route-based` },
            ]}
          />
        </Field>
        {s.tunnelType === 'route' && (
          <div className="col-span-2">
            <Toggle
              checked={s.specificSelectors}
              onChange={set('specificSelectors')}
              disabled={!v.routeSpecific}
              issue={issues.specificSelectors}
              label="Narrow selectors (proxy IDs)"
              hint={v.routeSpecific ? 'Needed when the peer is policy-based' : `${v.short} tunnel interfaces always negotiate 0.0.0.0/0`}
            />
          </div>
        )}
        <div className="col-span-2 rounded-md border border-line bg-well px-2.5 py-2">
          <div className="text-[10.5px] font-medium uppercase tracking-[0.06em] text-mute">Negotiated selectors</div>
          <div className="mt-0.5 font-mono text-[12.5px] text-fg [overflow-wrap:anywhere]">
            {sel.local} <span className="text-mute">⇄</span> {sel.remote}
          </div>
        </div>
        <Field label="Encryption" issue={issues.p2Enc}>
          <Select<P2Enc> value={s.p2Enc} onChange={set('p2Enc')} options={p2EncOptions} issue={issues.p2Enc} />
        </Field>
        <Field label="Authentication" issue={gcm ? undefined : issues.p2Auth}>
          {gcm ? (
            <Select<string> value="gcm" onChange={() => {}} disabled options={[{ value: 'gcm', label: 'Built into GCM / AEAD' }]} />
          ) : (
            <Select<Hash> value={s.p2Auth} onChange={set('p2Auth')} options={p2AuthOptions} issue={issues.p2Auth} />
          )}
        </Field>
        <Field label="PFS" issue={issues.pfs}>
          <Select<number> value={s.pfs} onChange={set('pfs')} options={pfsOptions} issue={issues.pfs} />
        </Field>
        <Field label="Lifetime" issue={issues.p2Life}>
          <Select<number> value={s.p2Life} onChange={set('p2Life')} options={P2_LIFETIMES.map((t) => ({ value: t, label: lifeLabel(t) }))} />
        </Field>
      </Section>

      <Section
        title="Data path"
        summary={[s.snat && 'SNAT', s.dnat && 'DNAT', !s.natExempt && 'NAT', !s.fwPolicy && 'policy', s.tunnelType === 'route' && !s.route && 'route', (s.blockIke || s.block4500 || s.blockEsp) && 'filter'].filter(Boolean).join(' · ') || 'clean'}
        flag={worst(issues, ['snat', 'dnat', 'natExempt', 'fwPolicy', 'route', 'blockIke', 'block4500', 'blockEsp'])}
      >
        <div className="col-span-2 -mx-1.5">
          <Toggle checked={s.fwPolicy} onChange={set('fwPolicy')} issue={issues.fwPolicy} label="Security policy" hint="Permits LAN ⇄ VPN in both directions" />
          {s.tunnelType === 'route' && (
            <Toggle checked={s.route} onChange={set('route')} issue={issues.route} label="Route into tunnel" hint="Static route for the remote network" />
          )}
        </div>
        <div className="col-span-2 border-t border-line pt-3">
          <div className="text-[11px] font-medium uppercase tracking-[0.06em] text-mute">Upstream of this gateway</div>
          <p className="mt-0.5 text-[11.5px] leading-snug text-mute">Simulate an ISP filter or edge ACL you do not control.</p>
          <div className="-mx-1.5 mt-1">
            <Toggle danger checked={s.blockIke} onChange={set('blockIke')} issue={issues.blockIke} label="Drop UDP 500 (IKE)" />
            <Toggle danger checked={s.block4500} onChange={set('block4500')} issue={issues.block4500} label="Drop UDP 4500 (NAT-T)" />
            <Toggle danger checked={s.blockEsp} onChange={set('blockEsp')} issue={issues.blockEsp} label="Drop ESP (IP protocol 50)" />
          </div>
        </div>
      </Section>
    </div>
  );
}
