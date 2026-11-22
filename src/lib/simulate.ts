import { cidrOverlap, hex, hostIn, ipInCidr, isCidr, isIp, normCidr, parseCidr } from './net';
import { ERROR_EVENTS, vendorLog, type LogCtx, type LogEvent } from './logs';
import {
  DH_NAME, HASH_LABEL, P1_ENC_LABEL, P2_ENC_LABEL, idOf, ifaceIp, isGcm, tok, type Site, type SiteKey,
} from './types';
import { VENDORS, tunnelName } from './vendors';

export type SaState = 'down' | 'negotiating' | 'up' | 'failed';
export type StepStatus = 'ok' | 'fail' | 'lost';

export interface LogLine {
  site: SiteKey;
  text: string;
  level: 'info' | 'error';
}

export interface Step {
  name: string;
  title: string;
  payload: string;
  from: SiteKey;
  port: 500 | 4500;
  phase: 1 | 2;
  status: StepStatus;
  note: string;
  logs: LogLine[];
  p1: SaState;
  p2: SaState;
}

export type Severity = 'critical' | 'warning' | 'info';
export type Stage = 'Reachability' | 'Phase 1' | 'Phase 2' | 'Data path' | 'Advisory';

export interface Fix {
  label: string;
  patches: { site: SiteKey; patch: Partial<Site> }[];
}

export interface Finding {
  code: string;
  severity: Severity;
  stage: Stage;
  title: string;
  detail: string;
  symptom?: string;
  fixes: Fix[];
  fields: { site: SiteKey; field: keyof Site }[];
  blocking?: boolean;
}

export interface Hop {
  site?: SiteKey;
  where: string;
  text: string;
  ok: boolean;
}

export interface Trace {
  from: SiteKey;
  src: string;
  dst: string;
  srcPostNat?: string;
  dstPostNat?: string;
  hops: Hop[];
  success: boolean;
  failCode?: string;
  counters: Record<SiteKey, { encaps: number; decaps: number }>;
}

export interface SimResult {
  initiator: SiteKey;
  exchange: string;
  steps: Step[];
  p1: SaState;
  p2: SaState;
  failCode?: string;
  nat: boolean;
  float: boolean;
  findings: Finding[];
  traffic: Record<SiteKey, Trace>;
  trafficOk: boolean;
  spi: Record<SiteKey, string>;
  headline: { tone: 'ok' | 'warn' | 'bad'; title: string; text: string };
}

/** Which gateway refused a failed message: the sender when the message is itself an error notify, otherwise the receiver. */
export function rejectedBy(step: Step): SiteKey {
  const notify = /N\((NO|INVALID|AUTH|TS)/.test(step.payload);
  return notify ? step.from : step.from === 'A' ? 'B' : 'A';
}

/* ---------- derived values ---------- */

/** The effective crypto subnet this site advertises/encrypts for local traffic (accounting for SNAT) */
export function cryptoSubnet(s: Site): string {
  if (s.snat && s.snatIp.trim()) {
    const c = parseCidr(s.snatIp.trim());
    if (c) return c.cidr;
    if (isIp(s.snatIp.trim())) return `${s.snatIp.trim()}/32`;
  }
  return normCidr(s.lan);
}

export function selectors(s: Site) {
  const any = s.tunnelType === 'route' && !s.specificSelectors;
  return { any, local: any ? '0.0.0.0/0' : cryptoSubnet(s), remote: any ? '0.0.0.0/0' : normCidr(s.remoteLan) };
}

/** Does this gateway check the identity its peer presents? */
export const validatesId = (s: Site) => s.remoteId.trim() !== '' || VENDORS[s.vendor].strictId(s.ikeVersion);
export const expectedId = (s: Site) => s.remoteId.trim() || s.peerIp.trim();

export interface Diff {
  field: keyof Site;
  label: string;
  x: string;
  y: string;
}

export function p1Diff(x: Site, y: Site): Diff[] {
  const d: Diff[] = [];
  if (x.p1Enc !== y.p1Enc) d.push({ field: 'p1Enc', label: 'encryption', x: P1_ENC_LABEL[x.p1Enc], y: P1_ENC_LABEL[y.p1Enc] });
  if (x.p1Hash !== y.p1Hash) d.push({ field: 'p1Hash', label: 'hash', x: HASH_LABEL[x.p1Hash], y: HASH_LABEL[y.p1Hash] });
  if (x.dh !== y.dh) d.push({ field: 'dh', label: 'DH group', x: `group ${x.dh}`, y: `group ${y.dh}` });
  return d;
}

export function p2Diff(x: Site, y: Site, withPfs: boolean): Diff[] {
  const d: Diff[] = [];
  if (x.p2Enc !== y.p2Enc) d.push({ field: 'p2Enc', label: 'encryption', x: P2_ENC_LABEL[x.p2Enc], y: P2_ENC_LABEL[y.p2Enc] });
  if (!isGcm(x.p2Enc) && !isGcm(y.p2Enc) && x.p2Auth !== y.p2Auth)
    d.push({ field: 'p2Auth', label: 'authentication', x: HASH_LABEL[x.p2Auth], y: HASH_LABEL[y.p2Auth] });
  if (withPfs && x.pfs !== y.pfs) d.push({ field: 'pfs', label: 'PFS', x: x.pfs ? `group ${x.pfs}` : 'off', y: y.pfs ? `group ${y.pfs}` : 'off' });
  return d;
}

const p1Suite = (s: Site) => `${P1_ENC_LABEL[s.p1Enc]} / ${HASH_LABEL[s.p1Hash]} / DH ${s.dh}`;
const p2Suite = (s: Site) => `${P2_ENC_LABEL[s.p2Enc]}${isGcm(s.p2Enc) ? '' : ` / ${HASH_LABEL[s.p2Auth]}`}${s.pfs ? ` / PFS ${s.pfs}` : ''}`;
const verLabel = (s: Site) => (s.ikeVersion === 'ikev2' ? 'IKEv2' : 'IKEv1');
const list = (d: Diff[]) => d.map((x) => x.label).join(', ');

const SA_STAGE = new Set<LogEvent>(['start', 'respond', 'unknown_peer', 'version', 'mode', 'p1_reject', 'p1_rejected', 'nat', 'timeout']);

/* ---------- negotiation ---------- */

export function simulate(a: Site, b: Site, initiator: SiteKey): SimResult {
  const I = initiator === 'A' ? a : b;
  const R = initiator === 'A' ? b : a;
  const v2 = I.ikeVersion === 'ikev2';
  const main = I.mode === 'main';
  const nat = a.behindNat || b.behindNat;
  const float = nat && a.natT && b.natT;
  const port: 500 | 4500 = float ? 4500 : 500;
  const selI = selectors(I);
  const selR = selectors(R);
  const seed = [a.wanIp, b.wanIp, a.psk, b.psk, initiator, a.dh, b.dh, a.p2Enc, b.p2Enc].join('|');
  const spi: Record<SiteKey, string> = { A: hex(seed + 'A', 8), B: hex(seed + 'B', 8) };

  const ctx = (s: Site, stage: 'sa' | 'auth'): LogCtx => {
    const o = s.key === 'A' ? b : a;
    const sel = selectors(s);
    const osel = selectors(o);
    return {
      self: s, other: o, local: ifaceIp(s), remote: s.key === I.key ? s.peerIp : o.wanIp,
      tn: tunnelName(o), T: tok(o.name), v2, main, init: s.key === I.key, stage,
      port: stage === 'auth' ? port : 500,
      selL: sel.local, selR: sel.remote, pL: osel.local, pR: osel.remote,
      myId: idOf(s), idSeen: idOf(o), idWant: expectedId(s), seed,
    };
  };
  const L = (s: Site, e: LogEvent, stage?: 'sa' | 'auth'): LogLine[] =>
    vendorLog(e, ctx(s, stage ?? (SA_STAGE.has(e) ? 'sa' : 'auth'))).map((text) => ({
      site: s.key, text, level: ERROR_EVENTS.has(e) ? 'error' : 'info',
    }));

  const steps: Step[] = [];
  let p1: SaState = 'negotiating';
  let p2: SaState = 'down';
  let failCode: string | undefined;

  const add = (
    from: Site, name: string, title: string, payload: string, prt: 500 | 4500, phase: 1 | 2,
    status: StepStatus, note: string, logs: LogLine[],
  ) => steps.push({ name, title, payload, from: from.key, port: prt, phase, status, note, logs, p1, p2 });

  // conditions, evaluated once; the flow below decides which one bites first
  const peerWrongI = I.peerIp.trim() !== R.wanIp.trim();
  const blk500 = I.blockIke ? I : R.blockIke ? R : null;
  const peerWrongR = R.peerIp.trim() !== I.wanIp.trim();
  const version = I.ikeVersion !== R.ikeVersion;
  const modeMismatch = !v2 && I.mode !== R.mode;
  const d1 = p1Diff(I, R);
  const blk4500 = float ? (I.block4500 ? I : R.block4500 ? R : null) : null;
  const psk = I.psk !== R.psk;
  const idR = validatesId(R) && idOf(I) !== expectedId(R);
  const idI = validatesId(I) && idOf(R) !== expectedId(I);
  const ts = selI.local !== selR.remote || selI.remote !== selR.local;
  const d2 = p2Diff(I, R, !v2);

  const natNote = !nat
    ? 'No NAT detected between the peers.'
    : float
      ? 'NAT detected. Both peers move IKE to UDP 4500 and will wrap ESP in UDP.'
      : `NAT is in the path but NAT-T is disabled on ${[a, b].filter((s) => !s.natT).map((s) => s.name).join(' and ')}. IKE stays on UDP 500.`;
  const natLogs = () => (float ? [...L(I, 'nat'), ...L(R, 'nat')] : []);

  const first = v2
    ? { name: 'IKE_SA_INIT', title: 'Request', payload: 'HDR, SAi1, KEi, Ni, N(NAT_DETECTION_*)' }
    : main
      ? { name: 'MM1', title: 'SA proposal', payload: 'HDR, SA, VID' }
      : { name: 'AM1', title: 'SA, key exchange, identity', payload: 'HDR, SA, KE, Ni, IDii' };

  const quickMode = () => {
    p2 = 'negotiating';
    add(I, 'QM1', 'IPsec proposal and proxy IDs', `HDR*, HASH(1), SA, Ni${I.pfs ? ', KE' : ''}, IDci, IDcr`, port, 2, 'ok',
      `Proposes ${p2Suite(I)} for ${selI.local} ⇄ ${selI.remote}.`, []);
    if (ts) {
      p2 = 'failed'; failCode = 'TS';
      add(R, 'INFORMATIONAL', 'Notify', 'HDR*, HASH, N(INVALID-ID-INFORMATION)', port, 2, 'fail',
        `${R.name} has no phase 2 for ${selI.remote} ⇄ ${selI.local}; it protects ${selR.local} ⇄ ${selR.remote}.`,
        [...L(R, 'ts_reject'), ...L(I, 'ts_rejected')]);
      return;
    }
    if (d2.length) {
      p2 = 'failed'; failCode = 'P2_PROPOSAL';
      add(R, 'INFORMATIONAL', 'Notify', 'HDR*, HASH, N(NO-PROPOSAL-CHOSEN)', port, 2, 'fail',
        `No common ${list(d2)}. ${R.name} expects ${p2Suite(R)}.`, [...L(R, 'p2_reject'), ...L(I, 'p2_rejected')]);
      return;
    }
    add(R, 'QM2', 'IPsec proposal accepted', `HDR*, HASH(2), SA, Nr${R.pfs ? ', KE' : ''}, IDci, IDcr`, port, 2, 'ok',
      `${p2Suite(R)} agreed${R.pfs ? '; fresh DH exchange for PFS' : ''}.`, []);
    p2 = 'up';
    add(I, 'QM3', 'Acknowledge', 'HDR*, HASH(3)', port, 2, 'ok', 'IPsec SAs installed in both directions.', [...L(I, 'p2_up'), ...L(R, 'p2_up')]);
  };

  (() => {
    /* --- first message: reachability and gateway lookup --- */
    if (peerWrongI || blk500) {
      p1 = 'failed';
      failCode = peerWrongI ? `PEER_IP:${I.key}` : `UDP500:${blk500!.key}`;
      add(I, first.name, first.title, first.payload, 500, 1, 'lost',
        peerWrongI
          ? `Sent to ${I.peerIp || '(no address)'}, where no VPN gateway answers. ${I.name} retransmits, then gives up.`
          : `UDP 500 is filtered upstream of ${blk500!.name}. The request never reaches ${R.name}.`,
        [...L(I, 'start'), ...L(I, 'timeout', 'sa')]);
      return;
    }
    if (peerWrongR || version || modeMismatch) {
      p1 = 'failed';
      failCode = peerWrongR ? `PEER_IP:${R.key}` : version ? 'VERSION' : 'MODE';
      add(I, first.name, first.title, first.payload, 500, 1, 'fail',
        peerWrongR
          ? `${R.name} has no gateway defined for source ${I.wanIp} (it expects ${R.peerIp || 'nothing'}) and discards the request.`
          : version
            ? `${R.name} is configured for ${verLabel(R)} only and ignores the ${verLabel(I)} request.`
            : `${R.name} is set to ${R.mode} mode and refuses the ${I.mode} mode exchange.`,
        [...L(I, 'start'), ...L(R, peerWrongR ? 'unknown_peer' : version ? 'version' : 'mode'), ...L(I, 'timeout', 'sa')]);
      return;
    }
    add(I, first.name, first.title, first.payload, 500, 1, 'ok', `Offers ${p1Suite(I)}, pre-shared key authentication.`, [...L(I, 'start'), ...L(R, 'respond')]);

    /* --- phase 1 proposal --- */
    if (d1.length) {
      p1 = 'failed'; failCode = 'P1_PROPOSAL';
      add(R, v2 ? 'IKE_SA_INIT' : 'INFORMATIONAL', v2 ? 'Response' : 'Notify', v2 ? 'HDR, N(NO_PROPOSAL_CHOSEN)' : 'HDR, N(NO-PROPOSAL-CHOSEN)', 500, 1, 'fail',
        `No common ${list(d1)}. ${R.name} only accepts ${p1Suite(R)}.`, [...L(R, 'p1_reject'), ...L(I, 'p1_rejected')]);
      return;
    }

    if (v2) {
      add(R, 'IKE_SA_INIT', 'Response', 'HDR, SAr1, KEr, Nr, N(NAT_DETECTION_*)', 500, 1, 'ok', `${p1Suite(R)} agreed. ${natNote}`, natLogs());
      if (blk4500) {
        p1 = 'failed'; failCode = `UDP4500:${blk4500.key}`;
        add(I, 'IKE_AUTH', 'Request', 'HDR, SK{IDi, AUTH, SAi2, TSi, TSr}', 4500, 1, 'lost',
          `UDP 4500 is filtered upstream of ${blk4500.name}. IKE_SA_INIT worked on port 500, but the NAT-T float is dropped.`, L(I, 'timeout', 'auth'));
        return;
      }
      p2 = 'negotiating';
      add(I, 'IKE_AUTH', 'Request', 'HDR, SK{IDi, AUTH, SAi2, TSi, TSr}', port, 1, 'ok',
        `Identity ${idOf(I)}. Proposes ${p2Suite({ ...I, pfs: 0 })} for ${selI.local} ⇄ ${selI.remote}.`, []);
      if (idR || psk) {
        p1 = 'failed'; p2 = 'down'; failCode = idR ? `ID:${I.key}` : 'PSK';
        add(R, 'IKE_AUTH', 'Response', 'HDR, SK{N(AUTHENTICATION_FAILED)}', port, 1, 'fail',
          idR
            ? `${R.name} expects peer identity ${expectedId(R)} but ${I.name} presented ${idOf(I)}.`
            : `The AUTH payload does not verify: the two pre-shared keys are different.`,
          [...L(R, idR ? 'id_fail' : 'psk_fail'), ...L(I, 'auth_rejected')]);
        return;
      }
      if (idI) {
        p1 = 'failed'; p2 = 'down'; failCode = `ID:${R.key}`;
        add(R, 'IKE_AUTH', 'Response', 'HDR, SK{IDr, AUTH, SAr2, TSi, TSr}', port, 1, 'fail',
          `${I.name} expects peer identity ${expectedId(I)} but ${R.name} identifies as ${idOf(R)}. ${I.name} deletes the SA.`, L(I, 'id_fail'));
        return;
      }
      p1 = 'up';
      if (ts || d2.length) {
        p2 = 'failed'; failCode = ts ? 'TS' : 'P2_PROPOSAL';
        add(R, 'IKE_AUTH', 'Response', `HDR, SK{IDr, AUTH, N(${ts ? 'TS_UNACCEPTABLE' : 'NO_PROPOSAL_CHOSEN'})}`, port, 2, 'fail',
          ts
            ? `Authentication succeeded, so the IKE SA is up. But ${R.name} protects ${selR.local} ⇄ ${selR.remote} and rejects the requested selectors.`
            : `Authentication succeeded, so the IKE SA is up. But there is no common ESP ${list(d2)}; ${R.name} expects ${p2Suite({ ...R, pfs: 0 })}.`,
          [...L(I, 'p1_up'), ...L(R, 'p1_up'), ...L(R, ts ? 'ts_reject' : 'p2_reject'), ...L(I, ts ? 'ts_rejected' : 'p2_rejected')]);
        return;
      }
      p2 = 'up';
      add(R, 'IKE_AUTH', 'Response', 'HDR, SK{IDr, AUTH, SAr2, TSi, TSr}', port, 2, 'ok',
        'Both peers authenticated. IKE SA and the first CHILD_SA are installed.',
        [...L(I, 'p1_up'), ...L(R, 'p1_up'), ...L(I, 'p2_up'), ...L(R, 'p2_up')]);
      return;
    }

    if (main) {
      add(R, 'MM2', 'SA accepted', 'HDR, SA, VID', 500, 1, 'ok', `${p1Suite(R)} agreed.`, []);
      add(I, 'MM3', 'Key exchange', 'HDR, KE, Ni, NAT-D', 500, 1, 'ok', 'Diffie-Hellman public value and nonce.', []);
      add(R, 'MM4', 'Key exchange', 'HDR, KE, Nr, NAT-D', 500, 1, 'ok', `Keys derived from DH and the pre-shared key. ${natNote}`, natLogs());
      if (blk4500) {
        p1 = 'failed'; failCode = `UDP4500:${blk4500.key}`;
        add(I, 'MM5', 'Identity and authentication', 'HDR*, IDii, HASH_I', 4500, 1, 'lost',
          `UDP 4500 is filtered upstream of ${blk4500.name}. MM1–MM4 worked on port 500, but the NAT-T float is dropped.`, L(I, 'timeout', 'auth'));
        return;
      }
      if (psk || idR) {
        p1 = 'failed'; failCode = psk ? 'PSK' : `ID:${I.key}`;
        add(I, 'MM5', 'Identity and authentication', 'HDR*, IDii, HASH_I', port, 1, 'fail',
          psk
            ? `${R.name} derived different keys from its pre-shared secret and cannot decrypt the message. ${I.name} keeps retransmitting.`
            : `${R.name} expects peer identity ${expectedId(R)} but ${I.name} presented ${idOf(I)}.`,
          [...L(R, psk ? 'psk_fail' : 'id_fail'), ...L(I, 'auth_rejected')]);
        return;
      }
      add(I, 'MM5', 'Identity and authentication', 'HDR*, IDii, HASH_I', port, 1, 'ok', `Encrypted. Identity ${idOf(I)}.`, []);
      if (idI) {
        p1 = 'failed'; failCode = `ID:${R.key}`;
        add(R, 'MM6', 'Identity and authentication', 'HDR*, IDir, HASH_R', port, 1, 'fail',
          `${I.name} expects peer identity ${expectedId(I)} but ${R.name} identifies as ${idOf(R)}.`, L(I, 'id_fail'));
        return;
      }
      p1 = 'up';
      add(R, 'MM6', 'Identity and authentication', 'HDR*, IDir, HASH_R', port, 1, 'ok', 'Both peers authenticated. ISAKMP SA established.', [...L(I, 'p1_up'), ...L(R, 'p1_up')]);
      quickMode();
      return;
    }

    /* --- IKEv1 aggressive mode --- */
    if (idR) {
      p1 = 'failed'; failCode = `ID:${I.key}`;
      add(R, 'INFORMATIONAL', 'Notify', 'HDR, N(INVALID-ID-INFORMATION)', 500, 1, 'fail',
        `${R.name} expects peer identity ${expectedId(R)} but ${I.name} presented ${idOf(I)}.`, [...L(R, 'id_fail'), ...L(I, 'timeout', 'sa')]);
      return;
    }
    if (psk || idI) {
      p1 = 'failed'; failCode = psk ? 'PSK' : `ID:${R.key}`;
      add(R, 'AM2', 'SA, key exchange, identity, hash', 'HDR, SA, KE, Nr, IDir, HASH_R, NAT-D', 500, 1, 'fail',
        psk
          ? `${I.name} computes a different HASH_R from its pre-shared key and rejects the reply.`
          : `${I.name} expects peer identity ${expectedId(I)} but ${R.name} identifies as ${idOf(R)}.`,
        [...L(I, psk ? 'psk_fail' : 'id_fail'), ...L(R, 'timeout', 'auth')]);
      return;
    }
    add(R, 'AM2', 'SA, key exchange, identity, hash', 'HDR, SA, KE, Nr, IDir, HASH_R, NAT-D', 500, 1, 'ok', `${p1Suite(R)} agreed. ${natNote}`, natLogs());
    if (blk4500) {
      p1 = 'failed'; failCode = `UDP4500:${blk4500.key}`;
      add(I, 'AM3', 'Authentication', 'HDR*, HASH_I, NAT-D', 4500, 1, 'lost',
        `UDP 4500 is filtered upstream of ${blk4500.name}. The NAT-T float is dropped.`, L(I, 'timeout', 'auth'));
      return;
    }
    p1 = 'up';
    add(I, 'AM3', 'Authentication', 'HDR*, HASH_I, NAT-D', port, 1, 'ok', 'Both peers authenticated. ISAKMP SA established.', [...L(I, 'p1_up'), ...L(R, 'p1_up')]);
    quickMode();
  })();

  const up = p2 === 'up';
  const traffic: Record<SiteKey, Trace> = {
    A: trace(a, b, up, nat, float, failCode, spi),
    B: trace(b, a, up, nat, float, failCode, spi),
  };
  const trafficOk = up && traffic.A.success && traffic.B.success;

  const findings = buildFindings(a, b, I, nat, float);
  const blockCode = failCode ?? (up ? (traffic.A.failCode ?? traffic.B.failCode) : undefined);
  const blocking = findings.find((f) => f.code === blockCode);
  if (blocking) blocking.blocking = true;

  const last = steps[steps.length - 1];
  const advisories = findings.filter((f) => f.severity === 'warning').length;
  const headline: SimResult['headline'] = !up
    ? {
        tone: 'bad',
        title: p1 === 'up' ? 'IKE SA is up, IPsec SA failed' : `Phase 1 failed at ${last.name}`,
        text: blocking?.title ?? last.note,
      }
    : !trafficOk
      ? { tone: 'warn', title: 'Tunnel is up, traffic is not passing', text: blocking?.title ?? 'Check the data path on both gateways.' }
      : {
          tone: advisories ? 'warn' : 'ok',
          title: advisories ? 'Tunnel is up, with warnings' : 'Tunnel established, traffic flowing',
          text: advisories
            ? `${advisories} issue${advisories > 1 ? 's' : ''} will cause trouble later. See the diagnosis.`
            : `${verLabel(I)} · ${p1Suite(I)} · ESP ${p2Suite(I)} · ${float ? 'ESP in UDP 4500' : 'native ESP'}`,
        };

  return {
    initiator,
    exchange: v2 ? 'IKEv2' : `IKEv1 ${main ? 'main' : 'aggressive'} mode`,
    steps, p1, p2, failCode, nat, float, findings, traffic, trafficOk, spi, headline,
  };
}

/* ---------- data path ---------- */

function trace(
  S: Site, D: Site, up: boolean, nat: boolean, float: boolean, failCode: string | undefined,
  spi: Record<SiteKey, string>, n = 5,
): Trace {
  const srcOrig = hostIn(S.lan);
  // Target destination host: uses S.remoteLan (which matches D.lan or D's post-NAT pool)
  const dstOrig = hostIn(S.remoteLan);
  const hops: Hop[] = [];
  const counters = { A: { encaps: 0, decaps: 0 }, B: { encaps: 0, decaps: 0 } };

  // Resolve SNAT translation on Site S
  let srcWire = srcOrig;
  let snatApplied = false;
  if (S.snat) {
    if (S.snatIp.trim()) {
      if (isCidr(S.snatIp)) {
        srcWire = hostIn(S.snatIp);
      } else if (isIp(S.snatIp)) {
        srcWire = S.snatIp.trim();
      }
    } else if (!S.natExempt) {
      srcWire = ifaceIp(S);
    }
    snatApplied = srcWire !== srcOrig;
  }

  // Resolve Outbound DNAT on Site S (when dnatIp targets the remote domain rather than S's own LAN)
  let dstWire = dstOrig;
  let dnatOutApplied = false;
  const dnatTargetHost = S.dnatIp.trim() ? (isIp(S.dnatIp) ? S.dnatIp.trim() : hostIn(S.dnatIp)) : '';
  if (S.dnat && dnatTargetHost && !ipInCidr(dnatTargetHost, S.lan)) {
    dstWire = dnatTargetHost;
    dnatOutApplied = dstWire !== dstOrig;
  }

  let finalDst = dstWire;

  const done = (code?: string): Trace => ({
    from: S.key,
    src: srcOrig,
    dst: dstOrig,
    srcPostNat: snatApplied ? srcWire : undefined,
    dstPostNat: (dnatOutApplied || finalDst !== dstWire) ? finalDst : undefined,
    hops,
    success: !code,
    failCode: code,
    counters,
  });

  const ok = (site: SiteKey | undefined, where: string, text: string) => hops.push({ site, where, text, ok: true });
  const bad = (site: SiteKey | undefined, where: string, text: string, code: string) => {
    hops.push({ site, where, text, ok: false });
    return done(code);
  };

  // Overlap check: only drops if destination is treated as on-link and no NAT translation avoids it
  const sl = parseCidr(S.lan);
  const dl = parseCidr(D.lan);
  if (sl && dl && cidrOverlap(sl, dl) && !dnatOutApplied && !S.snat) {
    return bad(S.key, 'Host', `${dstOrig} falls inside local subnet ${sl.cidr}. The host ARPs for it on its own LAN and never sends it to the gateway.`, 'OVERLAP');
  }

  ok(S.key, 'LAN', `Echo request ${srcOrig} → ${dstOrig} arrives on inside interface of ${S.name}.`);

  if (!S.fwPolicy)
    return bad(S.key, 'Security policy', `No rule permits LAN → VPN. ${S.name} drops the packet before any VPN lookup.`, `POLICY:${S.key}`);
  ok(S.key, 'Security policy', 'A rule permits LAN → VPN.');

  if (!up)
    return bad(S.key, 'IPsec SA', `No IPsec SA exists for this flow. ${S.name} drops the packet and keeps trying to negotiate.`, failCode ?? 'DOWN');

  // Route lookup on S
  if (S.tunnelType === 'route') {
    if (!S.route)
      return bad(S.key, 'Route lookup', `No route for ${dstWire} points into the tunnel. The packet follows the default route toward the internet in clear text.`, `ROUTE:${S.key}`);
    if (!ipInCidr(dstWire, S.remoteLan))
      return bad(S.key, 'Route lookup', `The tunnel route covers ${normCidr(S.remoteLan)}, which does not include ${dstWire}. The packet follows the default route instead.`, `ROUTE_NET:${S.key}`);
    ok(S.key, 'Route lookup', `${normCidr(S.remoteLan)} is routed into the tunnel interface.`);
  } else {
    const selS = selectors(S);
    ok(S.key, 'Crypto policy', `Matches interesting traffic ${selS.local} → ${selS.remote}.`);
  }

  // NAT processing on S
  const selS = selectors(S);
  if (snatApplied) {
    if (!selS.any && !ipInCidr(srcWire, selS.local)) {
      return bad(S.key, 'Source NAT (SNAT)', `Traffic source ${srcOrig} was Source-NATed to ${srcWire}, but does not match ${S.name} IPsec local selector ${selS.local}. Encapsulation denied.`, `NAT_EXEMPT:${S.key}`);
    }
    ok(S.key, 'Source NAT (SNAT)', `Policy SNAT applied: original client ${srcOrig} translated to ${srcWire}${S.snatIp.trim() ? ` (pool ${normCidr(S.snatIp)})` : ''}. Matches IPsec crypto policy.`);
  } else if (!S.natExempt && !S.snat) {
    return bad(S.key, 'NAT', `No NAT exemption: source translated to ${ifaceIp(S)} before encryption, failing IPsec selector match.`, `NAT_EXEMPT:${S.key}`);
  } else {
    ok(S.key, 'NAT', 'Exempt from source NAT. Original addresses are preserved.');
  }

  if (dnatOutApplied) {
    ok(S.key, 'Destination NAT (DNAT)', `Outbound DNAT applied: target destination ${dstOrig} mapped to ${dstWire}.`);
  }

  // Encapsulation
  counters[S.key].encaps += n;
  ok(S.key, 'Encrypt', `ESP tunnel mode, SPI 0x${spi[D.key]}. Inner packet: ${srcWire} → ${dstWire}. Outer header: ${ifaceIp(S)} → ${S.peerIp}${float ? ', UDP 4500' : ''}.`);

  // Internet Transit
  if (nat && !float) {
    const natted = S.behindNat ? S : D;
    return bad(undefined, 'Transit', `ESP is IP protocol 50 and has no ports, so the NAT device in front of ${natted.name} cannot translate it. NAT-T would have wrapped it in UDP 4500.`, 'NAT_NO_NATT');
  }
  if (!float && (S.blockEsp || D.blockEsp)) {
    const x = S.blockEsp ? S : D;
    return bad(undefined, 'Transit', `IP protocol 50 is filtered upstream of ${x.name}. IKE on UDP gets through, ESP does not.`, `ESP:${x.key}`);
  }
  ok(undefined, 'Transit', float ? 'ESP in UDP 4500 crosses the NAT device and the internet.' : 'ESP (IP protocol 50) crosses the internet.');

  // Decrypt on D
  counters[D.key].decaps += n;
  ok(D.key, 'Decrypt', `SPI matched, integrity verified. Inner packet ${srcWire} → ${dstWire} recovered.`);

  if (!D.fwPolicy)
    return bad(D.key, 'Security policy', `The decrypted packet is denied: no rule permits VPN → LAN on ${D.name}.`, `POLICY:${D.key}`);
  ok(D.key, 'Security policy', 'A rule permits VPN → LAN.');

  // Inbound DNAT or NAT-pool mapping on D
  if (D.dnat && D.dnatIp.trim()) {
    finalDst = isCidr(D.dnatIp) ? hostIn(D.dnatIp) : D.dnatIp.trim();
    ok(D.key, 'Destination NAT (DNAT)', `Inbound DNAT applied: packet addressed to ${dstWire} mapped to internal host ${finalDst}.`);
  } else if (D.snat && D.snatIp.trim() && ipInCidr(dstWire, D.snatIp)) {
    finalDst = hostIn(D.lan);
    ok(D.key, 'Inbound NAT (DNAT)', `Inbound NAT applied: traffic to NAT pool address ${dstWire} mapped to internal host ${finalDst}.`);
  }
  ok(D.key, 'LAN', `${finalDst} receives echo request from ${srcWire} and generates echo reply.`);

  // Return path routing and crypto lookup on D
  if (D.tunnelType === 'route') {
    if (!D.route)
      return bad(D.key, 'Route lookup', `No route for ${srcWire} points into the tunnel. Reply follows the default route.`, `ROUTE:${D.key}`);
    if (!ipInCidr(srcWire, D.remoteLan))
      return bad(D.key, 'Route lookup', `${D.name} only routes ${normCidr(D.remoteLan)} into the tunnel, which does not cover client ${srcWire}. Reply follows the default route.`, `ROUTE_NET:${D.key}`);
    ok(D.key, 'Route lookup', `${normCidr(D.remoteLan)} (covering ${srcWire}) is routed into the tunnel interface.`);
  } else {
    const selD = selectors(D);
    if (!selD.any && !ipInCidr(srcWire, selD.remote))
      return bad(D.key, 'Crypto policy', `Reply destination ${srcWire} does not match ${D.name} IPsec remote selector ${selD.remote}.`, `TS:${D.key}`);
    ok(D.key, 'Crypto policy', `Matches interesting traffic ${selD.local} → ${srcWire}.`);
  }

  // Reverse DNAT at D
  if (finalDst !== dstWire) {
    ok(D.key, 'Reverse DNAT', `Echo reply source ${finalDst} un-DNATed back to ${dstWire}.`);
  }

  // Encrypt reply at D
  counters[D.key].encaps += n;
  ok(D.key, 'Encrypt', `Echo reply ${dstWire} → ${srcWire} encrypted with SPI 0x${spi[S.key]}.`);

  // Decrypt reply at S
  counters[S.key].decaps += n;
  ok(S.key, 'Decrypt', `Reply decrypted on ${S.name}: ${dstWire} → ${srcWire}.`);

  // Reverse SNAT at S
  if (snatApplied) {
    ok(S.key, 'Reverse SNAT', `Inbound reply destination ${srcWire} de-NATed back to original client ${srcOrig}.`);
  }
  ok(S.key, 'LAN', `Echo reply successfully delivered to client host ${srcOrig}.`);

  return done();
}

/* ---------- diagnosis ---------- */

function pskHint(x: string, y: string): string {
  if (x.trim() === y.trim()) return 'They differ only by leading or trailing whitespace, a classic copy-and-paste artefact.';
  if (x.toLowerCase() === y.toLowerCase()) return 'They differ only in letter case.';
  if (x.length !== y.length) return `Their lengths differ (${x.length} and ${y.length} characters).`;
  const i = [...x].findIndex((ch, n) => ch !== y[n]);
  return `Same length; the first difference is character ${i + 1} (“${x[i]}” versus “${y[i]}”).`;
}

function selectorFixes(a: Site, b: Site): Fix[] {
  const fixes: Fix[] = [];
  const specific = (s: Site, p: Site): Partial<Site> | null => {
    const v = VENDORS[s.vendor];
    const patch: Partial<Site> = { remoteLan: cryptoSubnet(p) };
    if (s.tunnelType === 'route') {
      if (v.routeSpecific) patch.specificSelectors = true;
      else if (v.tunnelTypes.includes('policy')) patch.tunnelType = 'policy';
      else return null;
    }
    return patch;
  };
  const pa = specific(a, b);
  const pb = specific(b, a);
  if (pa && pb) fixes.push({ label: 'Use matching specific selectors on both sides', patches: [{ site: 'A', patch: pa }, { site: 'B', patch: pb }] });
  if (VENDORS[a.vendor].tunnelTypes.includes('route') && VENDORS[b.vendor].tunnelTypes.includes('route'))
    fixes.push({
      label: 'Make both sides route-based with 0.0.0.0/0',
      patches: [
        { site: 'A', patch: { tunnelType: 'route', specificSelectors: false, remoteLan: normCidr(b.lan) } },
        { site: 'B', patch: { tunnelType: 'route', specificSelectors: false, remoteLan: normCidr(a.lan) } },
      ],
    });
  return fixes;
}

function platformNotes(s: Site): string[] {
  const out: string[] = [];
  const v1 = s.ikeVersion === 'ikev1';
  if (s.vendor === 'cisco-asa' && v1 && !['md5', 'sha1'].includes(s.p1Hash))
    out.push(`ASA IKEv1 policies only accept MD5 or SHA-1 as the hash; ${HASH_LABEL[s.p1Hash]} needs IKEv2.`);
  if (s.vendor === 'cisco-asa' && v1 && (isGcm(s.p2Enc) || !['md5', 'sha1'].includes(s.p2Auth)))
    out.push('ASA IKEv1 transform sets only offer MD5 or SHA-1 HMAC and no GCM; use an IKEv2 ipsec-proposal for stronger ESP.');
  if (s.vendor === 'juniper-srx' && s.tunnelType === 'policy' && !v1)
    out.push('Junos supports policy-based VPNs with IKEv1 only; use a route-based (st0) VPN for IKEv2.');
  if (s.vendor === 'mikrotik' && s.p2Auth === 'sha384' && !isGcm(s.p2Enc))
    out.push('RouterOS proposals do not offer SHA-384 for ESP authentication; SHA-256 and SHA-512 are available.');
  if (s.vendor === 'fortigate' && !s.fwPolicy)
    out.push('FortiOS will not even start IKE for a tunnel that no firewall policy references.');
  if (s.vendor === 'azure') {
    if ([5, 15, 16, 18, 21, 31].includes(s.dh))
      out.push(`Azure custom IKE policy does not offer DH group ${s.dh}; use DHGroup14, DHGroup24, ECP256 or ECP384.`);
    if (s.pfs && [5, 15, 16, 18, 21, 31].includes(s.pfs))
      out.push(`Azure custom IPsec policy does not offer PFS group ${s.pfs}; use PFS14, PFS24, ECP256 or ECP384.`);
    if (!isGcm(s.p2Enc) && ['sha384', 'sha512', 'aesxcbc'].includes(s.p2Auth))
      out.push('Azure custom IPsec policy does not offer SHA-384, SHA-512 or AES-XCBC for ESP integrity; use SHA-256, SHA-1 or AES-GCM.');
    if (v1)
      out.push('Modern Azure route-based VpnGw deployments are IKEv2-first; IKEv1 is limited to legacy/policy-based deployments and specific SKUs.');
    if (v1 && s.mode === 'aggressive')
      out.push('Azure VPN Gateway does not expose IKEv1 aggressive mode; use IKEv2, or IKEv1 main mode where the gateway SKU supports it.');
    if (s.behindNat)
      out.push('An Azure VPN Gateway is a public managed endpoint, not a device behind NAT. NAT-T matters for the on-prem peer; the Azure side should be modelled with its gateway public IP.');
    if (s.localId.trim() || s.remoteId.trim())
      out.push('Azure VPN Gateway uses endpoint IP identities from the gateway public IP and the Local Network Gateway; free-text IKE IDs are not configured the way they are on an on-prem firewall.');
  }
  return out;
}

function weakNotes(s: Site): string[] {
  const out: string[] = [];
  if (s.p1Enc === 'des' || s.p1Enc === '3des') out.push(`${P1_ENC_LABEL[s.p1Enc]} for IKE`);
  if (s.p1Hash === 'md5' || s.p1Hash === 'sha1') out.push(`${HASH_LABEL[s.p1Hash]} for IKE`);
  if (s.dh === 1 || s.dh === 2 || s.dh === 5) out.push(`DH group ${s.dh} (${DH_NAME[s.dh] || ''})`);
  if (s.p2Enc === 'des' || s.p2Enc === '3des') out.push(`${P2_ENC_LABEL[s.p2Enc]} for ESP`);
  if (s.p2Enc === 'null') out.push('NULL encryption for ESP (cleartext payload)');
  if (!isGcm(s.p2Enc) && (s.p2Auth === 'md5' || s.p2Auth === 'sha1')) out.push(`${HASH_LABEL[s.p2Auth]} for ESP`);
  if (!s.pfs) out.push('PFS disabled');
  if (s.ikeVersion === 'ikev1' && s.mode === 'aggressive') out.push('aggressive mode (exposes a PSK hash to offline cracking)');
  if (s.psk.length < 12) out.push('pre-shared key shorter than 12 characters');
  return out;
}

const STAGE_ORDER: Stage[] = ['Reachability', 'Phase 1', 'Phase 2', 'Data path', 'Advisory'];

function buildFindings(a: Site, b: Site, I: Site, nat: boolean, float: boolean): Finding[] {
  const out: Finding[] = [];
  const both = [a, b] as const;
  const peerOf = (s: Site) => (s.key === 'A' ? b : a);
  const v2 = a.ikeVersion === 'ikev2' && b.ikeVersion === 'ikev2';
  const set = (site: SiteKey, patch: Partial<Site>) => ({ site, patch });

  for (const s of both) {
    const badFields: [keyof Site, string][] = [];
    if (!isIp(s.wanIp)) badFields.push(['wanIp', 'public IP']);
    if (!isIp(s.peerIp)) badFields.push(['peerIp', 'peer address']);
    if (s.behindNat && !isIp(s.natInsideIp)) badFields.push(['natInsideIp', 'inside address']);
    if (!isCidr(s.lan)) badFields.push(['lan', 'local network']);
    if (!isCidr(s.remoteLan)) badFields.push(['remoteLan', 'remote network']);
    if (s.snat && s.snatIp.trim() && !isIp(s.snatIp) && !isCidr(s.snatIp)) {
      badFields.push(['snatIp', 'SNAT mapped IP/subnet']);
    }
    if (s.dnat && s.dnatIp.trim() && !isIp(s.dnatIp) && !isCidr(s.dnatIp)) {
      badFields.push(['dnatIp', 'DNAT mapped IP/subnet']);
    }
    if (badFields.length)
      out.push({
        code: `ADDR:${s.key}`, severity: 'critical', stage: 'Reachability',
        title: `${s.name} has an invalid address`,
        detail: `Check the ${badFields.map((x) => x[1]).join(', ')}. Use dotted IPv4 addresses, and CIDR notation such as 10.10.0.0/24 for networks.`,
        fixes: [], fields: badFields.map(([field]) => ({ site: s.key, field })),
      });
  }

  for (const s of both) {
    const p = peerOf(s);
    if (s.peerIp.trim() !== p.wanIp.trim())
      out.push({
        code: `PEER_IP:${s.key}`, severity: 'critical', stage: 'Reachability',
        title: `${s.name} points at the wrong peer address`,
        detail: `${s.name} is configured with remote gateway ${s.peerIp || '(empty)'}, but ${p.name} is reachable at ${p.wanIp}${p.behindNat ? ', its public NAT address' : ''}.`,
        symptom: s.key === I.key
          ? `${s.name} sends IKE to an address where nothing answers: retransmissions, then a timeout. ${p.name} logs nothing at all.`
          : `${p.name}'s request arrives, but ${s.name} finds no gateway for source ${p.wanIp} and drops it. ${p.name} only sees a timeout.`,
        fixes: [{ label: `Set ${s.name} peer to ${p.wanIp}`, patches: [set(s.key, { peerIp: p.wanIp })] }],
        fields: [{ site: s.key, field: 'peerIp' }],
      });
  }

  for (const s of both)
    if (s.blockIke)
      out.push({
        code: `UDP500:${s.key}`, severity: 'critical', stage: 'Reachability',
        title: `UDP 500 is filtered upstream of ${s.name}`,
        detail: `An ISP filter, edge ACL or upstream firewall in front of ${s.name} drops IKE on UDP 500 in at least one direction.`,
        symptom: 'The initiator retransmits its first message and times out. A packet capture on the responder shows nothing arriving.',
        fixes: [{ label: `Permit UDP 500 at ${s.name}`, patches: [set(s.key, { blockIke: false })] }],
        fields: [{ site: s.key, field: 'blockIke' }],
      });

  if (a.ikeVersion !== b.ikeVersion)
    out.push({
      code: 'VERSION', severity: 'critical', stage: 'Phase 1',
      title: 'IKE version mismatch',
      detail: `${a.name} is set to ${verLabel(a)} and ${b.name} to ${verLabel(b)}. The two protocols use different exchanges and cannot interoperate.`,
      symptom: 'The responder ignores the request or logs that no gateway matches. The initiator sees only timeouts.',
      fixes: [
        { label: `Set ${b.name} to ${verLabel(a)}`, patches: [set('B', { ikeVersion: a.ikeVersion })] },
        { label: `Set ${a.name} to ${verLabel(b)}`, patches: [set('A', { ikeVersion: b.ikeVersion })] },
      ],
      fields: [{ site: 'A', field: 'ikeVersion' }, { site: 'B', field: 'ikeVersion' }],
    });

  if (a.ikeVersion === 'ikev1' && b.ikeVersion === 'ikev1' && a.mode !== b.mode)
    out.push({
      code: 'MODE', severity: 'critical', stage: 'Phase 1',
      title: 'IKEv1 exchange mode mismatch',
      detail: `${a.name} uses ${a.mode} mode and ${b.name} uses ${b.mode} mode.`,
      symptom: 'The responder rejects the first packet. Most platforms log it as “no proposal chosen” or “no matching gateway”.',
      fixes: [
        { label: 'Use main mode on both', patches: [set('A', { mode: 'main' }), set('B', { mode: 'main' })] },
      ],
      fields: [{ site: 'A', field: 'mode' }, { site: 'B', field: 'mode' }],
    });

  const d1 = p1Diff(a, b);
  if (d1.length)
    out.push({
      code: 'P1_PROPOSAL', severity: 'critical', stage: 'Phase 1',
      title: 'Phase 1 proposal mismatch',
      detail: d1.map((d) => `${d.label[0].toUpperCase()}${d.label.slice(1)}: ${a.name} ${d.x}, ${b.name} ${d.y}.`).join(' '),
      symptom: 'The responder answers the first message with NO_PROPOSAL_CHOSEN. Its debug prints the received and the configured proposals side by side.',
      fixes: [
        { label: `Copy ${a.name} proposal to ${b.name}`, patches: [set('B', { p1Enc: a.p1Enc, p1Hash: a.p1Hash, dh: a.dh })] },
        { label: `Copy ${b.name} proposal to ${a.name}`, patches: [set('A', { p1Enc: b.p1Enc, p1Hash: b.p1Hash, dh: b.dh })] },
      ],
      fields: d1.flatMap((d) => [{ site: 'A' as SiteKey, field: d.field }, { site: 'B' as SiteKey, field: d.field }]),
    });

  if (float)
    for (const s of both)
      if (s.block4500)
        out.push({
          code: `UDP4500:${s.key}`, severity: 'critical', stage: 'Phase 1',
          title: `UDP 4500 is filtered upstream of ${s.name}`,
          detail: `NAT was detected, so both peers move IKE to UDP 4500 after the first exchange. Something in front of ${s.name} only lets UDP 500 through.`,
          symptom: 'The first messages succeed, then the negotiation stalls. On Cisco gear the initiator sits in MM_KEY_EXCH / MM_WAIT_MSG6, which looks exactly like a bad pre-shared key.',
          fixes: [{ label: `Permit UDP 4500 at ${s.name}`, patches: [set(s.key, { block4500: false })] }],
          fields: [{ site: s.key, field: 'block4500' }],
        });

  if (a.psk !== b.psk)
    out.push({
      code: 'PSK', severity: 'critical', stage: 'Phase 1',
      title: 'Pre-shared key mismatch',
      detail: `The keys on ${a.name} and ${b.name} are not identical. ${pskHint(a.psk, b.psk)}`,
      symptom: v2
        ? 'IKE_SA_INIT succeeds, then IKE_AUTH is answered with AUTHENTICATION_FAILED.'
        : 'In main mode the responder cannot decrypt message 5; the initiator retransmits and times out. Logs mention a malformed payload or “probable pre-shared key mismatch”.',
      fixes: [
        { label: `Copy key from ${a.name} to ${b.name}`, patches: [set('B', { psk: a.psk })] },
        { label: `Copy key from ${b.name} to ${a.name}`, patches: [set('A', { psk: b.psk })] },
      ],
      fields: [{ site: 'A', field: 'psk' }, { site: 'B', field: 'psk' }],
    });

  for (const s of both) {
    const p = peerOf(s); // p validates the identity s presents
    if (validatesId(p) && idOf(s) !== expectedId(p))
      out.push({
        code: `ID:${s.key}`, severity: 'critical', stage: 'Phase 1',
        title: `${p.name} rejects the IKE identity of ${s.name}`,
        detail: `${s.name} identifies itself as ${idOf(s)}${!s.localId.trim() && s.behindNat ? ', the private address on its WAN interface, because it sits behind NAT' : ''}. ${p.name} expects ${expectedId(p)}${p.remoteId.trim() ? '' : `, because ${VENDORS[p.vendor].short} defaults the expected ID to the peer address`}.`,
        symptom: 'Proposals and key exchange succeed, then authentication fails even though the pre-shared keys match.',
        fixes: [
          { label: `Set ${s.name} local ID to ${expectedId(p)}`, patches: [set(s.key, { localId: expectedId(p) })] },
          { label: `Set ${p.name} remote ID to ${idOf(s)}`, patches: [set(p.key, { remoteId: idOf(s) })] },
        ],
        fields: [{ site: s.key, field: 'localId' }, { site: p.key, field: 'remoteId' }],
      });
  }

  const sa = selectors(a);
  const sb = selectors(b);
  if (sa.local !== sb.remote || sa.remote !== sb.local)
    out.push({
      code: 'TS', severity: 'critical', stage: 'Phase 2',
      title: v2 ? 'Traffic selector mismatch' : 'Proxy ID mismatch',
      detail: `${a.name} protects ${sa.local} ⇄ ${sa.remote}${sa.any ? ' (route-based, any-to-any)' : ''}. ${b.name} protects ${sb.local} ⇄ ${sb.remote}${sb.any ? ' (route-based, any-to-any)' : ''}. Each side's local selector must equal the other side's remote selector.${sa.any !== sb.any ? ' This is the usual result of pairing a route-based gateway with a policy-based one.' : ''}`,
      symptom: v2
        ? 'The IKE SA comes up, but the CHILD_SA is refused with TS_UNACCEPTABLE. Some IKEv2 stacks narrow instead; do not rely on it across vendors.'
        : 'Phase 1 completes, then quick mode is refused with INVALID-ID-INFORMATION or “no matching phase 2 / crypto map entry”.',
      fixes: selectorFixes(a, b),
      fields: ((sa.any !== sb.any ? ['tunnelType', 'specificSelectors'] : ['lan', 'remoteLan']) as (keyof Site)[]).flatMap((field) => [
        { site: 'A' as SiteKey, field }, { site: 'B' as SiteKey, field },
      ]),
    });

  const d2 = p2Diff(a, b, !v2);
  if (d2.length)
    out.push({
      code: 'P2_PROPOSAL', severity: 'critical', stage: 'Phase 2',
      title: 'Phase 2 proposal mismatch',
      detail: d2.map((d) => `${d.label[0].toUpperCase()}${d.label.slice(1)}: ${a.name} ${d.x}, ${b.name} ${d.y}.`).join(' '),
      symptom: 'The IKE SA is up but no IPsec SA appears. The responder logs NO_PROPOSAL_CHOSEN for the IPsec proposal.',
      fixes: [
        { label: `Copy ${a.name} proposal to ${b.name}`, patches: [set('B', { p2Enc: a.p2Enc, p2Auth: a.p2Auth, pfs: a.pfs })] },
        { label: `Copy ${b.name} proposal to ${a.name}`, patches: [set('A', { p2Enc: b.p2Enc, p2Auth: b.p2Auth, pfs: b.pfs })] },
      ],
      fields: d2.flatMap((d) => [{ site: 'A' as SiteKey, field: d.field }, { site: 'B' as SiteKey, field: d.field }]),
    });

  if (v2 && a.pfs !== b.pfs)
    out.push({
      code: 'PFS_REKEY', severity: 'warning', stage: 'Phase 2',
      title: 'PFS mismatch will break the tunnel at the first rekey',
      detail: `${a.name} has PFS ${a.pfs ? `group ${a.pfs}` : 'off'}, ${b.name} has PFS ${b.pfs ? `group ${b.pfs}` : 'off'}. In IKEv2 the first CHILD_SA takes its keys from the IKE SA, so no DH group is compared and the tunnel comes up. The mismatch only surfaces in CREATE_CHILD_SA.`,
      symptom: `The tunnel works, then drops roughly every ${Math.round(Math.min(a.p2Life, b.p2Life) / 60)} minutes when the IPsec SA rekeys, and recovers by renegotiating from scratch.`,
      fixes: [
        { label: `Copy PFS from ${a.name} to ${b.name}`, patches: [set('B', { pfs: a.pfs })] },
        { label: `Copy PFS from ${b.name} to ${a.name}`, patches: [set('A', { pfs: b.pfs })] },
      ],
      fields: [{ site: 'A', field: 'pfs' }, { site: 'B', field: 'pfs' }],
    });

  /* data path */
  const la = parseCidr(a.lan);
  const lb = parseCidr(b.lan);
  if (la && lb && cidrOverlap(la, lb))
    out.push({
      code: 'OVERLAP', severity: 'critical', stage: 'Data path',
      title: 'Local networks overlap',
      detail: `${a.name} uses ${la.cidr} and ${b.name} uses ${lb.cidr}. Hosts treat remote addresses as on-link and never send the traffic to their gateway.`,
      symptom: 'The tunnel is up but nothing is ever encrypted; hosts show incomplete ARP entries for the remote addresses.',
      fixes: [], fields: [{ site: 'A', field: 'lan' }, { site: 'B', field: 'lan' }],
    });

  if (nat && !float) {
    const off = both.filter((s) => !s.natT);
    out.push({
      code: 'NAT_NO_NATT', severity: 'critical', stage: 'Data path',
      title: 'NAT in the path, but NAT-T is disabled',
      detail: `${both.filter((s) => s.behindNat).map((s) => s.name).join(' and ')} sit${both.filter((s) => s.behindNat).length > 1 ? '' : 's'} behind NAT and NAT traversal is off on ${off.map((s) => s.name).join(' and ')}. IKE itself still works over UDP 500, but ESP has no ports for the NAT device to translate.`,
      symptom: 'Both phases show as up. Encapsulation counters climb on the sender, decapsulation stays at zero on the receiver.',
      fixes: [{ label: 'Enable NAT-T on both sides', patches: [set('A', { natT: true }), set('B', { natT: true })] }],
      fields: off.map((s) => ({ site: s.key, field: 'natT' as keyof Site })),
    });
  }

  for (const s of both) {
    const p = peerOf(s);
    if (s.blockEsp && !float)
      out.push({
        code: `ESP:${s.key}`, severity: 'critical', stage: 'Data path',
        title: `ESP is filtered upstream of ${s.name}`,
        detail: `IKE travels over UDP and gets through, but IP protocol 50 is dropped in front of ${s.name}. Without NAT in the path the peers have no reason to switch to UDP encapsulation.`,
        symptom: 'The tunnel is up on both sides. Each gateway counts encapsulated packets going out and zero decapsulated coming in.',
        fixes: [{ label: `Permit ESP at ${s.name}`, patches: [set(s.key, { blockEsp: false })] }],
        fields: [{ site: s.key, field: 'blockEsp' }],
      });
    if (!s.fwPolicy)
      out.push({
        code: `POLICY:${s.key}`, severity: 'critical', stage: 'Data path',
        title: `${s.name} has no security policy for VPN traffic`,
        detail: `Nothing on ${s.name} permits traffic between ${normCidr(s.lan)} and the tunnel. A negotiated tunnel does not imply permission to use it.`,
        symptom: `Packets from ${s.name}'s LAN never get encrypted, and packets arriving from ${p.name} are decrypted and then dropped.`,
        fixes: [{ label: `Add LAN ⇄ VPN policy on ${s.name}`, patches: [set(s.key, { fwPolicy: true })] }],
        fields: [{ site: s.key, field: 'fwPolicy' }],
      });
    if (s.tunnelType === 'route' && !s.route)
      out.push({
        code: `ROUTE:${s.key}`, severity: 'critical', stage: 'Data path',
        title: `${s.name} has no route into the tunnel`,
        detail: `A route-based VPN only carries what the routing table sends to the tunnel interface. ${s.name} has no route for ${normCidr(s.remoteLan)}, so that traffic follows the default route.`,
        symptom: `From ${p.name} it looks one-way: its requests arrive and are decrypted on ${s.name}, but replies never come back through the tunnel.`,
        fixes: [{ label: `Add route on ${s.name}`, patches: [set(s.key, { route: true })] }],
        fields: [{ site: s.key, field: 'route' }],
      });
    else if (s.tunnelType === 'route') {
      const peerExpectedSub = cryptoSubnet(p);
      if (isCidr(peerExpectedSub) && !ipInCidr(hostIn(peerExpectedSub), s.remoteLan)) {
        out.push({
          code: `ROUTE_NET:${s.key}`, severity: 'critical', stage: 'Data path',
          title: `${s.name} routes the wrong network into the tunnel`,
          detail: `${s.name} routes ${normCidr(s.remoteLan)} into the tunnel, but ${p.name}'s network${p.snat ? ' (post-SNAT)' : ''} is ${normCidr(peerExpectedSub)}.`,
          symptom: `Traffic for ${normCidr(peerExpectedSub)} follows the default route and never reaches the tunnel.`,
          fixes: [{ label: `Set ${s.name} remote network to ${normCidr(peerExpectedSub)}`, patches: [set(s.key, { remoteLan: normCidr(peerExpectedSub) })] }],
          fields: [{ site: s.key, field: 'remoteLan' }],
        });
      }
    }
    if (s.snat) {
      const snatSub = cryptoSubnet(s);
      const pAligned = p.tunnelType === 'route' && !p.specificSelectors
        ? ipInCidr(hostIn(snatSub), p.remoteLan)
        : normCidr(p.remoteLan) === snatSub;

      if (!pAligned) {
        out.push({
          code: `NAT_EXEMPT:${s.key}`, severity: 'critical', stage: 'Data path',
          title: `${p.name} is not configured for ${s.name}'s SNAT network`,
          detail: `${s.name} applies Source NAT (SNAT) translating ${normCidr(s.lan)} to ${snatSub}, but ${p.name} is configured with remote network ${normCidr(p.remoteLan)}.`,
          symptom: `Traffic from ${s.name} leaves with source in ${snatSub}, but ${p.name} does not route or match this subnet for the VPN tunnel.`,
          fixes: [
            { label: `Update ${p.name} remote network to ${snatSub}`, patches: [set(p.key, { remoteLan: snatSub })] },
            { label: `Turn off SNAT on ${s.name}`, patches: [set(s.key, { snat: false, natExempt: true })] },
          ],
          fields: [{ site: s.key, field: 'snat' }, { site: s.key, field: 'snatIp' }, { site: p.key, field: 'remoteLan' }],
        });
      } else {
        out.push({
          code: `SNAT_OK:${s.key}`, severity: 'info', stage: 'Advisory',
          title: `${s.name} Policy SNAT active (${snatSub})`,
          detail: `Outbound LAN traffic is Source-NATed to ${snatSub} before IPsec encapsulation. ${p.name} is aligned to accept this subnet.`,
          fixes: [],
          fields: [{ site: s.key, field: 'snat' }, { site: s.key, field: 'snatIp' }],
        });
      }
    } else if (!s.natExempt) {
      out.push({
        code: `NAT_EXEMPT:${s.key}`, severity: 'critical', stage: 'Data path',
        title: `${s.name} NATs traffic that should enter the tunnel`,
        detail: `NAT exemption is disabled for ${normCidr(s.lan)} → ${normCidr(s.remoteLan)}. Traffic is dynamically translated to ${ifaceIp(s)}, causing it to fail the IPsec selector match.`,
        symptom: `The tunnel is up but encapsulation counters on ${s.name} stay at zero for LAN traffic, or ${p.name} sees packets from an unexpected source address.`,
        fixes: [
          { label: `Add NAT exemption on ${s.name}`, patches: [set(s.key, { natExempt: true })] },
        ],
        fields: [{ site: s.key, field: 'natExempt' }],
      });
    }

    if (s.dnat) {
      if (s.dnatIp.trim() && !isIp(s.dnatIp) && !isCidr(s.dnatIp)) {
        out.push({
          code: `DNAT_FAIL:${s.key}`, severity: 'critical', stage: 'Data path',
          title: `${s.name} has an invalid DNAT IP/subnet`,
          detail: `DNAT is enabled but "${s.dnatIp}" is not a valid IPv4 address or CIDR subnet.`,
          fixes: [
            { label: `Turn off DNAT on ${s.name}`, patches: [set(s.key, { dnat: false })] },
          ],
          fields: [{ site: s.key, field: 'dnat' }, { site: s.key, field: 'dnatIp' }],
        });
      } else {
        out.push({
          code: `DNAT_OK:${s.key}`, severity: 'info', stage: 'Advisory',
          title: `${s.name} Inbound DNAT active`,
          detail: `Inbound traffic arriving from the VPN is Destination-NATed to ${s.dnatIp.trim() || 'internal host'}.`,
          fixes: [],
          fields: [{ site: s.key, field: 'dnat' }, { site: s.key, field: 'dnatIp' }],
        });
      }
    }
  }

  /* advisories */
  if (a.p1Life !== b.p1Life || a.p2Life !== b.p2Life) {
    const which = [a.p1Life !== b.p1Life ? `phase 1 (${a.p1Life} s and ${b.p1Life} s)` : '', a.p2Life !== b.p2Life ? `phase 2 (${a.p2Life} s and ${b.p2Life} s)` : ''].filter(Boolean).join(' and ');
    out.push({
      code: 'LIFETIME', severity: 'info', stage: 'Advisory',
      title: 'Lifetimes differ',
      detail: `Lifetimes differ for ${which}. IKEv1 peers usually settle on the lower value; IKEv2 does not negotiate lifetimes at all and each side rekeys on its own timer. Either way it works, but matching values make rekey behaviour predictable.`,
      fixes: [{
        label: 'Use the lower value on both',
        patches: (['A', 'B'] as SiteKey[]).map((k) => set(k, { p1Life: Math.min(a.p1Life, b.p1Life), p2Life: Math.min(a.p2Life, b.p2Life) })),
      }],
      fields: (['A', 'B'] as SiteKey[]).flatMap((k) => [
        ...(a.p1Life !== b.p1Life ? [{ site: k, field: 'p1Life' as keyof Site }] : []),
        ...(a.p2Life !== b.p2Life ? [{ site: k, field: 'p2Life' as keyof Site }] : []),
      ]),
    });
  }

  if (a.dpd !== b.dpd) {
    const off = a.dpd ? b : a;
    out.push({
      code: 'DPD', severity: 'info', stage: 'Advisory',
      title: `Dead peer detection is off on ${off.name}`,
      detail: `${off.name} will not notice when its peer disappears and can keep sending into stale SAs until they expire.`,
      fixes: [{ label: `Enable DPD on ${off.name}`, patches: [set(off.key, { dpd: true })] }],
      fields: [{ site: off.key, field: 'dpd' }],
    });
  }

  for (const s of both) {
    const notes = platformNotes(s);
    if (notes.length)
      out.push({
        code: `PLATFORM:${s.key}`, severity: 'warning', stage: 'Advisory',
        title: `${VENDORS[s.vendor].short} limitation on ${s.name}`,
        detail: notes.join(' '), fixes: [], fields: [],
      });
    const weak = weakNotes(s);
    if (weak.length)
      out.push({
        code: `WEAK:${s.key}`, severity: 'info', stage: 'Advisory',
        title: `Weak settings on ${s.name}`,
        detail: `${weak.join(', ')}. These still interoperate, but current guidance is AES-256 or AES-GCM, SHA-256 or better, and DH group 14, 19 or higher.`,
        fixes: [], fields: [],
      });
  }

  const sev: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
  return out
    .map((f, i) => ({ f, i }))
    .sort((x, y) => STAGE_ORDER.indexOf(x.f.stage) - STAGE_ORDER.indexOf(y.f.stage) || sev[x.f.severity] - sev[y.f.severity] || x.i - y.i)
    .map((x) => x.f);
}
