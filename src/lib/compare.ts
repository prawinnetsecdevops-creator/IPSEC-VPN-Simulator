import { expectedId, selectors, validatesId } from './simulate';
import { HASH_LABEL, P1_ENC_LABEL, P2_ENC_LABEL, dhLabel, idOf, isGcm, type Site } from './types';

export type RowStatus = 'match' | 'mismatch' | 'warn' | 'na';

export interface Row {
  group: 'Reachability' | 'Phase 1 · IKE' | 'Phase 2 · IPsec';
  label: string;
  a: string;
  b: string;
  status: RowStatus;
  note?: string;
}

/** Pre-flight comparison of the two configurations, independent of who initiates. */
export function compare(a: Site, b: Site): Row[] {
  const eq = (x: unknown, y: unknown): RowStatus => (x === y ? 'match' : 'mismatch');
  const v2 = a.ikeVersion === 'ikev2' && b.ikeVersion === 'ikev2';
  const bothV1 = a.ikeVersion === 'ikev1' && b.ikeVersion === 'ikev1';
  const nat = a.behindNat || b.behindNat;
  const sa = selectors(a);
  const sb = selectors(b);
  const ver = (s: Site) => (s.ikeVersion === 'ikev2' ? 'IKEv2' : 'IKEv1');
  const idRow = (from: Site, to: Site): Row => ({
    group: 'Phase 1 · IKE',
    label: `Identity of ${from.name}`,
    a: from.key === 'A' ? `sends ${idOf(from)}` : validatesId(to) ? `expects ${expectedId(to)}` : 'accepts any',
    b: from.key === 'B' ? `sends ${idOf(from)}` : validatesId(to) ? `expects ${expectedId(to)}` : 'accepts any',
    status: !validatesId(to) ? 'match' : eq(idOf(from), expectedId(to)),
  });

  return [
    { group: 'Reachability', label: `${a.name} dials`, a: `peer ${a.peerIp || '—'}`, b: `public ${b.wanIp || '—'}`, status: eq(a.peerIp.trim(), b.wanIp.trim()) },
    { group: 'Reachability', label: `${b.name} dials`, a: `public ${a.wanIp || '—'}`, b: `peer ${b.peerIp || '—'}`, status: eq(a.wanIp.trim(), b.peerIp.trim()) },
    {
      group: 'Reachability', label: 'NAT traversal',
      a: `${a.natT ? 'on' : 'off'}${a.behindNat ? ' · behind NAT' : ''}`,
      b: `${b.natT ? 'on' : 'off'}${b.behindNat ? ' · behind NAT' : ''}`,
      status: nat && !(a.natT && b.natT) ? 'mismatch' : a.natT !== b.natT ? 'warn' : 'match',
      note: nat && !(a.natT && b.natT) ? 'Required on both sides when NAT is in the path.' : undefined,
    },
    {
      group: 'Reachability', label: 'Protected traffic SNAT',
      a: a.snat ? `Enabled${a.snatIp.trim() ? ` (${a.snatIp.trim()})` : ''}` : 'Off',
      b: b.snat ? `Enabled${b.snatIp.trim() ? ` (${b.snatIp.trim()})` : ''}` : 'Off',
      status: !a.snat && !b.snat ? 'match' : 'mismatch',
      note: a.snat || b.snat ? 'SNAT on protected traffic alters source IP out of the IPsec crypto domain.' : undefined,
    },
    {
      group: 'Reachability', label: 'Protected traffic DNAT',
      a: a.dnat ? `Enabled${a.dnatIp.trim() ? ` (${a.dnatIp.trim()})` : ''}` : 'Off',
      b: b.dnat ? `Enabled${b.dnatIp.trim() ? ` (${b.dnatIp.trim()})` : ''}` : 'Off',
      status: !a.dnat && !b.dnat ? 'match' : 'mismatch',
      note: a.dnat || b.dnat ? 'DNAT on protected traffic alters destination IP out of the IPsec crypto domain.' : undefined,
    },

    { group: 'Phase 1 · IKE', label: 'IKE version', a: ver(a), b: ver(b), status: eq(a.ikeVersion, b.ikeVersion) },
    {
      group: 'Phase 1 · IKE', label: 'Exchange mode',
      a: a.ikeVersion === 'ikev1' ? a.mode : 'n/a', b: b.ikeVersion === 'ikev1' ? b.mode : 'n/a',
      status: bothV1 ? eq(a.mode, b.mode) : 'na',
    },
    { group: 'Phase 1 · IKE', label: 'Encryption', a: P1_ENC_LABEL[a.p1Enc], b: P1_ENC_LABEL[b.p1Enc], status: eq(a.p1Enc, b.p1Enc) },
    { group: 'Phase 1 · IKE', label: v2 ? 'Integrity / PRF' : 'Hash', a: HASH_LABEL[a.p1Hash], b: HASH_LABEL[b.p1Hash], status: eq(a.p1Hash, b.p1Hash) },
    { group: 'Phase 1 · IKE', label: 'DH group', a: dhLabel(a.dh), b: dhLabel(b.dh), status: eq(a.dh, b.dh) },
    { group: 'Phase 1 · IKE', label: 'Pre-shared key', a: a.psk || '—', b: b.psk || '—', status: eq(a.psk, b.psk) },
    idRow(a, b),
    idRow(b, a),
    {
      group: 'Phase 1 · IKE', label: 'Lifetime', a: `${a.p1Life} s`, b: `${b.p1Life} s`,
      status: a.p1Life === b.p1Life ? 'match' : 'warn', note: a.p1Life === b.p1Life ? undefined : 'Not fatal; rekey timing becomes uneven.',
    },

    { group: 'Phase 2 · IPsec', label: `${a.name} local = ${b.name} remote`, a: sa.local, b: sb.remote, status: eq(sa.local, sb.remote) },
    { group: 'Phase 2 · IPsec', label: `${a.name} remote = ${b.name} local`, a: sa.remote, b: sb.local, status: eq(sa.remote, sb.local) },
    { group: 'Phase 2 · IPsec', label: 'Encryption', a: P2_ENC_LABEL[a.p2Enc], b: P2_ENC_LABEL[b.p2Enc], status: eq(a.p2Enc, b.p2Enc) },
    {
      group: 'Phase 2 · IPsec', label: 'Authentication',
      a: isGcm(a.p2Enc) ? 'built into GCM' : HASH_LABEL[a.p2Auth], b: isGcm(b.p2Enc) ? 'built into GCM' : HASH_LABEL[b.p2Auth],
      status: isGcm(a.p2Enc) || isGcm(b.p2Enc) ? (isGcm(a.p2Enc) && isGcm(b.p2Enc) ? 'na' : 'mismatch') : eq(a.p2Auth, b.p2Auth),
    },
    {
      group: 'Phase 2 · IPsec', label: 'PFS', a: dhLabel(a.pfs), b: dhLabel(b.pfs),
      status: a.pfs === b.pfs ? 'match' : v2 ? 'warn' : 'mismatch',
      note: a.pfs !== b.pfs && v2 ? 'IKEv2 only compares this at rekey: the tunnel comes up, then drops.' : undefined,
    },
    {
      group: 'Phase 2 · IPsec', label: 'Lifetime', a: `${a.p2Life} s`, b: `${b.p2Life} s`,
      status: a.p2Life === b.p2Life ? 'match' : 'warn', note: a.p2Life === b.p2Life ? undefined : 'Not fatal; rekey timing becomes uneven.',
    },
  ];
}
