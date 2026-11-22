import { parseCidr, normCidr } from '../net';
import { selectors } from '../simulate';
import { ifaceIp, idType, tok, type Site } from '../types';
import { tunnelName } from '../vendors';

/** Everything a config generator needs, derived from what this site has configured. */
export interface Gen {
  s: Site;
  o: Site; // the other site — used for naming only
  T: string; // uppercase peer token
  t: string; // lowercase peer token
  tn: string; // tunnel name
  local: string; // WAN interface address
  peer: string;
  v2: boolean;
  policy: boolean; // policy-based
  specific: boolean; // negotiates specific selectors
  lan: { cidr: string; net: string; mask: string; wild: string };
  rlan: { cidr: string; net: string; mask: string; wild: string };
  localId: string;
  remoteId: string;
  tunIp: string;
  tunPeer: string;
  title: string;
}

function net(text: string) {
  const c = parseCidr(text);
  return c
    ? { cidr: c.cidr, net: c.network, mask: c.mask, wild: c.wildcard }
    : { cidr: normCidr(text) || '<network>', net: '<network>', mask: '<mask>', wild: '<wildcard>' };
}

export function mkGen(s: Site, o: Site): Gen {
  const sel = selectors(s);
  const v2 = s.ikeVersion === 'ikev2';
  const policy = s.tunnelType === 'policy';
  return {
    s, o,
    T: tok(o.name),
    t: tok(o.name).toLowerCase(),
    tn: tunnelName(o),
    local: ifaceIp(s) || '<wan-ip>',
    peer: s.peerIp.trim() || '<peer-ip>',
    v2, policy,
    specific: !sel.any,
    lan: net(s.lan),
    rlan: net(s.remoteLan),
    localId: s.localId.trim(),
    remoteId: s.remoteId.trim(),
    tunIp: s.key === 'A' ? '169.254.100.1' : '169.254.100.2',
    tunPeer: s.key === 'A' ? '169.254.100.2' : '169.254.100.1',
    title: `${s.name}: ${v2 ? 'IKEv2' : `IKEv1 ${s.mode} mode`}, ${policy ? 'policy-based' : 'route-based'} VPN to ${o.name} (${s.peerIp || 'no peer'})`,
  };
}

export { idType };

export const FAULT = 'FAULT:';
