import type { Site, SiteKey, Sites } from './types';
import { coerce } from './vendors';

const common = {
  behindNat: false,
  snat: false,
  snatIp: '',
  dnat: false,
  dnatIp: '',
  ikeVersion: 'ikev2',
  mode: 'main',
  p1Enc: 'aes256',
  p1Hash: 'sha256',
  dh: 14,
  p1Life: 86400,
  psk: 'Blue-Harbor-Tunnel-2025',
  localId: '',
  remoteId: '',
  natT: true,
  dpd: true,
  tunnelType: 'route',
  specificSelectors: false,
  p2Enc: 'aes256',
  p2Auth: 'sha256',
  pfs: 14,
  p2Life: 3600,
  natExempt: true,
  fwPolicy: true,
  route: true,
  blockIke: false,
  block4500: false,
  blockEsp: false,
} as const;

export function baseSites(): Sites {
  return {
    A: {
      ...common, key: 'A', name: 'HQ', vendor: 'fortigate',
      wanIp: '203.0.113.10', natInsideIp: '192.168.100.2', peerIp: '198.51.100.20',
      localId: '203.0.113.10', remoteId: '198.51.100.20',
      lan: '10.10.0.0/24', remoteLan: '10.20.0.0/24',
    },
    B: {
      ...common, key: 'B', name: 'Branch', vendor: 'cisco-ios',
      wanIp: '198.51.100.20', natInsideIp: '192.168.200.2', peerIp: '203.0.113.10',
      localId: '198.51.100.20', remoteId: '203.0.113.10',
      lan: '10.20.0.0/24', remoteLan: '10.10.0.0/24',
    },
  };
}

export interface Scenario {
  id: string;
  group: 'Baseline' | 'Tunnel down' | 'Phase 2' | 'Tunnel up, traffic failing';
  title: string;
  ticket: string;
  build: () => { sites: Sites; initiator: SiteKey };
}

function mk(a: Partial<Site>, b: Partial<Site>, initiator: SiteKey = 'A') {
  const base = baseSites();
  return { sites: { A: coerce({ ...base.A, ...a }), B: coerce({ ...base.B, ...b }) }, initiator };
}

const v1sha1 = { ikeVersion: 'ikev1', p1Hash: 'sha1', p2Auth: 'sha1' } as const;

export const SCENARIOS: Scenario[] = [
  {
    id: 'baseline',
    group: 'Baseline',
    title: 'Healthy tunnel',
    ticket: 'New tunnel between HQ and the branch. Bring it up and confirm traffic passes in both directions.',
    build: () => mk({}, {}),
  },
  {
    id: 'azure-branch',
    group: 'Baseline',
    title: 'Azure VNet to branch',
    ticket: 'Connect the Azure VNet to the branch office through an Azure VPN Gateway. Bring it up and confirm traffic passes in both directions.',
    build: () =>
      mk(
        { name: 'Azure VNet', vendor: 'azure', wanIp: '203.0.113.50', peerIp: '198.51.100.20', localId: '203.0.113.50', remoteId: '198.51.100.20', lan: '10.30.0.0/16', remoteLan: '10.20.0.0/24' },
        { vendor: 'fortigate', wanIp: '198.51.100.20', peerIp: '203.0.113.50', localId: '198.51.100.20', remoteId: '203.0.113.50', lan: '10.20.0.0/24', remoteLan: '10.30.0.0/16' },
      ),
  },
  {
    id: 'hardening',
    group: 'Tunnel down',
    title: 'Down after a hardening change',
    ticket: 'The security team hardened the HQ firewall last night. The branch tunnel has been down ever since.',
    build: () => mk({ vendor: 'fortigate', dh: 19, p1Hash: 'sha384' }, { vendor: 'juniper-srx' }),
  },
  {
    id: 'key-rotation',
    group: 'Tunnel down',
    title: 'Down after a key rotation',
    ticket: 'The pre-shared key was rotated on both ends during the change window. The tunnel has not come back.',
    build: () =>
      mk(
        { vendor: 'cisco-asa', tunnelType: 'policy', ...v1sha1, psk: 'Rotate-2025-Q1-k7Xp' },
        { vendor: 'cisco-ios', tunnelType: 'policy', ...v1sha1, psk: 'Rotate-2025-Q1-k7XP' },
      ),
  },
  {
    id: 'isp-migration',
    group: 'Tunnel down',
    title: 'Down after an ISP migration',
    ticket: 'The branch moved to a new ISP circuit this morning. HQ shows the tunnel down; the branch says its side is configured.',
    build: () => mk({ vendor: 'paloalto' }, { vendor: 'fortigate', wanIp: '192.0.2.77', localId: '192.0.2.77' }),
  },
  {
    id: 'new-router',
    group: 'Tunnel down',
    title: 'Never came up after a hardware swap',
    ticket: 'The branch replaced its firewall with a MikroTik router. Settings were “copied over”, but the tunnel never establishes.',
    build: () => mk({ vendor: 'cisco-asa', tunnelType: 'policy', ...v1sha1 }, { vendor: 'mikrotik', p1Hash: 'sha1', p2Auth: 'sha1' }, 'B'),
  },
  {
    id: 'nat-stall',
    group: 'Tunnel down',
    title: 'Stalls halfway, branch behind NAT',
    ticket: 'The branch is a Linux gateway behind the building’s shared router. IKE starts, then stalls at the same point every time.',
    build: () => mk({ vendor: 'fortigate' }, { vendor: 'strongswan', behindNat: true, localId: '198.51.100.20', block4500: true }, 'B'),
  },
  {
    id: 'nat-identity',
    group: 'Tunnel down',
    title: 'Authentication fails, keys match',
    ticket: 'The branch router was moved behind a carrier NAT. The keys were checked twice and match, yet authentication fails.',
    build: () => mk({ vendor: 'strongswan', remoteId: '198.51.100.20' }, { vendor: 'cisco-ios', behindNat: true, localId: '192.168.200.2' }, 'B'),
  },
  {
    id: 'proxy-id',
    group: 'Phase 2',
    title: 'Phase 1 green, phase 2 never forms',
    ticket: 'Palo Alto at HQ, Cisco ASA at the partner site. Phase 1 is green on both, but no IPsec SA ever appears.',
    build: () => mk({ vendor: 'paloalto' }, { vendor: 'cisco-asa', tunnelType: 'policy' }),
  },
  {
    id: 'p2-proposal',
    group: 'Phase 2',
    title: '“No proposal chosen” in quick mode',
    ticket: 'Phase 1 is up. Phase 2 fails with “no proposal chosen” although encryption and hash were double-checked.',
    build: () => mk({ vendor: 'fortigate', tunnelType: 'policy', ikeVersion: 'ikev1' }, { vendor: 'mikrotik', ikeVersion: 'ikev1', pfs: 5 }),
  },
  {
    id: 'hourly-drop',
    group: 'Phase 2',
    title: 'Works, but drops every hour',
    ticket: 'The tunnel works, but users report a short outage roughly once an hour, always at a similar interval.',
    build: () => mk({ vendor: 'paloalto' }, { vendor: 'juniper-srx', pfs: 19 }),
  },
  {
    id: 'nat-exempt',
    group: 'Tunnel up, traffic failing',
    title: 'Tunnel up, HQ cannot reach the branch',
    ticket: 'The tunnel shows as up on both firewalls, but nobody at HQ can reach the branch file server.',
    build: () => mk({ vendor: 'cisco-asa', tunnelType: 'policy', natExempt: false, snat: true }, { vendor: 'fortigate', specificSelectors: true }),
  },
  {
    id: 'esp-filter',
    group: 'Tunnel up, traffic failing',
    title: 'Packets out, nothing in',
    ticket: 'Both sides report the tunnel as up. Each side counts packets going out and none coming in.',
    build: () => mk({ vendor: 'juniper-srx' }, { vendor: 'paloalto', blockEsp: true }),
  },
  {
    id: 'missing-route',
    group: 'Tunnel up, traffic failing',
    title: 'Requests arrive, replies vanish',
    ticket: 'HQ cannot reach the branch. A capture on the branch router shows HQ’s packets arriving through the tunnel.',
    build: () => mk({ vendor: 'fortigate' }, { vendor: 'cisco-ios', route: false }),
  },
];

export const FAULT_SCENARIOS = SCENARIOS.filter((s) => s.id !== 'baseline');
