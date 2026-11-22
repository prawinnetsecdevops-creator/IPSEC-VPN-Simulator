import { hostIn, parseCidr } from './net';
import { ifaceIp, tok, type IkeVersion, type Site, type TunnelType, type VendorId } from './types';

import type { Hash, P1Enc, P2Enc } from './types';

export interface VendorCapabilities {
  p1Enc: (v2: boolean) => P1Enc[];
  p1Hash: (v2: boolean) => Hash[];
  p2Enc: P2Enc[];
  p2Auth: Hash[];
  dh: number[];
}

export interface VendorInfo {
  id: VendorId;
  name: string;
  short: string;
  platform: string;
  /** Tunnel models the platform can build natively. */
  tunnelTypes: TunnelType[];
  /** Can a route-based tunnel carry narrowed selectors / proxy-IDs? */
  routeSpecific: boolean;
  /** Does it validate the peer IKE ID against the peer address when no remote ID is configured? */
  strictId: (v: IkeVersion) => boolean;
  file: string;
  capabilities: VendorCapabilities;
}

export const VENDORS: Record<VendorId, VendorInfo> = {
  'cisco-ios': {
    id: 'cisco-ios',
    name: 'Cisco IOS-XE',
    short: 'IOS-XE',
    platform: 'ISR / ASR / Catalyst 8000',
    tunnelTypes: ['route', 'policy'],
    routeSpecific: true,
    strictId: (v) => v === 'ikev2',
    file: 'ios-xe.txt',
    capabilities: {
      p1Enc: (v2) => v2 ? ['aes256', 'aes192', 'aes128', 'aes256gcm', 'aes128gcm', 'chacha20poly1305', '3des', 'des'] : ['aes256', 'aes192', 'aes128', '3des', 'des'],
      p1Hash: (v2) => v2 ? ['sha256', 'sha384', 'sha512', 'sha1', 'md5', 'aesxcbc'] : ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes192gcm', 'aes128gcm', 'chacha20poly1305', 'aes256', 'aes192', 'aes128', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha384', 'sha512', 'sha1', 'md5', 'aesxcbc'],
      dh: [14, 19, 20, 21, 24, 15, 16, 5, 2, 1],
    },
  },
  'cisco-asa': {
    id: 'cisco-asa',
    name: 'Cisco ASA',
    short: 'ASA',
    platform: 'ASA 9.x / Firepower (ASA image)',
    tunnelTypes: ['route', 'policy'],
    routeSpecific: false,
    strictId: () => false,
    file: 'asa.txt',
    capabilities: {
      p1Enc: (v2) => v2 ? ['aes256', 'aes192', 'aes128', 'aes256gcm', 'aes128gcm', '3des', 'des'] : ['aes256', 'aes192', 'aes128', '3des', 'des'],
      p1Hash: (v2) => v2 ? ['sha256', 'sha384', 'sha512', 'sha1', 'md5', 'aesxcbc'] : ['sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes192gcm', 'aes128gcm', 'aes256', 'aes192', 'aes128', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha384', 'sha512', 'sha1', 'md5', 'aesxcbc'],
      dh: [14, 19, 20, 21, 24, 5, 2, 1],
    },
  },
  fortigate: {
    id: 'fortigate',
    name: 'Fortinet FortiGate',
    short: 'FortiGate',
    platform: 'FortiOS 7.x',
    tunnelTypes: ['route', 'policy'],
    routeSpecific: true,
    strictId: () => false,
    file: 'fortigate.conf',
    capabilities: {
      p1Enc: () => ['aes256', 'aes192', 'aes128', 'aes256gcm', 'aes128gcm', 'chacha20poly1305', '3des', 'des'],
      p1Hash: () => ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes128gcm', 'chacha20poly1305', 'aes256', 'aes192', 'aes128', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      dh: [14, 19, 20, 21, 31, 15, 16, 18, 5, 2, 1],
    },
  },
  paloalto: {
    id: 'paloalto',
    name: 'Palo Alto PAN-OS',
    short: 'PAN-OS',
    platform: 'PA-Series / VM-Series',
    tunnelTypes: ['route'],
    routeSpecific: true,
    strictId: () => false,
    file: 'panos-set.txt',
    capabilities: {
      p1Enc: () => ['aes256', 'aes192', 'aes128', 'aes256gcm', 'aes128gcm', '3des', 'des'],
      p1Hash: () => ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes128gcm', 'aes256', 'aes192', 'aes128', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      dh: [14, 19, 20, 5, 2, 1],
    },
  },
  'juniper-srx': {
    id: 'juniper-srx',
    name: 'Juniper SRX',
    short: 'SRX',
    platform: 'Junos OS',
    tunnelTypes: ['route', 'policy'],
    routeSpecific: true,
    strictId: () => true,
    file: 'junos-set.txt',
    capabilities: {
      p1Enc: () => ['aes256', 'aes192', 'aes128', 'aes256gcm', 'aes128gcm', '3des', 'des'],
      p1Hash: () => ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes128gcm', 'aes256', 'aes192', 'aes128', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha384', 'sha512', 'sha1', 'md5'],
      dh: [14, 19, 20, 21, 24, 15, 16, 5, 2, 1],
    },
  },
  mikrotik: {
    id: 'mikrotik',
    name: 'MikroTik RouterOS',
    short: 'RouterOS',
    platform: 'RouterOS 7',
    tunnelTypes: ['policy'],
    routeSpecific: false,
    strictId: () => false,
    file: 'routeros.rsc',
    capabilities: {
      p1Enc: () => ['aes256', 'aes192', 'aes128', 'chacha20poly1305', 'camellia256', 'camellia192', 'camellia128', 'blowfish', '3des', 'des'],
      p1Hash: () => ['sha256', 'sha512', 'sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes128gcm', 'chacha20poly1305', 'aes256', 'aes192', 'aes128', 'camellia256', 'camellia192', 'camellia128', 'blowfish', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha512', 'sha1', 'md5'],
      dh: [14, 19, 20, 21, 31, 15, 16, 18, 5, 2, 1],
    },
  },
  strongswan: {
    id: 'strongswan',
    name: 'strongSwan (Linux)',
    short: 'strongSwan',
    platform: 'swanctl / charon 5.9+',
    tunnelTypes: ['route', 'policy'],
    routeSpecific: true,
    strictId: () => true,
    file: 'swanctl.conf',
    capabilities: {
      p1Enc: () => ['aes256gcm', 'aes128gcm', 'chacha20poly1305', 'aes256', 'aes192', 'aes128', 'camellia256', 'camellia192', 'camellia128', 'blowfish', '3des', 'des'],
      p1Hash: () => ['sha256', 'sha384', 'sha512', 'sha1', 'md5', 'aesxcbc'],
      p2Enc: ['aes256gcm', 'aes192gcm', 'aes128gcm', 'chacha20poly1305', 'aes256', 'aes192', 'aes128', 'camellia256', 'camellia192', 'camellia128', 'blowfish', '3des', 'des', 'null'],
      p2Auth: ['sha256', 'sha384', 'sha512', 'sha1', 'md5', 'aesxcbc'],
      dh: [14, 19, 20, 21, 24, 31, 15, 16, 18, 5, 2, 1],
    },
  },
  azure: {
    id: 'azure',
    name: 'Microsoft Azure VPN Gateway',
    short: 'Azure',
    platform: 'Azure Virtual Network Gateway · route-based VpnGw SKUs',
    tunnelTypes: ['route'],
    routeSpecific: true,
    strictId: () => true,
    file: 'azure-cli.sh',
    capabilities: {
      p1Enc: () => ['aes256gcm', 'aes128gcm', 'aes256', 'aes192', 'aes128', '3des', 'des'],
      p1Hash: () => ['sha384', 'sha256', 'sha1', 'md5'],
      p2Enc: ['aes256gcm', 'aes192gcm', 'aes128gcm', 'aes256', 'aes192', 'aes128', '3des', 'des'],
      p2Auth: ['sha256', 'sha1', 'md5'],
      dh: [14, 19, 20, 24, 2, 1],
    },
  },
};

export function getVendorP1Enc(vendor: VendorId, v2: boolean): P1Enc[] {
  return VENDORS[vendor].capabilities.p1Enc(v2);
}

export function getVendorP1Hash(vendor: VendorId, v2: boolean): Hash[] {
  return VENDORS[vendor].capabilities.p1Hash(v2);
}

export function getVendorP2Enc(vendor: VendorId): P2Enc[] {
  return VENDORS[vendor].capabilities.p2Enc;
}

export function getVendorP2Auth(vendor: VendorId): Hash[] {
  return VENDORS[vendor].capabilities.p2Auth;
}

export function getVendorDh(vendor: VendorId): number[] {
  return VENDORS[vendor].capabilities.dh;
}

export const VENDOR_LIST = Object.values(VENDORS);

/** Applies platform constraints after a vendor or tunnel-type change. */
export function coerce(s: Site): Site {
  const v = VENDORS[s.vendor];
  let next = s;
  if (!v.tunnelTypes.includes(next.tunnelType)) next = { ...next, tunnelType: v.tunnelTypes[0] };
  if (next.tunnelType === 'route' && next.specificSelectors && !v.routeSpecific)
    next = { ...next, specificSelectors: false };

  const v2 = next.ikeVersion === 'ikev2';
  const supP1Enc = v.capabilities.p1Enc(v2);
  if (!supP1Enc.includes(next.p1Enc)) {
    next = { ...next, p1Enc: supP1Enc.includes('aes256') ? 'aes256' : supP1Enc[0] };
  }
  const supP1Hash = v.capabilities.p1Hash(v2);
  if (!supP1Hash.includes(next.p1Hash)) {
    next = { ...next, p1Hash: supP1Hash.includes('sha256') ? 'sha256' : supP1Hash[0] };
  }
  const supP2Enc = v.capabilities.p2Enc;
  if (!supP2Enc.includes(next.p2Enc)) {
    next = { ...next, p2Enc: supP2Enc.includes('aes256') ? 'aes256' : supP2Enc[0] };
  }
  const supP2Auth = v.capabilities.p2Auth;
  if (!supP2Auth.includes(next.p2Auth)) {
    next = { ...next, p2Auth: supP2Auth.includes('sha256') ? 'sha256' : supP2Auth[0] };
  }
  const supDh = v.capabilities.dh;
  if (!supDh.includes(next.dh)) {
    next = { ...next, dh: supDh.includes(14) ? 14 : supDh[0] };
  }
  if (next.pfs !== 0 && !supDh.includes(next.pfs)) {
    next = { ...next, pfs: supDh.includes(14) ? 14 : supDh[0] };
  }

  return next;
}

export const tunnelName = (peer: Site) => `to-${tok(peer.name)}`;

export type CmdStage = 'ike' | 'ipsec' | 'traffic' | 'debug';
export interface Cmd {
  stage: CmdStage;
  cmd: string;
  why: string;
}

/** Verification and debug commands an engineer would run on this gateway. */
export function verifyCommands(s: Site, o: Site): Cmd[] {
  const peer = s.peerIp;
  const local = ifaceIp(s);
  const v2 = s.ikeVersion === 'ikev2';
  const T = tok(o.name);
  const tn = tunnelName(o);
  const lhost = hostIn(s.lan);
  const rhost = hostIn(s.remoteLan);
  const rnet = parseCidr(s.remoteLan)?.network ?? '<remote-net>';

  switch (s.vendor) {
    case 'cisco-ios':
      return [
        v2
          ? { stage: 'ike', cmd: 'show crypto ikev2 sa detailed', why: 'READY means the IKE SA is up; lists the negotiated encryption, integrity and DH group.' }
          : { stage: 'ike', cmd: 'show crypto isakmp sa', why: 'QM_IDLE is healthy. MM_NO_STATE points at reachability or proposals, MM_KEY_EXCH at the pre-shared key or UDP 4500.' },
        { stage: 'ipsec', cmd: `show crypto ipsec sa peer ${peer}`, why: 'Check local/remote ident (the selectors) and the #pkts encaps / decaps counters.' },
        { stage: 'traffic', cmd: `show ip route ${rnet}`, why: 'Confirms the remote LAN is routed toward the tunnel and not the default route.' },
        { stage: 'traffic', cmd: `show ip nat translations | include ${lhost}`, why: 'A translation here means VPN traffic is being NATed before it reaches the crypto engine.' },
        { stage: 'debug', cmd: `debug crypto condition peer ipv4 ${peer}`, why: 'Scopes the debugs to this one peer.' },
        { stage: 'debug', cmd: v2 ? 'debug crypto ikev2' : 'debug crypto isakmp', why: 'Shows each exchange and the exact reason a proposal or authentication was rejected.' },
        { stage: 'debug', cmd: 'debug crypto ipsec', why: 'Explains transform-set and proxy identity rejections in phase 2.' },
      ];
    case 'cisco-asa':
      return [
        { stage: 'ike', cmd: v2 ? 'show crypto ikev2 sa detail' : 'show crypto ikev1 sa detail', why: v2 ? 'READY is healthy. No entry at all means IKE never got an answer.' : 'MM_ACTIVE is healthy. MM_WAIT_MSG2 = no reply or proposals, MM_WAIT_MSG6 = pre-shared key or UDP 4500.' },
        { stage: 'ipsec', cmd: `show crypto ipsec sa peer ${peer}`, why: 'Shows the negotiated proxies plus #pkts encaps / decaps for one-way traffic problems.' },
        { stage: 'traffic', cmd: `packet-tracer input inside icmp ${lhost} 8 0 ${rhost} detailed`, why: 'Walks the packet through NAT, ACL and VPN phases and names the phase that drops it.' },
        { stage: 'traffic', cmd: 'show nat detail', why: 'The identity (no-NAT) rule for the VPN must sit above the dynamic PAT rule.' },
        { stage: 'debug', cmd: `debug crypto condition peer ${peer}`, why: 'Scopes the debugs to this one peer.' },
        { stage: 'debug', cmd: v2 ? 'debug crypto ikev2 protocol 127' : 'debug crypto ikev1 127', why: 'Full IKE negotiation trace including the reason for a rejection.' },
      ];
    case 'fortigate':
      return [
        { stage: 'ike', cmd: `diagnose vpn ike gateway list name ${tn}`, why: 'Shows whether the IKE SA is established, its direction and NAT-T state.' },
        { stage: 'ipsec', cmd: `diagnose vpn tunnel list name ${tn}`, why: 'Lists selectors, SPIs and the enc / dec packet counters for each phase 2.' },
        { stage: 'traffic', cmd: `diagnose sniffer packet any 'host ${peer} and (udp port 500 or udp port 4500 or esp)' 4 0 l`, why: 'Proves whether IKE and ESP are actually leaving and arriving on the wire.' },
        { stage: 'traffic', cmd: `diagnose debug flow filter addr ${rhost}\ndiagnose debug flow trace start 10`, why: 'Shows the policy, route and NAT decision made for a packet to the remote LAN.' },
        { stage: 'debug', cmd: `diagnose vpn ike log filter rem-addr4 ${peer}\ndiagnose debug application ike -1\ndiagnose debug enable`, why: 'Prints incoming vs. configured proposals side by side — the fastest way to spot a mismatch.' },
      ];
    case 'paloalto':
      return [
        { stage: 'ike', cmd: `show vpn ike-sa gateway GW-${T}`, why: 'An entry with an established time means phase 1 is up.' },
        { stage: 'ike', cmd: `test vpn ike-sa gateway GW-${T}`, why: 'Forces this firewall to initiate so you get fresh log entries.' },
        { stage: 'ipsec', cmd: `show vpn ipsec-sa tunnel IPSEC-${T}`, why: 'Lists SPIs and the proxy-ID each SA was built for.' },
        { stage: 'ipsec', cmd: `show vpn flow name IPSEC-${T}`, why: 'Encap / decap packet counters and error counters for the tunnel.' },
        { stage: 'traffic', cmd: `test routing fib-lookup virtual-router default ip ${rhost}`, why: 'Confirms the remote LAN resolves to the tunnel interface.' },
        { stage: 'traffic', cmd: `show session all filter destination ${rhost}`, why: 'Shows the matched security rule, zones and any NAT applied.' },
        { stage: 'debug', cmd: 'tail follow yes mp-log ikemgr.log', why: 'Detailed IKE daemon log; the System log (subtype vpn) carries the summary lines.' },
      ];
    case 'juniper-srx':
      return [
        { stage: 'ike', cmd: 'show security ike security-associations detail', why: 'State UP with the negotiated algorithms. No entry means phase 1 never completed.' },
        { stage: 'ipsec', cmd: 'show security ipsec security-associations', why: 'One inbound and one outbound SA per traffic selector when healthy.' },
        { stage: 'ipsec', cmd: 'show security ipsec inactive-tunnels', why: 'Lists tunnels that are down together with the last failure reason.' },
        { stage: 'ipsec', cmd: 'show security ipsec statistics', why: 'Encrypted / decrypted packet counters and ESP error counters.' },
        { stage: 'traffic', cmd: `show route ${rhost}`, why: 'The remote LAN must resolve to st0, not the default route.' },
        { stage: 'traffic', cmd: `show security flow session destination-prefix ${rhost}`, why: 'Shows zones, policy and NAT for the live session.' },
        { stage: 'debug', cmd: `request security ike debug-enable local ${local} remote ${peer}\nshow log kmd`, why: 'Per-peer IKE debug without committing traceoptions.' },
      ];
    case 'mikrotik':
      return [
        { stage: 'ike', cmd: '/ip ipsec active-peers print', why: 'state=established means phase 1 is up; also shows NAT-T and uptime.' },
        { stage: 'ipsec', cmd: '/ip ipsec policy print', why: 'ph2-state=established is healthy. no-phase2 points at selectors or the proposal.' },
        { stage: 'ipsec', cmd: '/ip ipsec installed-sa print', why: 'One SA per direction with current-bytes counters for one-way traffic.' },
        { stage: 'traffic', cmd: `/tool sniffer quick ip-address=${peer}`, why: 'Shows whether UDP 500/4500 and ESP are on the wire.' },
        { stage: 'traffic', cmd: '/ip firewall nat print', why: 'The srcnat accept rule for the VPN must sit above masquerade.' },
        { stage: 'debug', cmd: '/system logging add topics=ipsec,!packet\n/log print follow where topics~"ipsec"', why: 'Verbose IPsec log without the per-packet noise.' },
      ];
    case 'azure':
      return [
        { stage: 'ike', cmd: `az network vpn-connection show --name con-${tn.toLowerCase()} --resource-group <rg> --output json`, why: 'connectionStatus should be Connected. IngressBytesTransferred and EgressBytesTransferred show whether traffic is flowing.' },
        { stage: 'ike', cmd: `az network local-gateway show --name lng-${tn.toLowerCase()} --resource-group <rg> --output json`, why: 'This is the on-prem peer as Azure sees it: gatewayIpAddress and localAddressPrefixes must match the branch public IP and LAN.' },
        { stage: 'ipsec', cmd: `az network vpn-connection ipsec-policy list --connection-name con-${tn.toLowerCase()} --resource-group <rg> --output table`, why: 'Shows the custom IKE/IPsec policy on the connection, if one is set. Empty means Azure default proposals are in use.' },
        { stage: 'traffic', cmd: `az network route-table route list --resource-group <rg> --route-table-name <workload-route-table> --output table`, why: 'On-prem prefixes must resolve to VirtualNetworkGateway on the workload subnets that need the tunnel.' },
        { stage: 'traffic', cmd: `AzureDiagnostics\n| where Category == "TunnelDiagnosticLog"\n| where Message contains "${peer}"\n| project TimeGenerated, Message\n| order by TimeGenerated desc`, why: 'Tunnel diagnostics in Log Analytics: look for connected state and byte counters for this peer.' },
        { stage: 'debug', cmd: `AzureDiagnostics\n| where Category == "IKEDiagnosticLog"\n| where Message contains "${peer}"\n| project TimeGenerated, Message\n| order by TimeGenerated desc`, why: 'Azure-side IKE errors: proposal, authentication, identity and traffic-selector failures with the peer endpoint.' },
        { stage: 'debug', cmd: `Start-AzVirtualNetworkGatewayPacketCapture -ResourceGroupName <rg> -VirtualNetworkGatewayName <vgw>`, why: 'Starts a gateway packet capture (stop it with Stop-AzVirtualNetworkGatewayPacketCapture and a storage SAS URL) to prove UDP 500/4500 or ESP arrival.' },
      ];
    case 'strongswan':
      return [
        { stage: 'ike', cmd: 'swanctl --list-sas', why: 'ESTABLISHED IKE SA with INSTALLED child SAs, byte and packet counters.' },
        { stage: 'ike', cmd: `swanctl --initiate --child net-net`, why: 'Initiates in the foreground and prints the negotiation as it happens.' },
        { stage: 'ipsec', cmd: 'ip -s xfrm state', why: 'Kernel SAs with per-direction packet counters.' },
        { stage: 'ipsec', cmd: 'ip xfrm policy', why: 'The selectors the kernel will actually encrypt.' },
        { stage: 'traffic', cmd: `tcpdump -ni any 'host ${peer} and (udp port 500 or udp port 4500 or esp)'`, why: 'Proves whether IKE and ESP are leaving and arriving.' },
        { stage: 'debug', cmd: 'swanctl --log', why: 'Live charon log: received vs. configured proposals, selector decisions and auth results.' },
      ];
  }
}
