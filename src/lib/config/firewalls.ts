import { isGcm, type Hash, type P1Enc, type P2Enc } from '../types';
import { FAULT, idType, type Gen } from './common';

/* ---------- Fortinet FortiGate ---------- */

const FG_P2: Record<P2Enc, string> = {
  aes256gcm: 'aes256gcm',
  aes192gcm: 'aes256gcm',
  aes128gcm: 'aes128gcm',
  chacha20poly1305: 'chacha20poly1305',
  aes256: 'aes256',
  aes192: 'aes192',
  aes128: 'aes128',
  '3des': '3des',
  des: 'des',
  null: 'null',
  camellia256: 'aes256',
  camellia192: 'aes192',
  camellia128: 'aes128',
  blowfish: 'aes128',
};

export function fortigateConfig(g: Gen): string {
  const { s } = g;
  const L: string[] = [`# ${g.title}`, '# FortiGate, FortiOS 7.x', ''];
  const i = (n: number, t: string) => ' '.repeat(n * 4) + t;
  const p2prop = isGcm(s.p2Enc) ? FG_P2[s.p2Enc] : `${FG_P2[s.p2Enc]}-${s.p2Auth}`;

  L.push(`config vpn ipsec ${g.policy ? 'phase1' : 'phase1-interface'}`, i(1, `edit "${g.tn}"`), i(2, 'set interface "wan1"'), i(2, `set ike-version ${g.v2 ? 2 : 1}`));
  if (!g.v2) L.push(i(2, `set mode ${s.mode}`));
  if (g.remoteId) L.push(i(2, 'set peertype one'), i(2, `set peerid "${g.remoteId}"`));
  else L.push(i(2, 'set peertype any'));
  if (!g.policy) L.push(i(2, 'set net-device disable'));
  L.push(i(2, `set proposal ${s.p1Enc}-${s.p1Hash}`), i(2, `set dhgrp ${s.dh}`), i(2, `set keylife ${s.p1Life}`));
  L.push(i(2, `set nattraversal ${s.natT ? 'enable' : 'disable'}`), i(2, `set dpd ${s.dpd ? 'on-demand' : 'disable'}`));
  if (g.localId) L.push(i(2, `set localid "${g.localId}"`));
  L.push(i(2, `set remote-gw ${g.peer}`), i(2, `set psksecret ${s.psk}`), i(1, 'next'), 'end');

  L.push(`config vpn ipsec ${g.policy ? 'phase2' : 'phase2-interface'}`, i(1, `edit "${g.tn}-p2"`), i(2, `set phase1name "${g.tn}"`), i(2, `set proposal ${p2prop}`));
  if (s.pfs) L.push(i(2, 'set pfs enable'), i(2, `set dhgrp ${s.pfs}`));
  else L.push(i(2, 'set pfs disable'));
  L.push(i(2, `set keylifeseconds ${s.p2Life}`));
  if (g.specific) L.push(i(2, `set src-subnet ${g.lan.net} ${g.lan.mask}`), i(2, `set dst-subnet ${g.rlan.net} ${g.rlan.mask}`));
  L.push(i(1, 'next'), 'end');

  if (g.policy) {
    L.push('config firewall address', i(1, 'edit "NET-LOCAL"'), i(2, `set subnet ${g.lan.net} ${g.lan.mask}`), i(1, 'next'), i(1, `edit "NET-${g.T}"`), i(2, `set subnet ${g.rlan.net} ${g.rlan.mask}`), i(1, 'next'), 'end');
    if (s.fwPolicy) {
      L.push('config firewall policy', i(1, 'edit 0'), i(2, `set name "VPN-${g.T}"`), i(2, 'set srcintf "internal"'), i(2, 'set dstintf "wan1"'), i(2, 'set srcaddr "NET-LOCAL"'), i(2, `set dstaddr "NET-${g.T}"`), i(2, 'set action ipsec'), i(2, 'set schedule "always"'), i(2, 'set service "ALL"'), i(2, 'set inbound enable'), i(2, 'set outbound enable'), i(2, `set vpntunnel "${g.tn}"`));
      if (!s.natExempt) L.push(i(2, `set natoutbound enable    # ${FAULT} VPN traffic is source-NATed`));
      L.push(i(1, 'next'), 'end');
    } else L.push(`# ${FAULT} no IPsec policy references tunnel "${g.tn}" — FortiOS will not negotiate or pass traffic`);
    return L.join('\n');
  }

  if (s.route) L.push('config router static', i(1, 'edit 0'), i(2, `set dst ${g.rlan.net} ${g.rlan.mask}`), i(2, `set device "${g.tn}"`), i(1, 'next'), 'end');
  else L.push(`# ${FAULT} no static route for ${g.rlan.cidr} via "${g.tn}" — traffic follows the default route`);

  if (s.fwPolicy) {
    const pol = (name: string, src: string, dst: string, natLine: boolean) => [
      i(1, 'edit 0'), i(2, `set name "${name}"`), i(2, `set srcintf "${src}"`), i(2, `set dstintf "${dst}"`),
      i(2, 'set srcaddr "all"'), i(2, 'set dstaddr "all"'), i(2, 'set action accept'), i(2, 'set schedule "always"'), i(2, 'set service "ALL"'),
      ...(natLine ? [i(2, `set nat enable    # ${FAULT} VPN traffic is source-NATed`)] : []),
      i(1, 'next'),
    ];
    L.push('config firewall policy', ...pol(`LAN-to-${g.T}`, 'internal', g.tn, !s.natExempt), ...pol(`${g.T}-to-LAN`, g.tn, 'internal', false), 'end');
  } else L.push(`# ${FAULT} no firewall policy references "${g.tn}" — FortiOS will not negotiate or pass traffic`);
  return L.join('\n');
}

/* ---------- Palo Alto PAN-OS ---------- */

const PAN_ENC: Record<P1Enc | P2Enc, string> = {
  aes256gcm: 'aes-256-gcm',
  aes192gcm: 'aes-256-gcm',
  aes128gcm: 'aes-128-gcm',
  chacha20poly1305: 'aes-256-gcm',
  aes256: 'aes-256-cbc',
  aes192: 'aes-192-cbc',
  aes128: 'aes-128-cbc',
  '3des': '3des',
  des: 'des',
  null: 'none',
  camellia256: 'aes-256-cbc',
  camellia192: 'aes-192-cbc',
  camellia128: 'aes-128-cbc',
  blowfish: 'aes-128-cbc',
};

export function panosConfig(g: Gen): string {
  const { s } = g;
  const gw = `GW-${g.T}`;
  const tun = `IPSEC-${g.T}`;
  const ike = `set network ike crypto-profiles ike-crypto-profiles IKE-${g.T}`;
  const ipsec = `set network ike crypto-profiles ipsec-crypto-profiles ESP-${g.T}`;
  const ver = g.v2 ? 'ikev2' : 'ikev1';
  const idt = (id: string) => `type ${idType(id)} id ${id}`;
  const L: string[] = [`# ${g.title}`, '# PAN-OS set commands (configure mode). PAN-OS VPNs are always route-based.', ''];

  L.push(`${ike} encryption ${PAN_ENC[s.p1Enc]}`, `${ike} hash ${s.p1Hash}`, `${ike} dh-group group${s.dh}`, `${ike} lifetime seconds ${s.p1Life}`);
  L.push(`${ipsec} esp encryption ${PAN_ENC[s.p2Enc]}`, `${ipsec} esp authentication ${isGcm(s.p2Enc) ? 'none' : s.p2Auth}`, `${ipsec} dh-group ${s.pfs ? `group${s.pfs}` : 'no-pfs'}`, `${ipsec} lifetime seconds ${s.p2Life}`);

  L.push('', `set network interface tunnel units tunnel.10 comment "to ${g.o.name}"`, 'set network virtual-router default interface tunnel.10', 'set zone vpn network layer3 tunnel.10');

  const g1 = `set network ike gateway ${gw}`;
  L.push('', `${g1} authentication pre-shared-key key ${s.psk}`, `${g1} protocol version ${ver}`, `${g1} protocol ${ver} ike-crypto-profile IKE-${g.T}`, `${g1} protocol ${ver} dpd enable ${s.dpd ? 'yes' : 'no'}`);
  if (!g.v2) L.push(`${g1} protocol ikev1 exchange-mode ${s.mode}`);
  L.push(`${g1} protocol-common nat-traversal enable ${s.natT ? 'yes' : 'no'}`, `${g1} local-address interface ethernet1/1 ip ${g.local}`, `${g1} peer-address ip ${g.peer}`);
  if (g.localId) L.push(`${g1} local-id ${idt(g.localId)}`);
  if (g.remoteId) L.push(`${g1} peer-id ${idt(g.remoteId)}`);

  const t1 = `set network tunnel ipsec ${tun}`;
  L.push('', `${t1} auto-key ike-gateway ${gw}`, `${t1} auto-key ipsec-crypto-profile ESP-${g.T}`, `${t1} tunnel-interface tunnel.10`);
  if (g.specific) L.push(`${t1} auto-key proxy-id PID-1 local ${g.lan.cidr} remote ${g.rlan.cidr} protocol any`);
  else L.push('# no proxy-id: negotiates 0.0.0.0/0 <-> 0.0.0.0/0 (add one when the peer is policy-based)');

  L.push('');
  if (s.route) L.push(`set network virtual-router default routing-table ip static-route TO-${g.T} destination ${g.rlan.cidr} interface tunnel.10`);
  else L.push(`# ${FAULT} no static route for ${g.rlan.cidr} via tunnel.10 — traffic follows the default route`);

  L.push('');
  if (s.fwPolicy) {
    const r = (name: string, from: string, to: string) => `set rulebase security rules ${name} from ${from} to ${to} source any destination any application any service any action allow`;
    L.push(r(`LAN-to-${g.T}`, 'trust', 'vpn'), r(`${g.T}-to-LAN`, 'vpn', 'trust'));
  } else L.push(`# ${FAULT} no security rule between zones trust and vpn — interzone default denies the traffic`);

  L.push('');
  if (s.natExempt) L.push('# NAT: the internet source-NAT rule is scoped trust -> untrust, so trust -> vpn traffic is not translated');
  else
    L.push(
      `# ${FAULT} the source-NAT rule matches "to any", so trust -> vpn traffic is translated as well`,
      'set rulebase nat rules SNAT-ALL from trust to any source any destination any service any source-translation dynamic-ip-and-port interface-address interface ethernet1/1',
    );
  return L.join('\n');
}

/* ---------- Juniper SRX ---------- */

const SRX_ENC: Record<P1Enc | P2Enc, string> = {
  aes256gcm: 'aes-256-gcm',
  aes192gcm: 'aes-256-gcm',
  aes128gcm: 'aes-128-gcm',
  chacha20poly1305: 'aes-256-gcm',
  aes256: 'aes-256-cbc',
  aes192: 'aes-192-cbc',
  aes128: 'aes-128-cbc',
  '3des': '3des-cbc',
  des: 'des-cbc',
  null: 'null',
  camellia256: 'aes-256-cbc',
  camellia192: 'aes-192-cbc',
  camellia128: 'aes-128-cbc',
  blowfish: 'aes-128-cbc',
};
const SRX_IKE_AUTH: Record<Hash, string> = {
  sha256: 'sha-256',
  sha384: 'sha-384',
  sha512: 'sha-512',
  sha1: 'sha1',
  md5: 'md5',
  aesxcbc: 'aes-xcbc-mac',
};
const SRX_ESP_AUTH: Record<Hash, string> = {
  sha256: 'hmac-sha-256-128',
  sha384: 'hmac-sha-384',
  sha512: 'hmac-sha-512',
  sha1: 'hmac-sha1-96',
  md5: 'hmac-md5-96',
  aesxcbc: 'aes-xcbc-mac',
};

export function srxConfig(g: Gen): string {
  const { s } = g;
  const gw = `set security ike gateway GW-${g.T}`;
  const vpn = `set security ipsec vpn VPN-${g.T}`;
  const idj = (id: string) => (idType(id) === 'ipaddr' ? `inet ${id}` : idType(id) === 'fqdn' ? `hostname ${id}` : `user-at-hostname "${id}"`);
  const L: string[] = [`# ${g.title}`, '# Junos OS set commands (SRX)', ''];

  const ip = `set security ike proposal IKE-${g.T}`;
  L.push(`${ip} authentication-method pre-shared-keys`, `${ip} dh-group group${s.dh}`, `${ip} authentication-algorithm ${SRX_IKE_AUTH[s.p1Hash]}`, `${ip} encryption-algorithm ${SRX_ENC[s.p1Enc]}`, `${ip} lifetime-seconds ${s.p1Life}`);
  const pol = `set security ike policy IKEPOL-${g.T}`;
  if (!g.v2) L.push(`${pol} mode ${s.mode}`);
  L.push(`${pol} proposals IKE-${g.T}`, `${pol} pre-shared-key ascii-text "${s.psk}"`);
  L.push(`${gw} ike-policy IKEPOL-${g.T}`, `${gw} address ${g.peer}`, `${gw} external-interface ge-0/0/0.0`, `${gw} local-address ${g.local}`, `${gw} version ${g.v2 ? 'v2-only' : 'v1-only'}`);
  if (s.dpd) L.push(`${gw} dead-peer-detection optimized interval 10 threshold 3`);
  if (!s.natT) L.push(`${gw} no-nat-traversal`);
  if (g.localId) L.push(`${gw} local-identity ${idj(g.localId)}`);
  if (g.remoteId) L.push(`${gw} remote-identity ${idj(g.remoteId)}`);

  const pp = `set security ipsec proposal ESP-${g.T}`;
  L.push('', `${pp} protocol esp`);
  if (!isGcm(s.p2Enc)) L.push(`${pp} authentication-algorithm ${SRX_ESP_AUTH[s.p2Auth]}`);
  L.push(`${pp} encryption-algorithm ${SRX_ENC[s.p2Enc]}`, `${pp} lifetime-seconds ${s.p2Life}`);
  if (s.pfs) L.push(`set security ipsec policy ESPPOL-${g.T} perfect-forward-secrecy keys group${s.pfs}`);
  L.push(`set security ipsec policy ESPPOL-${g.T} proposals ESP-${g.T}`);
  L.push(`${vpn} ike gateway GW-${g.T}`, `${vpn} ike ipsec-policy ESPPOL-${g.T}`, `${vpn} establish-tunnels immediately`);
  L.push('set security zones security-zone untrust host-inbound-traffic system-services ike');

  if (g.policy) {
    if (g.v2) L.push('# UNSUPPORTED: Junos policy-based VPNs work with IKEv1 only — use a route-based (st0) VPN for IKEv2');
    L.push('', `set security zones security-zone trust address-book address NET-LOCAL ${g.lan.cidr}`, `set security zones security-zone untrust address-book address NET-${g.T} ${g.rlan.cidr}`);
    if (s.fwPolicy) {
      const out = 'set security policies from-zone trust to-zone untrust policy VPN-OUT';
      const inn = 'set security policies from-zone untrust to-zone trust policy VPN-IN';
      L.push(
        `${out} match source-address NET-LOCAL destination-address NET-${g.T} application any`, `${out} then permit tunnel ipsec-vpn VPN-${g.T} pair-policy VPN-IN`,
        `${inn} match source-address NET-${g.T} destination-address NET-LOCAL application any`, `${inn} then permit tunnel ipsec-vpn VPN-${g.T} pair-policy VPN-OUT`,
        'insert security policies from-zone trust to-zone untrust policy VPN-OUT before policy INTERNET',
      );
    } else L.push(`# ${FAULT} no tunnel policy (then permit tunnel ipsec-vpn VPN-${g.T}) — nothing is sent into the VPN`);
    const nr = 'set security nat source rule-set TRUST-TO-UNTRUST';
    L.push('', `${nr} from zone trust`, `${nr} to zone untrust`);
    if (s.natExempt) L.push(`${nr} rule NO-NAT-${g.T} match source-address ${g.lan.cidr} destination-address ${g.rlan.cidr}`, `${nr} rule NO-NAT-${g.T} then source-nat off`);
    else L.push(`# ${FAULT} no "source-nat off" rule for ${g.lan.cidr} -> ${g.rlan.cidr}; the interface NAT rule below translates VPN traffic`);
    L.push(`${nr} rule INTERNET match source-address 0.0.0.0/0`, `${nr} rule INTERNET then source-nat interface`);
    return L.join('\n');
  }

  L.push('', 'set interfaces st0 unit 0 family inet', 'set security zones security-zone vpn interfaces st0.0', `${vpn} bind-interface st0.0`);
  if (g.specific) L.push(`${vpn} traffic-selector TS-1 local-ip ${g.lan.cidr} remote-ip ${g.rlan.cidr}`);
  if (s.route) L.push(`set routing-options static route ${g.rlan.cidr} next-hop st0.0`);
  else L.push(`# ${FAULT} no static route for ${g.rlan.cidr} via st0.0 — traffic follows the default route`);

  L.push('');
  if (s.fwPolicy) {
    const p = (name: string, from: string, to: string) => {
      const base = `set security policies from-zone ${from} to-zone ${to} policy ${name}`;
      return [`${base} match source-address any destination-address any application any`, `${base} then permit`];
    };
    L.push(...p(`LAN-to-${g.T}`, 'trust', 'vpn'), ...p(`${g.T}-to-LAN`, 'vpn', 'trust'));
  } else L.push(`# ${FAULT} no security policy between zones trust and vpn — default-deny drops the traffic`);

  L.push('');
  if (s.natExempt) L.push('# NAT: the source NAT rule-set is trust -> untrust, so trust -> vpn traffic is not translated');
  else
    L.push(
      `# ${FAULT} a source NAT rule-set from trust to zone vpn translates traffic entering the tunnel`,
      'set security nat source rule-set TRUST-TO-VPN from zone trust', 'set security nat source rule-set TRUST-TO-VPN to zone vpn',
      'set security nat source rule-set TRUST-TO-VPN rule SNAT match source-address 0.0.0.0/0', 'set security nat source rule-set TRUST-TO-VPN rule SNAT then source-nat interface',
    );
  return L.join('\n');
}
