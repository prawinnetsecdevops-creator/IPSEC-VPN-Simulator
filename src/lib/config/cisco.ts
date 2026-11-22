import { isGcm, type Hash, type P1Enc, type P2Enc } from '../types';
import { FAULT, idType, type Gen } from './common';

/* ---------- Cisco IOS-XE ---------- */

const IOS_ENC1: Record<P1Enc, string> = {
  des: 'des', '3des': '3des', aes128: 'aes', aes192: 'aes 192', aes256: 'aes 256',
  aes128gcm: 'aes', aes256gcm: 'aes 256', chacha20poly1305: 'aes 256',
  camellia128: 'aes', camellia192: 'aes 192', camellia256: 'aes 256', blowfish: 'aes',
};
const IOS_HASH1: Record<Hash, string> = {
  md5: 'md5', sha1: 'sha', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512', aesxcbc: 'sha256',
};
const IOS_ENC2: Record<P1Enc, string> = {
  des: 'des', '3des': '3des', aes128: 'aes-cbc-128', aes192: 'aes-cbc-192', aes256: 'aes-cbc-256',
  aes128gcm: 'aes-gcm-128', aes256gcm: 'aes-gcm-256', chacha20poly1305: 'chacha20-poly1305',
  camellia128: 'aes-cbc-128', camellia192: 'aes-cbc-192', camellia256: 'aes-cbc-256', blowfish: 'aes-cbc-128',
};
const IOS_ESP: Record<P2Enc, string> = {
  des: 'esp-des', '3des': 'esp-3des', aes128: 'esp-aes', aes192: 'esp-aes 192', aes256: 'esp-aes 256',
  aes128gcm: 'esp-gcm', aes192gcm: 'esp-gcm 192', aes256gcm: 'esp-gcm 256',
  chacha20poly1305: 'esp-chacha20-poly1305', null: 'esp-null',
  camellia128: 'esp-aes', camellia192: 'esp-aes 192', camellia256: 'esp-aes 256', blowfish: 'esp-aes',
};
const IOS_ESP_AUTH: Record<Hash, string> = {
  md5: 'esp-md5-hmac', sha1: 'esp-sha-hmac', sha256: 'esp-sha256-hmac', sha384: 'esp-sha384-hmac', sha512: 'esp-sha512-hmac',
  aesxcbc: 'esp-aes-xcbc-mac',
};

function iosId(id: string, remote: boolean): string {
  const t = idType(id);
  if (t === 'ipaddr') return remote ? `address ${id} 255.255.255.255` : `address ${id}`;
  return `${t === 'fqdn' ? 'fqdn' : 'email'} ${id}`;
}

export function iosConfig(g: Gen): string {
  const { s } = g;
  const L: string[] = [`! ${g.title}`, '! Cisco IOS-XE', '!'];
  const wan = 'GigabitEthernet0/0/0';
  const acl = g.policy || g.specific;

  if (!g.v2) {
    L.push('crypto isakmp policy 10', ` encryption ${IOS_ENC1[s.p1Enc]}`, ` hash ${IOS_HASH1[s.p1Hash]}`, ' authentication pre-share', ` group ${s.dh}`, ` lifetime ${s.p1Life}`);
    if (s.mode === 'aggressive')
      L.push(`crypto isakmp peer address ${g.peer}`, ` set aggressive-mode password ${s.psk}`, ` set aggressive-mode client-endpoint ipv4-address ${g.localId || g.local}`);
    else L.push(`crypto isakmp key ${s.psk} address ${g.peer}`);
    if (g.localId && idType(g.localId) !== 'ipaddr') L.push('crypto isakmp identity hostname');
    L.push(s.dpd ? 'crypto isakmp keepalive 10 3 periodic' : 'no crypto isakmp keepalive');
  } else {
    L.push(
      `crypto ikev2 proposal PROP-${g.T}`, ` encryption ${IOS_ENC2[s.p1Enc]}`, ` integrity ${s.p1Hash}`, ` group ${s.dh}`,
      `crypto ikev2 policy POL-${g.T}`, ` match address local ${g.local}`, ` proposal PROP-${g.T}`,
      `crypto ikev2 keyring KR-${g.T}`, ` peer ${g.T}`, `  address ${g.peer}`, `  pre-shared-key ${s.psk}`,
      `crypto ikev2 profile PROF-${g.T}`,
      ` match identity remote ${iosId(g.remoteId || g.peer, true)}`,
      ` identity local ${iosId(g.localId || g.local, false)}`,
      ' authentication remote pre-share', ' authentication local pre-share',
      ` keyring local KR-${g.T}`, ` lifetime ${s.p1Life}`,
    );
    if (s.dpd) L.push(' dpd 10 3 periodic');
  }
  if (!s.natT) L.push('no crypto ipsec nat-transparency udp-encapsulation');

  L.push('!', `crypto ipsec transform-set TS-${g.T} ${IOS_ESP[s.p2Enc]}${isGcm(s.p2Enc) ? '' : ` ${IOS_ESP_AUTH[s.p2Auth]}`}`, ' mode tunnel');
  if (acl) L.push('!', `ip access-list extended VPN-${g.T}`, ` permit ip ${g.lan.net} ${g.lan.wild} ${g.rlan.net} ${g.rlan.wild}`);

  const saOpts = [
    ` set transform-set TS-${g.T}`,
    ...(s.pfs ? [` set pfs group${s.pfs}`] : []),
    ` set security-association lifetime seconds ${s.p2Life}`,
    ...(g.v2 ? [` set ikev2-profile PROF-${g.T}`] : []),
  ];

  if (g.policy) {
    L.push('!', 'crypto map CMAP 10 ipsec-isakmp', ` set peer ${g.peer}`, ...saOpts, ` match address VPN-${g.T}`);
    L.push('!', `interface ${wan}`, ' description WAN', ` ip address ${g.local} 255.255.255.248`, ' ip nat outside', ' crypto map CMAP');
  } else {
    L.push('!', `crypto ipsec profile IPSEC-${g.T}`, ...saOpts);
    L.push('!', 'interface Tunnel10', ` description VTI to ${g.o.name}`, ` ip unnumbered ${wan}`, ` tunnel source ${wan}`, ` tunnel destination ${g.peer}`, ' tunnel mode ipsec ipv4');
    if (g.specific) L.push(` tunnel protection ipsec policy ipv4 VPN-${g.T}   ! multi-SA VTI, IOS-XE 16.12 or later`);
    L.push(` tunnel protection ipsec profile IPSEC-${g.T}`);
    L.push('!');
    if (s.route) L.push(`ip route ${g.rlan.net} ${g.rlan.mask} Tunnel10`);
    else L.push(`! ${FAULT} no route for ${g.rlan.cidr} via Tunnel10 — traffic follows the default route`);
  }

  L.push('!', 'ip access-list extended NAT-INTERNET');
  if (s.dnat) {
    L.push(` ! ${FAULT} ip nat inside source static tcp ${s.dnatIp.trim() || g.lan.net} 80 ${g.peer} 80 — DNAT rewrites VPN traffic`);
  }
  if (s.snat || !s.natExempt) {
    L.push(` ! ${FAULT} missing "deny ip ${g.lan.net} ${g.lan.wild} ${g.rlan.net} ${g.rlan.wild}" — VPN traffic is translated (SNAT: ${s.snatIp.trim() || 'interface'})`);
  }
  if (!s.snat && !s.dnat && s.natExempt) {
    L.push(` deny ip ${g.lan.net} ${g.lan.wild} ${g.rlan.net} ${g.rlan.wild}   ! NAT exemption (No SNAT or DNAT)`);
  }
  L.push(` permit ip ${g.lan.net} ${g.lan.wild} any`, `ip nat inside source list NAT-INTERNET interface ${wan} overload`);

  L.push('!');
  if (s.fwPolicy) L.push(`! LAN <-> VPN: no ACL or zone-based policy restricts ${g.lan.cidr} <-> ${g.rlan.cidr}`);
  else
    L.push(
      `! ${FAULT} the LAN interface ACL drops traffic to and from ${g.rlan.cidr}`,
      'ip access-list extended LAN-IN', ` deny ip ${g.lan.net} ${g.lan.wild} ${g.rlan.net} ${g.rlan.wild}`, ' permit ip any any',
    );
  return L.join('\n');
}

/* ---------- Cisco ASA ---------- */

const ASA_ENC: Record<P1Enc, string> = {
  des: 'des', '3des': '3des', aes128: 'aes', aes192: 'aes-192', aes256: 'aes-256',
  aes128gcm: 'aes-gcm', aes256gcm: 'aes-gcm-256', chacha20poly1305: 'aes-256',
  camellia128: 'aes', camellia192: 'aes-192', camellia256: 'aes-256', blowfish: 'aes',
};
const ASA_HASH1: Record<Hash, string> = {
  md5: 'md5', sha1: 'sha', sha256: 'sha256', sha384: 'sha384', sha512: 'sha512', aesxcbc: 'aes-xcbc',
};
const ASA_ESP1: Record<P2Enc, string> = {
  des: 'esp-des', '3des': 'esp-3des', aes128: 'esp-aes', aes192: 'esp-aes-192', aes256: 'esp-aes-256',
  aes128gcm: 'esp-aes', aes192gcm: 'esp-aes-192', aes256gcm: 'esp-aes-256',
  chacha20poly1305: 'esp-aes-256', null: 'esp-none',
  camellia128: 'esp-aes', camellia192: 'esp-aes-192', camellia256: 'esp-aes-256', blowfish: 'esp-aes',
};
const ASA_ESP1_AUTH: Record<Hash, string> = {
  md5: 'esp-md5-hmac', sha1: 'esp-sha-hmac', sha256: 'esp-sha-hmac', sha384: 'esp-sha-hmac', sha512: 'esp-sha-hmac',
  aesxcbc: 'esp-aes-xcbc-mac',
};
const ASA_ESP2: Record<P2Enc, string> = {
  des: 'des', '3des': '3des', aes128: 'aes', aes192: 'aes-192', aes256: 'aes-256',
  aes128gcm: 'aes-gcm', aes192gcm: 'aes-gcm-192', aes256gcm: 'aes-gcm-256',
  chacha20poly1305: 'aes-256', null: 'null',
  camellia128: 'aes', camellia192: 'aes-192', camellia256: 'aes-256', blowfish: 'aes',
};
const ASA_INTEG2: Record<Hash, string> = {
  md5: 'md5', sha1: 'sha-1', sha256: 'sha-256', sha384: 'sha-384', sha512: 'sha-512', aesxcbc: 'aes-xcbc',
};

export function asaConfig(g: Gen): string {
  const { s } = g;
  const L: string[] = [`! ${g.title}`, '! Cisco ASA 9.x', '!'];
  const vti = `vti-${g.t}`;
  const v1Sha2 = !g.v2 && !['md5', 'sha1'].includes(s.p1Hash);
  const v1EspBad = !g.v2 && (isGcm(s.p2Enc) || !['md5', 'sha1'].includes(s.p2Auth));

  if (!g.v2) {
    L.push('crypto ikev1 enable outside', 'crypto ikev1 policy 10', ' authentication pre-share', ` encryption ${ASA_ENC[s.p1Enc]}`);
    if (v1Sha2) L.push(` ! UNSUPPORTED: ASA IKEv1 only accepts "hash md5" or "hash sha" — ${s.p1Hash} requires IKEv2`);
    L.push(` hash ${ASA_HASH1[s.p1Hash]}`, ` group ${s.dh}`, ` lifetime ${s.p1Life}`);
  } else {
    L.push('crypto ikev2 enable outside', 'crypto ikev2 policy 10', ` encryption ${ASA_ENC[s.p1Enc]}`, ` integrity ${ASA_HASH1[s.p1Hash]}`, ` group ${s.dh}`, ` prf ${ASA_HASH1[s.p1Hash]}`, ` lifetime seconds ${s.p1Life}`);
  }
  L.push(s.natT ? 'crypto isakmp nat-traversal 20' : 'no crypto isakmp nat-traversal');
  if (g.localId) L.push(`crypto isakmp identity ${idType(g.localId) === 'ipaddr' ? 'address' : 'hostname'}   ! presents ${g.localId}`);

  L.push('!', `tunnel-group ${g.peer} type ipsec-l2l`, `tunnel-group ${g.peer} ipsec-attributes`);
  if (!g.v2) L.push(` ikev1 pre-shared-key ${s.psk}`);
  else L.push(` ikev2 remote-authentication pre-shared-key ${s.psk}`, ` ikev2 local-authentication pre-shared-key ${s.psk}`);
  L.push(s.dpd ? ' isakmp keepalive threshold 10 retry 3' : ' isakmp keepalive disable');
  if (g.remoteId) L.push(' peer-id-validate req');

  L.push('!');
  if (!g.v2) {
    if (v1EspBad) L.push('! UNSUPPORTED: ASA IKEv1 transform sets offer only MD5 or SHA-1 HMAC and no GCM');
    L.push(`crypto ipsec ikev1 transform-set TS-${g.T} ${ASA_ESP1[s.p2Enc]} ${ASA_ESP1_AUTH[s.p2Auth]}`);
  } else {
    L.push(`crypto ipsec ikev2 ipsec-proposal PROP-${g.T}`, ` protocol esp encryption ${ASA_ESP2[s.p2Enc]}`, ` protocol esp integrity ${isGcm(s.p2Enc) ? 'null' : ASA_INTEG2[s.p2Auth]}`);
  }
  const setProp = g.v2 ? `set ikev2 ipsec-proposal PROP-${g.T}` : `set ikev1 transform-set TS-${g.T}`;

  L.push('!', 'object network NET-LOCAL', ` subnet ${g.lan.net} ${g.lan.mask}`, `object network NET-${g.T}`, ` subnet ${g.rlan.net} ${g.rlan.mask}`);

  if (g.policy) {
    const m = 'crypto map OUTSIDE_MAP 10';
    L.push('!', `access-list VPN-${g.T} extended permit ip object NET-LOCAL object NET-${g.T}`);
    L.push(`${m} match address VPN-${g.T}`, `${m} set peer ${g.peer}`, `${m} ${setProp}`);
    if (s.pfs) L.push(`${m} set pfs group${s.pfs}`);
    L.push(`${m} set security-association lifetime seconds ${s.p2Life}`);
    if (!g.v2 && s.mode === 'aggressive') L.push(`${m} set ikev1 phase1-mode aggressive`);
    L.push('crypto map OUTSIDE_MAP interface outside');
  } else {
    L.push('!', `crypto ipsec profile IPSEC-${g.T}`, ` ${setProp}`);
    if (s.pfs) L.push(` set pfs group${s.pfs}`);
    L.push(` set security-association lifetime seconds ${s.p2Life}`);
    L.push('!', 'interface Tunnel1', ` nameif ${vti}`, ` ip address ${g.tunIp} 255.255.255.252`, ' tunnel source interface outside', ` tunnel destination ${g.peer}`, ' tunnel mode ipsec ipv4', ` tunnel protection ipsec profile IPSEC-${g.T}`);
    L.push('!');
    if (s.route) L.push(`route ${vti} ${g.rlan.net} ${g.rlan.mask} ${g.tunPeer}`);
    else L.push(`! ${FAULT} no route for ${g.rlan.cidr} via ${vti} — traffic follows the default route`);
  }

  L.push('!');
  if (s.dnat) {
    L.push(`! ${FAULT} nat (outside,inside) source static any any destination static interface ${s.dnatIp.trim() || 'NET-LOCAL'} — DNAT redirects VPN flows`);
  }
  if (s.snat || !s.natExempt) {
    L.push(`! ${FAULT} no identity NAT for NET-LOCAL -> NET-${g.T}; the dynamic PAT rule below translates VPN traffic (SNAT: ${s.snatIp.trim() || 'interface'})`);
  }
  if (!s.snat && !s.dnat && s.natExempt) {
    L.push(`nat (inside,outside) source static NET-LOCAL NET-LOCAL destination static NET-${g.T} NET-${g.T} no-proxy-arp route-lookup   ! NAT bypass`);
  }
  L.push('nat (inside,outside) after-auto source dynamic any interface');

  L.push('!');
  if (s.fwPolicy) L.push('sysopt connection permit-vpn');
  else L.push(`! ${FAULT} VPN bypass is off and no ACL permits NET-${g.T} <-> NET-LOCAL`, 'no sysopt connection permit-vpn');
  return L.join('\n');
}
