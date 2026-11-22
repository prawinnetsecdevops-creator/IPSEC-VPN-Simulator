import { isGcm, type P1Enc, type P2Enc } from '../types';
import { FAULT, idType, type Gen } from './common';

const MODP: Record<number, string> = {
  1: 'modp768',
  2: 'modp1024',
  5: 'modp1536',
  14: 'modp2048',
  15: 'modp3072',
  16: 'modp4096',
  18: 'modp8192',
  19: 'ecp256',
  20: 'ecp384',
  21: 'ecp521',
  24: 'modp2048s256',
  31: 'curve25519',
};

/* ---------- MikroTik RouterOS 7 ---------- */

const ROS_P1: Record<P1Enc, string> = {
  aes256: 'aes-256',
  aes192: 'aes-192',
  aes128: 'aes-128',
  aes256gcm: 'aes-256',
  aes128gcm: 'aes-128',
  chacha20poly1305: 'chacha20-poly1305',
  camellia256: 'camellia-256',
  camellia192: 'camellia-192',
  camellia128: 'camellia-128',
  blowfish: 'blowfish',
  '3des': '3des',
  des: 'des',
};

const ROS_P2: Record<P2Enc, string> = {
  aes256gcm: 'aes-256-gcm',
  aes192gcm: 'aes-256-gcm',
  aes128gcm: 'aes-128-gcm',
  chacha20poly1305: 'chacha20-poly1305',
  aes256: 'aes-256-cbc',
  aes192: 'aes-192-cbc',
  aes128: 'aes-128-cbc',
  camellia256: 'camellia-256',
  camellia192: 'camellia-192',
  camellia128: 'camellia-128',
  blowfish: 'blowfish',
  '3des': '3des',
  des: 'des',
  null: 'null',
};

function rosTime(sec: number): string {
  if (sec % 86400 === 0) return `${sec / 86400}d`;
  if (sec % 3600 === 0) return `${sec / 3600}h`;
  if (sec % 60 === 0) return `${sec / 60}m`;
  return `${sec}s`;
}

export function mikrotikConfig(g: Gen): string {
  const { s } = g;
  const rid = (id: string) => `${idType(id) === 'ipaddr' ? 'address' : idType(id) === 'fqdn' ? 'fqdn' : 'user-fqdn'}:${id}`;
  const L: string[] = [`# ${g.title}`, '# MikroTik RouterOS 7. Plain IPsec on RouterOS is policy-based.', ''];

  L.push(
    '/ip ipsec profile',
    `add name=prof-${g.t} enc-algorithm=${ROS_P1[s.p1Enc]} hash-algorithm=${s.p1Hash} dh-group=${MODP[s.dh]} lifetime=${rosTime(s.p1Life)} nat-traversal=${s.natT ? 'yes' : 'no'} ${s.dpd ? 'dpd-interval=10s dpd-maximum-failures=3' : 'dpd-interval=disable-dpd'}`,
    '/ip ipsec peer',
    `add name=${g.tn} address=${g.peer}/32 local-address=${g.local} profile=prof-${g.t} exchange-mode=${g.v2 ? 'ike2' : s.mode}`,
    '/ip ipsec identity',
    `add peer=${g.tn} auth-method=pre-shared-key secret="${s.psk}"${g.localId ? ` my-id=${rid(g.localId)}` : ''}${g.remoteId ? ` remote-id=${rid(g.remoteId)}` : ''}`,
    '/ip ipsec proposal',
    `add name=prop-${g.t} enc-algorithms=${ROS_P2[s.p2Enc]} auth-algorithms=${isGcm(s.p2Enc) ? 'null' : s.p2Auth} pfs-group=${s.pfs ? MODP[s.pfs] : 'none'} lifetime=${rosTime(s.p2Life)}`,
    '/ip ipsec policy',
    `add peer=${g.tn} tunnel=yes src-address=${g.lan.cidr} dst-address=${g.rlan.cidr} proposal=prop-${g.t} action=encrypt`,
  );
  if (!isGcm(s.p2Enc) && s.p2Auth === 'sha384') L.splice(L.length - 2, 0, '# UNSUPPORTED: RouterOS proposals offer md5, sha1, sha256, sha512 — not sha384');

  L.push('', '/ip firewall filter', `add chain=input action=accept protocol=udp dst-port=500,4500 src-address=${g.peer} comment="IKE and NAT-T from ${g.o.name}"`, `add chain=input action=accept protocol=ipsec-esp src-address=${g.peer} comment="ESP from ${g.o.name}"`);
  if (s.fwPolicy)
    L.push(
      `add chain=forward action=accept src-address=${g.lan.cidr} dst-address=${g.rlan.cidr} comment="LAN to ${g.o.name}"`,
      `add chain=forward action=accept src-address=${g.rlan.cidr} dst-address=${g.lan.cidr} ipsec-policy=in,ipsec comment="${g.o.name} to LAN"`,
    );
  else L.push(`# ${FAULT} no forward rules for ${g.lan.cidr} <-> ${g.rlan.cidr}; the final drop rule discards the traffic`);

  L.push('', '/ip firewall nat');
  if (s.natExempt) L.push(`add chain=srcnat action=accept src-address=${g.lan.cidr} dst-address=${g.rlan.cidr} place-before=0 comment="no NAT into the VPN"`);
  else L.push(`# ${FAULT} no srcnat accept rule above masquerade — VPN traffic is translated before the IPsec policy sees it`);
  L.push('add chain=srcnat action=masquerade out-interface-list=WAN');
  return L.join('\n');
}

/* ---------- strongSwan (swanctl) ---------- */

const SW_ENC: Record<P1Enc | P2Enc, string> = {
  aes256gcm: 'aes256gcm16',
  aes192gcm: 'aes192gcm16',
  aes128gcm: 'aes128gcm16',
  chacha20poly1305: 'chacha20poly1305',
  aes256: 'aes256',
  aes192: 'aes192',
  aes128: 'aes128',
  camellia256: 'camellia256',
  camellia192: 'camellia192',
  camellia128: 'camellia128',
  blowfish: 'blowfish',
  '3des': '3des',
  des: 'des',
  null: 'null',
};

export function strongswanConfig(g: Gen): string {
  const { s } = g;
  const cn = g.tn.toLowerCase();
  const esp = [SW_ENC[s.p2Enc], isGcm(s.p2Enc) ? null : s.p2Auth, s.pfs ? MODP[s.pfs] : null].filter(Boolean).join('-');
  const L: string[] = [`# ${g.title}`, '# strongSwan: /etc/swanctl/conf.d/' + cn + '.conf, then "swanctl --load-all"', ''];
  const i = (n: number, t: string) => ' '.repeat(n * 4) + t;

  L.push('connections {', i(1, `${cn} {`), i(2, `version = ${g.v2 ? 2 : 1}`));
  if (!g.v2 && s.mode === 'aggressive') L.push(i(2, 'aggressive = yes'));
  L.push(i(2, `local_addrs = ${g.local}`), i(2, `remote_addrs = ${g.peer}`), i(2, `proposals = ${SW_ENC[s.p1Enc]}-${s.p1Hash}-${MODP[s.dh]}`));
  L.push(i(2, `${g.v2 ? 'rekey_time' : 'reauth_time'} = ${s.p1Life}s`), i(2, `dpd_delay = ${s.dpd ? '10s' : '0s'}`));
  if (s.natT) L.push(i(2, '# NAT-T is automatic: charon floats to UDP 4500 when NAT is detected'));
  else L.push(i(2, '# NOTE: strongSwan cannot switch NAT-T off; it is always offered'));
  if (!g.policy) L.push(i(2, 'if_id_in = 10'), i(2, 'if_id_out = 10'));
  L.push(i(2, 'local {'), i(3, 'auth = psk'), i(3, `id = ${g.localId || g.local}`), i(2, '}'));
  L.push(i(2, 'remote {'), i(3, 'auth = psk'), i(3, `id = ${g.remoteId || g.peer}`), i(2, '}'));
  L.push(
    i(2, 'children {'), i(3, 'net-net {'),
    i(4, `local_ts = ${g.specific ? g.lan.cidr : '0.0.0.0/0'}`), i(4, `remote_ts = ${g.specific ? g.rlan.cidr : '0.0.0.0/0'}`),
    i(4, `esp_proposals = ${esp}`), i(4, `rekey_time = ${s.p2Life}s`), i(4, 'mode = tunnel'),
    i(4, `dpd_action = ${s.dpd ? 'restart' : 'clear'}`), i(4, 'start_action = start'),
    i(3, '}'), i(2, '}'), i(1, '}'), '}',
  );
  L.push('', 'secrets {', i(1, `ike-${cn} {`), i(2, `id = ${g.remoteId || g.peer}`), i(2, `secret = "${s.psk}"`), i(1, '}'), '}');

  L.push('', '# --- host setup (shell) ---', '# sysctl -w net.ipv4.ip_forward=1');
  if (!g.policy) {
    L.push('# ip link add ipsec0 type xfrm dev eth0 if_id 10 && ip link set ipsec0 up');
    if (s.route) L.push(`# ip route add ${g.rlan.cidr} dev ipsec0`);
    else L.push(`# ${FAULT} no "ip route add ${g.rlan.cidr} dev ipsec0" — traffic follows the default route`);
  }
  if (s.fwPolicy) L.push(`# nft add rule inet filter forward ip saddr ${g.lan.cidr} ip daddr ${g.rlan.cidr} accept`, `# nft add rule inet filter forward ip saddr ${g.rlan.cidr} ip daddr ${g.lan.cidr} accept`);
  else L.push(`# ${FAULT} the forward chain has no accept rules for ${g.lan.cidr} <-> ${g.rlan.cidr}`);
  if (s.natExempt) L.push(`# nft insert rule ip nat postrouting ip saddr ${g.lan.cidr} ip daddr ${g.rlan.cidr} accept`);
  else L.push(`# ${FAULT} no NAT exemption above masquerade — VPN traffic is translated before the IPsec policy lookup`);
  L.push('# nft add rule ip nat postrouting oifname "eth0" masquerade');
  return L.join('\n');
}
