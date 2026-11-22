export type SiteKey = 'A' | 'B';
export type VendorId =
  | 'cisco-ios'
  | 'cisco-asa'
  | 'fortigate'
  | 'paloalto'
  | 'juniper-srx'
  | 'mikrotik'
  | 'strongswan'
  | 'azure';
export type IkeVersion = 'ikev1' | 'ikev2';
export type IkeMode = 'main' | 'aggressive';
export type P1Enc =
  | 'des'
  | '3des'
  | 'aes128'
  | 'aes192'
  | 'aes256'
  | 'aes128gcm'
  | 'aes256gcm'
  | 'chacha20poly1305'
  | 'camellia128'
  | 'camellia192'
  | 'camellia256'
  | 'blowfish';

export type Hash =
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'sha384'
  | 'sha512'
  | 'aesxcbc';

export type P2Enc =
  | 'des'
  | '3des'
  | 'aes128'
  | 'aes192'
  | 'aes256'
  | 'aes128gcm'
  | 'aes192gcm'
  | 'aes256gcm'
  | 'chacha20poly1305'
  | 'camellia128'
  | 'camellia192'
  | 'camellia256'
  | 'blowfish'
  | 'null';

export type TunnelType = 'route' | 'policy';

export interface Site {
  key: SiteKey;
  name: string;
  vendor: VendorId;

  // addressing
  wanIp: string; // public address the peer sees
  behindNat: boolean;
  natInsideIp: string; // interface address when behind NAT
  peerIp: string; // configured remote gateway
  lan: string; // local protected network (CIDR)
  remoteLan: string; // remote protected network as configured here

  // NAT on protected traffic (can be SNAT, DNAT, both, or neither)
  snat: boolean;
  snatIp: string; // mapped source IP or subnet pool (defaults to gateway IP if empty)
  dnat: boolean;
  dnatIp: string; // mapped destination IP or subnet (defaults to internal target if empty)

  // phase 1
  ikeVersion: IkeVersion;
  mode: IkeMode;
  p1Enc: P1Enc;
  p1Hash: Hash;
  dh: number;
  p1Life: number;
  psk: string;
  localId: string; // '' = interface address
  remoteId: string; // '' = platform default
  natT: boolean;
  dpd: boolean;

  // phase 2
  tunnelType: TunnelType;
  specificSelectors: boolean; // route-based only: narrow selectors instead of 0.0.0.0/0
  p2Enc: P2Enc;
  p2Auth: Hash;
  pfs: number; // 0 = off
  p2Life: number;

  // data path on the gateway
  natExempt: boolean;
  fwPolicy: boolean;
  route: boolean;

  // upstream filtering between this gateway and the internet
  blockIke: boolean;
  block4500: boolean;
  blockEsp: boolean;
}

export type Sites = Record<SiteKey, Site>;

export const P1_ENC_LABEL: Record<P1Enc, string> = {
  aes256: 'AES-256',
  aes192: 'AES-192',
  aes128: 'AES-128',
  aes256gcm: 'AES-256-GCM',
  aes128gcm: 'AES-128-GCM',
  chacha20poly1305: 'ChaCha20-Poly1305',
  camellia256: 'Camellia-256',
  camellia192: 'Camellia-192',
  camellia128: 'Camellia-128',
  blowfish: 'Blowfish',
  '3des': '3DES',
  des: 'DES',
};

export const HASH_LABEL: Record<Hash, string> = {
  sha256: 'SHA-256',
  sha384: 'SHA-384',
  sha512: 'SHA-512',
  sha1: 'SHA-1',
  md5: 'MD5',
  aesxcbc: 'AES-XCBC-96',
};

export const P2_ENC_LABEL: Record<P2Enc, string> = {
  aes256gcm: 'AES-256-GCM',
  aes192gcm: 'AES-192-GCM',
  aes128gcm: 'AES-128-GCM',
  chacha20poly1305: 'ChaCha20-Poly1305',
  aes256: 'AES-256',
  aes192: 'AES-192',
  aes128: 'AES-128',
  camellia256: 'Camellia-256',
  camellia192: 'Camellia-192',
  camellia128: 'Camellia-128',
  blowfish: 'Blowfish',
  '3des': '3DES',
  des: 'DES',
  null: 'NULL (Authentication only)',
};

export const DH_GROUPS = [1, 2, 5, 14, 15, 16, 18, 19, 20, 21, 24, 31] as const;

export const DH_NAME: Record<number, string> = {
  1: 'MODP-768 (legacy)',
  2: 'MODP-1024',
  5: 'MODP-1536',
  14: 'MODP-2048',
  15: 'MODP-3072',
  16: 'MODP-4096',
  18: 'MODP-8192',
  19: 'ECP-256',
  20: 'ECP-384',
  21: 'ECP-521',
  24: 'MODP-2048-256',
  31: 'Curve25519 (X25519)',
};

export const P1_LIFETIMES = [3600, 14400, 28800, 43200, 86400];
export const P2_LIFETIMES = [1800, 3600, 14400, 28800, 43200];

export const isAead = (e: P1Enc | P2Enc) =>
  e === 'aes128gcm' || e === 'aes192gcm' || e === 'aes256gcm' || e === 'chacha20poly1305';

export const isGcm = (e: P2Enc) => isAead(e);

export function lifeLabel(sec: number): string {
  if (sec % 3600 === 0) return `${sec} s · ${sec / 3600} h`;
  return `${sec} s · ${Math.round(sec / 60)} min`;
}

export function dhLabel(g: number): string {
  return g === 0 ? 'Off' : `Group ${g} · ${DH_NAME[g] ?? '?'}`;
}

export const other = (k: SiteKey): SiteKey => (k === 'A' ? 'B' : 'A');

/** Uppercase token safe for object names in CLI config. */
export function tok(name: string): string {
  const t = name
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return t || 'PEER';
}

/** Address the gateway actually owns on its WAN interface. */
export const ifaceIp = (s: Site) => (s.behindNat ? s.natInsideIp : s.wanIp);

/** IKE identity this gateway presents. */
export const idOf = (s: Site) => s.localId.trim() || ifaceIp(s);

export function idType(id: string): 'ipaddr' | 'fqdn' | 'ufqdn' {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(id.trim())) return 'ipaddr';
  if (id.includes('@')) return 'ufqdn';
  return 'fqdn';
}
