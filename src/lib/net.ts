export function ipToInt(ip: string): number | null {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  if (p.some((n) => n > 255)) return null;
  return ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3];
}

export const isIp = (ip: string) => ipToInt(ip) !== null;

export function intToIp(n: number): string {
  return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join('.');
}

export interface Cidr {
  net: number;
  bits: number;
  size: number;
  cidr: string;
  network: string;
  mask: string;
  wildcard: string;
}

function maskOf(bits: number): number {
  return bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
}

export function parseCidr(s: string): Cidr | null {
  const m = s.trim().match(/^([\d.]+)\/(\d{1,2})$/);
  if (!m) return null;
  const ip = ipToInt(m[1]);
  const bits = Number(m[2]);
  if (ip === null || bits > 32) return null;
  const mask = maskOf(bits);
  const net = (ip & mask) >>> 0;
  return {
    net,
    bits,
    size: Math.pow(2, 32 - bits),
    cidr: `${intToIp(net)}/${bits}`,
    network: intToIp(net),
    mask: intToIp(mask),
    wildcard: intToIp((~mask) >>> 0),
  };
}

export const isCidr = (s: string) => parseCidr(s) !== null;

/** Normalised CIDR text, or the trimmed input when it does not parse. */
export function normCidr(s: string): string {
  return parseCidr(s)?.cidr ?? s.trim();
}

export function cidrContains(outer: Cidr, inner: Cidr): boolean {
  return outer.bits <= inner.bits && ((inner.net & maskOf(outer.bits)) >>> 0) === outer.net;
}

export function cidrOverlap(a: Cidr, b: Cidr): boolean {
  return cidrContains(a, b) || cidrContains(b, a);
}

/** A plausible host address inside the network. */
export function hostIn(s: string, offset = 10): string {
  const c = parseCidr(s);
  if (!c) return '<host>';
  if (c.bits >= 31) return intToIp(c.net);
  return intToIp(c.net + Math.min(offset, c.size - 2));
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const n = ipToInt(ip);
  const c = parseCidr(cidr);
  if (n === null || !c) return false;
  return ((n & maskOf(c.bits)) >>> 0) === c.net;
}

/** Deterministic 32-bit hash rendered as hex — used for stable fake SPIs/cookies. */
export function hex(seed: string, len = 8): string {
  let h = 2166136261;
  let out = '';
  for (let round = 0; out.length < len; round++) {
    for (let i = 0; i < seed.length; i++) {
      h ^= seed.charCodeAt(i) + round;
      h = Math.imul(h, 16777619);
    }
    out += (h >>> 0).toString(16).padStart(8, '0');
  }
  return out.slice(0, len);
}
