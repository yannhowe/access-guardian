/**
 * Decide whether one ingress rule is ok or a finding.
 *
 * This function does not call AWS and does not call Grok. A sensitive port
 * is a finding when any IPv4 or IPv6 source range is not fully inside private
 * space. Private space is 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
 * 100.64.0.0/10, and fc00::/7. A range that only partly overlaps that space,
 * and a CIDR that cannot be parsed, are findings. Protocol -1, a tcp or udp
 * range that covers a sensitive port, and a missing or unparseable port
 * count as sensitive. A tcp or udp range that covers none of those ports
 * uses the world-open rule. A sensitive port stays a finding when the group
 * is tagged public=true. Any other port uses the world-open rule: 0.0.0.0/0
 * or ::/0 is a finding unless that tag is set with the exact key and value.
 * IPv6 outside fc00::/7 is outside private space.
 */
import { SENSITIVE_PORTS } from './sensitive-ports.js';

export type IngressRule = {
  readonly protocol: string;
  readonly fromPort: number | null | undefined;
  readonly toPort: number | null | undefined;
  readonly ipv4Cidrs: readonly string[];
  readonly ipv6Cidrs: readonly string[];
};

export type SecurityGroupTag = {
  readonly key: string;
  readonly value: string;
};

export type IngressVerdict = 'ok' | 'finding';

const WORLD_IPV4 = '0.0.0.0/0';
const WORLD_IPV6 = '::/0';
const PUBLIC_KEY = 'public';
const PUBLIC_VALUE = 'true';
const ALL_TRAFFIC = '-1';

/** First 7 bits of fc00::/7. Covers fc00::/8 and fd00::/8. */
const UNIQUE_LOCAL_PREFIX = 7;
const UNIQUE_LOCAL_FIRST = 0xfc;
const UNIQUE_LOCAL_MASK = 0xfe;

type Ipv4Block = {
  readonly address: number;
  readonly prefix: number;
};

const PRIVATE_IPV4: readonly Ipv4Block[] = [
  { address: ipv4(10, 0, 0, 0), prefix: 8 },
  { address: ipv4(172, 16, 0, 0), prefix: 12 },
  { address: ipv4(192, 168, 0, 0), prefix: 16 },
  { address: ipv4(100, 64, 0, 0), prefix: 10 },
];

export function classifyIngress(rule: IngressRule, sgTags: readonly SecurityGroupTag[]): IngressVerdict {
  if (isSensitive(rule)) {
    return sourceOutsidePrivateSpace(rule) ? 'finding' : 'ok';
  }
  if (!isWorldOpen(rule)) {
    return 'ok';
  }
  if (hasPublicTag(sgTags)) {
    return 'ok';
  }
  return 'finding';
}

/**
 * IPv4 or IPv6 when the text is one CIDR the checkers below accept.
 * Host bits may be set. Anything else is not a CIDR.
 */
export function cidrFamily(cidr: string): 'ipv4' | 'ipv6' | undefined {
  if (parseIpv4Cidr(cidr) !== undefined) {
    return 'ipv4';
  }
  if (parseIpv6Cidr(cidr) !== undefined) {
    return 'ipv6';
  }
  return undefined;
}

function isWorldOpen(rule: IngressRule): boolean {
  return rule.ipv4Cidrs.some(isWorldCidr) || rule.ipv6Cidrs.some(isWorldCidr);
}

function isWorldCidr(cidr: string): boolean {
  return cidr === WORLD_IPV4 || cidr === WORLD_IPV6;
}

function isSensitive(rule: IngressRule): boolean {
  if (rule.protocol === ALL_TRAFFIC) {
    return true;
  }
  // tcp and udp ranges that cover a sensitive port count as that port.
  // Any other protocol that carries ports uses the same port check.
  // Protocol -1 is handled above and does not depend on the port numbers.
  return portsAreSensitive(rule.fromPort, rule.toPort);
}

function portsAreSensitive(fromPort: number | null | undefined, toPort: number | null | undefined): boolean {
  if (!isUsablePort(fromPort) || !isUsablePort(toPort) || fromPort > toPort) {
    return true;
  }
  return SENSITIVE_PORTS.some((port) => port >= fromPort && port <= toPort);
}

function isUsablePort(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 65535;
}

function hasPublicTag(sgTags: readonly SecurityGroupTag[]): boolean {
  return sgTags.some((tag) => tag.key === PUBLIC_KEY && tag.value === PUBLIC_VALUE);
}

/**
 * True when any source is missing from private space. An empty list has no
 * such range. A CIDR that cannot be parsed counts as outside.
 */
function sourceOutsidePrivateSpace(rule: IngressRule): boolean {
  if (rule.ipv4Cidrs.some((cidr) => !ipv4FullyPrivate(cidr))) {
    return true;
  }
  return rule.ipv6Cidrs.some((cidr) => !ipv6FullyPrivate(cidr));
}

function ipv4FullyPrivate(cidr: string): boolean {
  const parsed = parseIpv4Cidr(cidr);
  if (parsed === undefined) {
    return false;
  }
  return PRIVATE_IPV4.some((block) => ipv4Contains(block, parsed.address, parsed.prefix));
}

function ipv6FullyPrivate(cidr: string): boolean {
  const parsed = parseIpv6Cidr(cidr);
  if (parsed === undefined) {
    return false;
  }
  return ipv6InsideUniqueLocal(parsed.bytes, parsed.prefix);
}

/**
 * The candidate is fully inside the block when its prefix is at least as
 * long and every address it covers shares the block's network bits. A wider
 * prefix only partly overlaps, so it is outside. Host bits in the text are
 * masked by that comparison.
 */
function ipv4Contains(block: Ipv4Block, address: number, prefix: number): boolean {
  if (prefix < block.prefix) {
    return false;
  }
  const mask = ipv4Mask(block.prefix);
  return ((address & mask) >>> 0) === ((block.address & mask) >>> 0);
}

/**
 * A JavaScript shift uses the low 5 bits of the count, so a shift of 32
 * would keep every bit. Prefix 0 and prefix 32 are handled on their own.
 */
function ipv4Mask(prefix: number): number {
  if (prefix <= 0) {
    return 0;
  }
  if (prefix >= 32) {
    return 0xffffffff;
  }
  return (0xffffffff << (32 - prefix)) >>> 0;
}

function ipv6InsideUniqueLocal(bytes: Uint8Array, prefix: number): boolean {
  const first = bytes[0];
  if (first === undefined || prefix < UNIQUE_LOCAL_PREFIX) {
    return false;
  }
  return (first & UNIQUE_LOCAL_MASK) === UNIQUE_LOCAL_FIRST;
}

function parseIpv4Cidr(cidr: string): { address: number; prefix: number } | undefined {
  const parts = splitCidr(cidr);
  if (parts === undefined) {
    return undefined;
  }
  const address = parseIpv4Address(parts.address);
  const prefix = parsePrefixLength(parts.prefix, 32);
  if (address === undefined || prefix === undefined) {
    return undefined;
  }
  return { address, prefix };
}

function parseIpv6Cidr(cidr: string): { bytes: Uint8Array; prefix: number } | undefined {
  const parts = splitCidr(cidr);
  if (parts === undefined) {
    return undefined;
  }
  const bytes = parseIpv6Address(parts.address);
  const prefix = parsePrefixLength(parts.prefix, 128);
  if (bytes === undefined || prefix === undefined) {
    return undefined;
  }
  return { bytes, prefix };
}

function splitCidr(cidr: string): { address: string; prefix: string } | undefined {
  if (typeof cidr !== 'string') {
    return undefined;
  }
  const slash = cidr.indexOf('/');
  if (slash <= 0 || slash !== cidr.lastIndexOf('/')) {
    return undefined;
  }
  const address = cidr.slice(0, slash);
  const prefix = cidr.slice(slash + 1);
  if (address.length === 0 || prefix.length === 0) {
    return undefined;
  }
  return { address, prefix };
}

function parsePrefixLength(text: string, max: number): number | undefined {
  if (!/^(0|[1-9]\d{0,2})$/.test(text)) {
    return undefined;
  }
  const value = Number(text);
  if (!Number.isInteger(value) || value > max) {
    return undefined;
  }
  return value;
}

function parseIpv4Address(text: string): number | undefined {
  const parts = text.split('.');
  if (parts.length !== 4) {
    return undefined;
  }
  let address = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) {
      return undefined;
    }
    const octet = Number(part);
    if (octet > 255) {
      return undefined;
    }
    address = (address * 256 + octet) >>> 0;
  }
  return address;
}

function ipv4(a: number, b: number, c: number, d: number): number {
  return (((a * 256 + b) * 256 + c) * 256 + d) >>> 0;
}

function parseIpv6Address(text: string): Uint8Array | undefined {
  if (text.length === 0 || text.includes(':::')) {
    return undefined;
  }
  const halves = text.split('::');
  if (halves.length > 2) {
    return undefined;
  }
  const head = halves[0] ?? '';
  const left = head === '' ? [] : head.split(':');
  const compressed = halves.length === 2;
  const tail = halves[1] ?? '';
  const right = compressed && tail !== '' ? tail.split(':') : [];
  if (!compressed && left.length !== 8) {
    return undefined;
  }
  if (compressed && left.length + right.length > 7) {
    return undefined;
  }
  const groups: string[] = [];
  for (const group of left) {
    groups.push(group);
  }
  if (compressed) {
    const missing = 8 - left.length - right.length;
    for (let index = 0; index < missing; index += 1) {
      groups.push('0');
    }
    for (const group of right) {
      groups.push(group);
    }
  }
  if (groups.length !== 8) {
    return undefined;
  }
  const bytes = new Uint8Array(16);
  for (let index = 0; index < groups.length; index += 1) {
    const group = groups[index];
    if (group === undefined || !/^[0-9a-fA-F]{1,4}$/.test(group)) {
      return undefined;
    }
    const value = Number.parseInt(group, 16);
    if (!Number.isInteger(value) || value > 0xffff) {
      return undefined;
    }
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 0xff;
  }
  return bytes;
}
