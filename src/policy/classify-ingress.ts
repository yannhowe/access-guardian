/**
 * Decide whether one ingress rule is ok or a finding.
 *
 * This function does not call AWS and does not call Grok. A rule that is not
 * open to 0.0.0.0/0 or ::/0 is ok. A world-open rule on a sensitive port is a
 * finding even when the group is tagged intended-public=true. Protocol -1, a
 * range that overlaps a sensitive port, and a missing or unparseable port
 * count as sensitive. Any other world-open port is a finding unless that tag
 * is set with the exact key and value.
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
const INTENDED_PUBLIC_KEY = 'intended-public';
const INTENDED_PUBLIC_VALUE = 'true';
const ALL_TRAFFIC = '-1';

export function classifyIngress(rule: IngressRule, sgTags: readonly SecurityGroupTag[]): IngressVerdict {
  if (!isWorldOpen(rule)) {
    return 'ok';
  }
  if (isSensitive(rule)) {
    return 'finding';
  }
  if (hasIntendedPublic(sgTags)) {
    return 'ok';
  }
  return 'finding';
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

function hasIntendedPublic(sgTags: readonly SecurityGroupTag[]): boolean {
  return sgTags.some((tag) => tag.key === INTENDED_PUBLIC_KEY && tag.value === INTENDED_PUBLIC_VALUE);
}
