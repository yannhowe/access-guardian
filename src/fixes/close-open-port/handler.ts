/**
 * Lambda ag-fix-close-open-port.
 *
 * One close call: ec2:RevokeSecurityGroupIngress.
 * Two reads: ec2:DescribeSecurityGroupRules, so a missing single-port tcp or
 * udp rule returns changed: false instead of revoking, and
 * ec2:DescribeSecurityGroups, which returns the group tags. A missing -1
 * rule is refused. A missing port-range rule is refused.
 *
 * apply defaults to false. Only a boolean true revokes. The bot sets that
 * after Yann's yes. This file does not call Grok.
 *
 * What Grok decides: nothing.
 * What code decides: whether the input is one rule, whether that rule is
 * present, whether the group has tag auto-remediate set to true, whether
 * classifyIngress says the named rule is a finding, and whether the one
 * revoke is sent. Protocol -1 has no port. A tcp or udp rule is either one
 * port or a fromPort and toPort range. The revoke names that protocol, that
 * port or range, and that one IPv4 or IPv6 CIDR. It never targets a
 * security-group source. For a range, and for protocol -1, zero matches and
 * more than one match are refused. An ok verdict uses the same refusal as
 * a single port.
 *
 * The role only revokes a group tagged purpose=ag-demo-synthetic and
 * auto-remediate=true. IAM enforces both tags. The handler also refuses,
 * including on a dry run, unless auto-remediate=true exactly.
 */
import {
  DescribeSecurityGroupRulesCommand,
  DescribeSecurityGroupsCommand,
  EC2Client,
  RevokeSecurityGroupIngressCommand,
} from '@aws-sdk/client-ec2';
import { cidrFamily, classifyIngress, type SecurityGroupTag } from '../../policy/classify-ingress.js';

export const ACTION = 'ec2:RevokeSecurityGroupIngress' as const;

const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';
const AUTO_REMEDIATE_TAG_VALUE = 'true';

function hasAutoRemediateTag(tags: readonly unknown[]): boolean {
  for (const tag of tags) {
    if (typeof tag !== 'object' || tag === null) {
      continue;
    }
    const record = tag as { Key?: unknown; Value?: unknown };
    if (record.Key === AUTO_REMEDIATE_TAG_KEY && record.Value === AUTO_REMEDIATE_TAG_VALUE) {
      return true;
    }
  }
  return false;
}

const GROUP_ID = /^sg-[a-z0-9]{8,17}$/;
const CASE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export type AwsClient = {
  send(command: unknown): Promise<unknown>;
};

type PortIdentity = { protocol: 'tcp' | 'udp'; port: number };
type RangeIdentity = { protocol: 'tcp' | 'udp'; fromPort: number; toPort: number };
type RuleIdentity = PortIdentity | RangeIdentity | { protocol: '-1' };

export type CloseOpenPortInput = {
  caseId: string;
  securityGroupId: string;
  cidr: string;
  apply: boolean;
} & RuleIdentity;

type Named = {
  action: typeof ACTION;
  caseId: string;
  securityGroupId: string;
  cidr: string;
} & RuleIdentity;

export type FixResult =
  | ({
      ok: true;
      changed: boolean;
      dryRun: boolean;
      reason: 'dry_run' | 'already_closed' | 'revoked';
    } & Named)
  | {
      ok: false;
      changed: false;
      errorCode: string;
      errorMessage: string;
    }
  | ({
      ok: false;
      changed: false;
      status: 'refused';
      reason: string;
    } & Named);

type Planned = CloseOpenPortInput & { cidrFamily: 'ipv4' | 'ipv6' };

type LiveRule = {
  groupId: string;
  egress: boolean;
  protocol: string;
  fromPort: number | null;
  toPort: number | null;
  cidr: string;
  family: 'ipv4' | 'ipv6';
};

export async function handler(event: unknown): Promise<FixResult> {
  const client = new EC2Client({});
  return handleCloseOpenPort(event, client);
}

/**
 * Validate the event, read the group's rules, and revoke the one matching
 * ingress rule only when apply is true, that rule is present, and
 * classifyIngress calls it a finding.
 */
export async function handleCloseOpenPort(event: unknown, client: AwsClient): Promise<FixResult> {
  const parsed = parseEvent(event);
  if (!parsed.ok) {
    return { ok: false, changed: false, errorCode: 'InvalidInput', errorMessage: parsed.message };
  }

  const input = parsed.value;
  let described: unknown;
  try {
    described = await client.send(
      new DescribeSecurityGroupRulesCommand({
        Filters: [{ Name: 'group-id', Values: [input.securityGroupId] }],
      }),
    );
  } catch (err) {
    return { ok: false, changed: false, ...readAwsError(err) };
  }

  const rules = readRules(described);
  if (rules === undefined) {
    return {
      ok: false,
      changed: false,
      errorCode: 'InvalidResponse',
      errorMessage: 'DescribeSecurityGroupRules did not return a rule list',
    };
  }

  const matches = rules.filter((rule) => isTarget(rule, input));
  const body = ruleBody(input);
  if (matches.length !== 1) {
    if (input.protocol === '-1') {
      return {
        ok: false,
        changed: false,
        status: 'refused',
        reason:
          matches.length > 1
            ? 'more than one ingress rule matches this protocol and CIDR'
            : 'no ingress rule matches this protocol and CIDR',
        ...body,
      };
    }
    if (isRange(input)) {
      return {
        ok: false,
        changed: false,
        status: 'refused',
        reason:
          matches.length > 1
            ? 'more than one ingress rule matches this protocol, port range, and CIDR'
            : 'no ingress rule matches this protocol, port range, and CIDR',
        ...body,
      };
    }
    if (matches.length > 1) {
      return {
        ok: false,
        changed: false,
        errorCode: 'NotOneRule',
        errorMessage: 'More than one ingress rule matches this port, protocol, and CIDR',
      };
    }
    return { ok: true, changed: false, dryRun: !input.apply, ...body, reason: 'already_closed' };
  }

  const tagged = await readGroupTags(client, input.securityGroupId);
  if (!tagged.ok) {
    return tagged.failure;
  }
  if (!hasAutoRemediateTag(tagged.tags)) {
    return {
      ok: false,
      changed: false,
      errorCode: 'MissingAutoRemediateTag',
      errorMessage: 'security group must have tag auto-remediate set to true',
    };
  }

  const verdict = classifyIngress(ingressRule(input), ingressTags(tagged.tags));
  if (verdict === 'ok') {
    return {
      ok: false,
      changed: false,
      status: 'refused',
      reason: 'rule is not a finding under the port rule',
      ...body,
    };
  }

  if (!input.apply) {
    return { ok: true, changed: false, dryRun: true, ...body, reason: 'dry_run' };
  }

  try {
    await client.send(
      new RevokeSecurityGroupIngressCommand({
        GroupId: input.securityGroupId,
        IpPermissions: [ipPermission(input)],
      }),
    );
  } catch (err) {
    return { ok: false, changed: false, ...readAwsError(err) };
  }

  return { ok: true, changed: true, dryRun: false, ...body, reason: 'revoked' };
}

function parseEvent(event: unknown): { ok: true; value: Planned } | { ok: false; message: string } {
  if (typeof event !== 'object' || event === null) {
    return { ok: false, message: 'input must be an object' };
  }
  const record = event as Record<string, unknown>;

  if (typeof record.caseId !== 'string' || !CASE_ID.test(record.caseId)) {
    return { ok: false, message: 'caseId must be 1 to 64 letters, digits, hyphens, or underscores' };
  }
  if (typeof record.securityGroupId !== 'string' || !GROUP_ID.test(record.securityGroupId)) {
    return { ok: false, message: 'securityGroupId must look like sg- and then 8 to 17 lowercase letters or digits' };
  }
  if (record.protocol !== 'tcp' && record.protocol !== 'udp' && record.protocol !== '-1') {
    return { ok: false, message: 'protocol must be tcp, udp, or -1' };
  }
  const identity = parseIdentity(record.protocol, record);
  if (!identity.ok) {
    return identity;
  }
  if (typeof record.cidr !== 'string') {
    return { ok: false, message: 'cidr must be one IPv4 or IPv6 CIDR' };
  }
  const family = cidrFamily(record.cidr);
  if (family === undefined) {
    return { ok: false, message: 'cidr must be one IPv4 or IPv6 CIDR' };
  }
  if ('apply' in record && typeof record.apply !== 'boolean') {
    return { ok: false, message: 'apply must be a boolean' };
  }

  return {
    ok: true,
    value: {
      caseId: record.caseId,
      securityGroupId: record.securityGroupId,
      cidr: record.cidr,
      cidrFamily: family,
      apply: record.apply === true,
      ...identity.value,
    },
  };
}

function parseIdentity(
  protocol: 'tcp' | 'udp' | '-1',
  record: Record<string, unknown>,
): { ok: true; value: RuleIdentity } | { ok: false; message: string } {
  const hasPort = 'port' in record;
  const hasFrom = 'fromPort' in record;
  const hasTo = 'toPort' in record;

  if (protocol === '-1') {
    if (hasPort || hasFrom || hasTo) {
      return { ok: false, message: 'protocol -1 does not take a port' };
    }
    return { ok: true, value: { protocol: '-1' } };
  }
  if (hasPort && (hasFrom || hasTo)) {
    return { ok: false, message: 'send port or fromPort and toPort, not both' };
  }
  if (hasPort) {
    if (!isPort(record.port)) {
      return { ok: false, message: 'port must be an integer from 0 to 65535' };
    }
    return { ok: true, value: { protocol, port: record.port } };
  }
  if (hasFrom || hasTo) {
    if (!hasFrom || !hasTo) {
      return { ok: false, message: 'fromPort and toPort are required together' };
    }
    if (!isPort(record.fromPort) || !isPort(record.toPort)) {
      return { ok: false, message: 'fromPort and toPort must be integers from 0 to 65535' };
    }
    if (record.fromPort > record.toPort) {
      return { ok: false, message: 'fromPort must be less than or equal to toPort' };
    }
    return { ok: true, value: { protocol, fromPort: record.fromPort, toPort: record.toPort } };
  }
  return { ok: false, message: 'port must be an integer from 0 to 65535' };
}

function isPort(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 65535;
}

function isRange(input: Planned): input is Planned & RangeIdentity {
  return input.protocol !== '-1' && !('port' in input);
}

function readRules(payload: unknown): LiveRule[] | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return undefined;
  }
  const list = (payload as { SecurityGroupRules?: unknown }).SecurityGroupRules;
  if (!Array.isArray(list)) {
    return undefined;
  }

  const rules: LiveRule[] = [];
  for (const item of list) {
    const rule = readRule(item);
    if (rule === 'bad') {
      return undefined;
    }
    if (rule !== 'skip') {
      rules.push(rule);
    }
  }
  return rules;
}

function readRule(item: unknown): LiveRule | 'skip' | 'bad' {
  if (typeof item !== 'object' || item === null) {
    return 'bad';
  }
  const rule = item as Record<string, unknown>;
  if (typeof rule.GroupId !== 'string' || typeof rule.IpProtocol !== 'string' || typeof rule.IsEgress !== 'boolean') {
    return 'bad';
  }
  if (isSecurityGroupSource(rule)) {
    return 'skip';
  }
  const cidr = readRuleCidr(rule);
  if (cidr === undefined) {
    return 'skip';
  }
  if (typeof rule.FromPort === 'number' && typeof rule.ToPort === 'number') {
    return {
      groupId: rule.GroupId,
      egress: rule.IsEgress,
      protocol: rule.IpProtocol,
      fromPort: rule.FromPort,
      toPort: rule.ToPort,
      cidr: cidr.value,
      family: cidr.family,
    };
  }
  if (rule.IpProtocol === '-1' && portAbsent(rule.FromPort) && portAbsent(rule.ToPort)) {
    return {
      groupId: rule.GroupId,
      egress: rule.IsEgress,
      protocol: rule.IpProtocol,
      fromPort: null,
      toPort: null,
      cidr: cidr.value,
      family: cidr.family,
    };
  }
  return 'skip';
}

function isSecurityGroupSource(rule: Record<string, unknown>): boolean {
  return typeof rule.ReferencedGroupInfo === 'object' && rule.ReferencedGroupInfo !== null;
}

/** One CIDR, either IPv4 or IPv6. A rule with both, or with neither, is not a match. */
function readRuleCidr(rule: Record<string, unknown>): { value: string; family: 'ipv4' | 'ipv6' } | undefined {
  const ipv4 = cidrText(rule.CidrIpv4);
  const ipv6 = cidrText(rule.CidrIpv6);
  if (ipv4 !== undefined && ipv6 !== undefined) {
    return undefined;
  }
  if (ipv4 !== undefined) {
    return { value: ipv4, family: 'ipv4' };
  }
  if (ipv6 !== undefined) {
    return { value: ipv6, family: 'ipv6' };
  }
  return undefined;
}

function cidrText(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }
  return undefined;
}

function portAbsent(value: unknown): boolean {
  return value === undefined || value === null;
}

function isTarget(rule: LiveRule, target: Planned): boolean {
  if (
    rule.groupId !== target.securityGroupId ||
    rule.egress !== false ||
    rule.protocol !== target.protocol ||
    rule.cidr !== target.cidr ||
    rule.family !== target.cidrFamily
  ) {
    return false;
  }
  if (target.protocol === '-1') {
    return true;
  }
  if ('port' in target) {
    return rule.fromPort === target.port && rule.toPort === target.port;
  }
  return rule.fromPort === target.fromPort && rule.toPort === target.toPort;
}

/**
 * Protocol -1 is all traffic. IpPermission does not require a port range
 * for that protocol. The revoke omits FromPort and ToPort. A described
 * rule may still report those ports as -1, and that rule still matches.
 * The permission names one CIDR, in IpRanges or Ipv6Ranges, and no group pair.
 */
function ipPermission(input: Planned): {
  IpProtocol: string;
  FromPort?: number;
  ToPort?: number;
  IpRanges?: Array<{ CidrIp: string }>;
  Ipv6Ranges?: Array<{ CidrIpv6: string }>;
} {
  const ports = portBounds(input);
  if (input.cidrFamily === 'ipv6') {
    return { IpProtocol: input.protocol, ...ports, Ipv6Ranges: [{ CidrIpv6: input.cidr }] };
  }
  return { IpProtocol: input.protocol, ...ports, IpRanges: [{ CidrIp: input.cidr }] };
}

function portBounds(input: Planned): { FromPort?: number; ToPort?: number } {
  if (input.protocol === '-1') {
    return {};
  }
  if ('port' in input) {
    return { FromPort: input.port, ToPort: input.port };
  }
  return { FromPort: input.fromPort, ToPort: input.toPort };
}

function ingressRule(input: Planned): {
  protocol: string;
  fromPort: number | null;
  toPort: number | null;
  ipv4Cidrs: string[];
  ipv6Cidrs: string[];
} {
  const ipv4Cidrs = input.cidrFamily === 'ipv4' ? [input.cidr] : [];
  const ipv6Cidrs = input.cidrFamily === 'ipv6' ? [input.cidr] : [];
  if (input.protocol === '-1') {
    return { protocol: '-1', fromPort: null, toPort: null, ipv4Cidrs, ipv6Cidrs };
  }
  if ('port' in input) {
    return { protocol: input.protocol, fromPort: input.port, toPort: input.port, ipv4Cidrs, ipv6Cidrs };
  }
  return { protocol: input.protocol, fromPort: input.fromPort, toPort: input.toPort, ipv4Cidrs, ipv6Cidrs };
}

function ruleBody(input: Planned): Named {
  const common = {
    action: ACTION,
    caseId: input.caseId,
    securityGroupId: input.securityGroupId,
    cidr: input.cidr,
  };
  if (input.protocol === '-1') {
    return { ...common, protocol: '-1' };
  }
  if ('port' in input) {
    return { ...common, protocol: input.protocol, port: input.port };
  }
  return { ...common, protocol: input.protocol, fromPort: input.fromPort, toPort: input.toPort };
}

type GroupTag = { Key?: unknown; Value?: unknown };

function ingressTags(tags: readonly GroupTag[]): SecurityGroupTag[] {
  const out: SecurityGroupTag[] = [];
  for (const tag of tags) {
    if (typeof tag.Key === 'string' && typeof tag.Value === 'string') {
      out.push({ key: tag.Key, value: tag.Value });
    }
  }
  return out;
}

async function readGroupTags(
  client: AwsClient,
  groupId: string,
): Promise<{ ok: true; tags: GroupTag[] } | { ok: false; failure: Extract<FixResult, { ok: false }> }> {
  let described: unknown;
  try {
    described = await client.send(
      new DescribeSecurityGroupsCommand({
        GroupIds: [groupId],
      }),
    );
  } catch (err) {
    return { ok: false, failure: { ok: false, changed: false, ...readAwsError(err) } };
  }

  const tags = readGroupTagList(described, groupId);
  if (tags === undefined) {
    return {
      ok: false,
      failure: {
        ok: false,
        changed: false,
        errorCode: 'InvalidResponse',
        errorMessage: 'DescribeSecurityGroups did not return the security group',
      },
    };
  }
  return { ok: true, tags };
}

function readGroupTagList(payload: unknown, groupId: string): GroupTag[] | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return undefined;
  }
  const groups = (payload as { SecurityGroups?: unknown }).SecurityGroups;
  if (!Array.isArray(groups)) {
    return undefined;
  }
  const group = groups.find((item) => {
    return typeof item === 'object' && item !== null && (item as { GroupId?: unknown }).GroupId === groupId;
  });
  if (typeof group !== 'object' || group === null) {
    return undefined;
  }
  const raw = (group as { Tags?: unknown }).Tags;
  if (raw === undefined) {
    return [];
  }
  if (!Array.isArray(raw)) {
    return undefined;
  }
  const tags: GroupTag[] = [];
  for (const item of raw) {
    if (typeof item !== 'object' || item === null) {
      return undefined;
    }
    tags.push(item as GroupTag);
  }
  return tags;
}

function readAwsError(err: unknown): { errorCode: string; errorMessage: string } {
  if (typeof err === 'string' && err.length > 0) {
    return { errorCode: 'Unknown', errorMessage: err };
  }
  if (typeof err !== 'object' || err === null) {
    return { errorCode: 'Unknown', errorMessage: 'AWS call failed' };
  }
  const record = err as { name?: unknown; Code?: unknown; message?: unknown; Message?: unknown };
  const errorCode = stringField(record.name) ?? stringField(record.Code) ?? 'Unknown';
  const errorMessage = stringField(record.message) ?? stringField(record.Message) ?? 'AWS call failed';
  return { errorCode, errorMessage };
}

function stringField(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }
  return undefined;
}

