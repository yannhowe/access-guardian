/**
 * Lambda ag-fix-close-open-port.
 *
 * One close call: ec2:RevokeSecurityGroupIngress.
 * Two reads: ec2:DescribeSecurityGroupRules, so a missing rule returns
 * changed: false instead of revoking, and ec2:DescribeSecurityGroups, which
 * returns the group tags.
 *
 * apply defaults to false. Only a boolean true revokes. The bot sets that
 * after Yann's yes. This file does not call Grok.
 *
 * What Grok decides: nothing.
 * What code decides: whether the input is one rule, whether that rule is
 * present, whether the group has tag auto-remediate set to true, whether
 * classifyIngress says the named rule is a finding, and whether the one
 * revoke is sent.
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
import { classifyIngress, type SecurityGroupTag } from '../../policy/classify-ingress.js';

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

export type CloseOpenPortInput = {
  caseId: string;
  securityGroupId: string;
  protocol: 'tcp' | 'udp';
  port: number;
  cidr: string;
  apply: boolean;
};

export type FixResult =
  | {
      ok: true;
      changed: boolean;
      dryRun: boolean;
      action: typeof ACTION;
      caseId: string;
      securityGroupId: string;
      protocol: 'tcp' | 'udp';
      port: number;
      cidr: string;
      reason: 'dry_run' | 'already_closed' | 'revoked';
    }
  | {
      ok: false;
      changed: false;
      errorCode: string;
      errorMessage: string;
    }
  | {
      ok: false;
      changed: false;
      status: 'refused';
      reason: 'rule is not a finding under the port rule';
      action: typeof ACTION;
      caseId: string;
      securityGroupId: string;
      protocol: 'tcp' | 'udp';
      port: number;
      cidr: string;
    };

type Planned = CloseOpenPortInput;

type LiveRule = {
  groupId: string;
  egress: boolean;
  protocol: string;
  fromPort: number;
  toPort: number;
  cidr: string;
};

export async function handler(event: unknown): Promise<FixResult> {
  const client = new EC2Client({});
  return handleCloseOpenPort(event, client);
}

/**
 * Validate the event, read the group's rules, and revoke the one matching
 * ingress rule only when apply is true and that rule is present.
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
  if (matches.length > 1) {
    return {
      ok: false,
      changed: false,
      errorCode: 'NotOneRule',
      errorMessage: 'More than one ingress rule matches this port, protocol, and CIDR',
    };
  }

  const body = {
    action: ACTION,
    caseId: input.caseId,
    securityGroupId: input.securityGroupId,
    protocol: input.protocol,
    port: input.port,
    cidr: input.cidr,
  };

  if (matches.length === 0) {
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

  const verdict = classifyIngress(
    {
      protocol: input.protocol,
      fromPort: input.port,
      toPort: input.port,
      ipv4Cidrs: [input.cidr],
      ipv6Cidrs: [],
    },
    ingressTags(tagged.tags),
  );
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
        IpPermissions: [
          {
            IpProtocol: input.protocol,
            FromPort: input.port,
            ToPort: input.port,
            IpRanges: [{ CidrIp: input.cidr }],
          },
        ],
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
  if (record.protocol !== 'tcp' && record.protocol !== 'udp') {
    return { ok: false, message: 'protocol must be tcp or udp' };
  }
  if (typeof record.port !== 'number' || !Number.isInteger(record.port) || record.port < 0 || record.port > 65535) {
    return { ok: false, message: 'port must be an integer from 0 to 65535' };
  }
  if (typeof record.cidr !== 'string' || !isIpv4Cidr(record.cidr)) {
    return { ok: false, message: 'cidr must be one IPv4 CIDR' };
  }
  if ('apply' in record && typeof record.apply !== 'boolean') {
    return { ok: false, message: 'apply must be a boolean' };
  }

  return {
    ok: true,
    value: {
      caseId: record.caseId,
      securityGroupId: record.securityGroupId,
      protocol: record.protocol,
      port: record.port,
      cidr: record.cidr,
      apply: record.apply === true,
    },
  };
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
  if (typeof rule.FromPort !== 'number' || typeof rule.ToPort !== 'number' || typeof rule.CidrIpv4 !== 'string') {
    return 'skip';
  }
  return {
    groupId: rule.GroupId,
    egress: rule.IsEgress,
    protocol: rule.IpProtocol,
    fromPort: rule.FromPort,
    toPort: rule.ToPort,
    cidr: rule.CidrIpv4,
  };
}

function isTarget(rule: LiveRule, target: Planned): boolean {
  return (
    rule.groupId === target.securityGroupId &&
    rule.egress === false &&
    rule.protocol === target.protocol &&
    rule.fromPort === target.port &&
    rule.toPort === target.port &&
    rule.cidr === target.cidr
  );
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

/** One IPv4 CIDR. Host bits are not checked. Octets are 0 to 255, prefix is 0 to 32. */
function isIpv4Cidr(value: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(value);
  if (match === null) {
    return false;
  }

  const parts = [match[1], match[2], match[3], match[4], match[5]];
  if (parts.some((part) => part === undefined)) {
    return false;
  }

  for (const part of parts) {
    if (part === undefined) {
      return false;
    }
    if (part.length > 1 && part.startsWith('0')) {
      return false;
    }
  }

  const octets = parts.slice(0, 4).map((part) => Number(part));
  if (octets.some((octet) => octet > 255)) {
    return false;
  }

  const prefix = Number(parts[4]);
  return prefix <= 32;
}
