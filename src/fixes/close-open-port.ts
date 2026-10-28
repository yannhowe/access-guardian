/**
 * One action: RevokeSecurityGroupIngress.
 *
 * The API name is the constant below. The security group id, protocol, port,
 * and CIDR identify which single rule that call removes. They are checked
 * here. They are not a second action.
 *
 * Dry-run is the default. `options.apply` must be exactly `true` or this
 * function does not call AWS. Set that flag in our own code after Yann's yes.
 * Do not copy it from the event, from Slack, or from a model reply.
 *
 * IAM: ec2:RevokeSecurityGroupIngress on that security group. This file does
 * not describe the group and does not authorize the rule back. The undo is
 * the allow-list line, done by a human if the revoke was wrong.
 *
 * What Grok decides: nothing. This file does not call Grok.
 * What code decides: whether the four fields are one valid rule, and whether
 * the one revoke is sent.
 */
import { ALLOWED_FIXES } from './allow-list.js';

export const ACTION = 'RevokeSecurityGroupIngress' as const;

type ActionMatches =
  typeof ACTION extends (typeof ALLOWED_FIXES)['close-open-port']['action'] ? true : never;

/** Compile-time check. The hardcoded action and the allow-list entry stay the same string. */
export const actionMatchesAllowList: ActionMatches = true;

export const IAM_ACTIONS = ['ec2:RevokeSecurityGroupIngress'] as const;

export type SecurityGroupClient = {
  send(command: RevokeIngressCommand): Promise<unknown>;
};

export type RevokeIngressCommand = {
  action: typeof ACTION;
  input: {
    GroupId: string;
    IpPermissions: [
      {
        IpProtocol: 'tcp' | 'udp';
        FromPort: number;
        ToPort: number;
        IpRanges: [{ CidrIp: string }];
      },
    ];
  };
};

export type PlannedRule = {
  securityGroupId: string;
  protocol: 'tcp' | 'udp';
  port: number;
  cidr: string;
};

export type CloseOpenPortResult =
  | { ok: true; applied: false; action: typeof ACTION; rule: PlannedRule; command: RevokeIngressCommand }
  | { ok: true; applied: true; action: typeof ACTION; rule: PlannedRule; command: RevokeIngressCommand }
  | { ok: false; reason: 'invalid_input' | 'aws_error' };

const GROUP_ID = /^sg-[a-z0-9]{8,17}$/;

/**
 * Plan the one revoke, and send it only when `options.apply` is `true`.
 * `input` is untrusted. A bad shape returns `invalid_input` and does not call AWS.
 */
export async function closeOpenPort(
  input: unknown,
  client: SecurityGroupClient,
  options?: { apply?: boolean },
): Promise<CloseOpenPortResult> {
  const parsed = parseRule(input);
  if (parsed === undefined) {
    return { ok: false, reason: 'invalid_input' };
  }

  const command = buildCommand(parsed);
  if (options?.apply !== true) {
    return { ok: true, applied: false, action: ACTION, rule: parsed, command };
  }

  try {
    await client.send(command);
  } catch {
    return { ok: false, reason: 'aws_error' };
  }

  return { ok: true, applied: true, action: ACTION, rule: parsed, command };
}

function parseRule(input: unknown): PlannedRule | undefined {
  if (typeof input !== 'object' || input === null) {
    return undefined;
  }

  const record = input as Record<string, unknown>;
  const securityGroupId = record.securityGroupId;
  const protocol = record.protocol;
  const port = record.port;
  const cidr = record.cidr;

  if (typeof securityGroupId !== 'string' || !GROUP_ID.test(securityGroupId)) {
    return undefined;
  }
  if (protocol !== 'tcp' && protocol !== 'udp') {
    return undefined;
  }
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 0 || port > 65535) {
    return undefined;
  }
  if (typeof cidr !== 'string' || !isIpv4Cidr(cidr)) {
    return undefined;
  }

  return { securityGroupId, protocol, port, cidr };
}

function buildCommand(rule: PlannedRule): RevokeIngressCommand {
  return {
    action: ACTION,
    input: {
      GroupId: rule.securityGroupId,
      IpPermissions: [
        {
          IpProtocol: rule.protocol,
          FromPort: rule.port,
          ToPort: rule.port,
          IpRanges: [{ CidrIp: rule.cidr }],
        },
      ],
    },
  };
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
