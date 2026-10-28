/**
 * Tests for the close-open-port Lambda. The EC2 client is a fake.
 * These tests do not call AWS.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DescribeSecurityGroupRulesCommand,
  DescribeSecurityGroupsCommand,
  RevokeSecurityGroupIngressCommand,
} from '@aws-sdk/client-ec2';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALLOWED_FIXES } from '../../src/fixes/allow-list.js';
import {
  ACTION,
  handleCloseOpenPort,
  handler,
  type AwsClient,
} from '../../src/fixes/close-open-port/handler.js';
import { registryKeysMatchAllowList } from '../../src/fixes/registry.js';

const EVENT = {
  caseId: 'case-demo-1',
  securityGroupId: 'sg-demo0001',
  protocol: 'tcp',
  port: 22,
  cidr: '0.0.0.0/0',
};

const ALL_EVENT = {
  caseId: 'case-demo-1',
  securityGroupId: 'sg-demo0001',
  protocol: '-1',
  cidr: '0.0.0.0/0',
};

function openRule(over: Record<string, unknown> = {}) {
  return {
    GroupId: 'sg-demo0001',
    IsEgress: false,
    IpProtocol: 'tcp',
    FromPort: 22,
    ToPort: 22,
    CidrIpv4: '0.0.0.0/0',
    ...over,
  };
}

function allTrafficRule(over: Record<string, unknown> = {}) {
  return {
    GroupId: 'sg-demo0001',
    IsEgress: false,
    IpProtocol: '-1',
    FromPort: -1,
    ToPort: -1,
    CidrIpv4: '0.0.0.0/0',
    ...over,
  };
}

const GROUP_TAGS = [
  { Key: 'purpose', Value: 'ag-demo-synthetic' },
  { Key: 'auto-remediate', Value: 'true' },
];

function described(rules: unknown[]) {
  return { SecurityGroupRules: rules };
}

function groupResponse(tags: Array<{ Key: string; Value: string }> | 'omit') {
  const group: { GroupId: string; Tags?: Array<{ Key: string; Value: string }> } = { GroupId: 'sg-demo0001' };
  if (tags !== 'omit') {
    group.Tags = tags;
  }
  return { SecurityGroups: [group] };
}

function fakeClient(
  rules: unknown[],
  options: { tags?: Array<{ Key: string; Value: string }> | 'omit' } = {},
): { client: AwsClient; send: ReturnType<typeof vi.fn> } {
  const tags = options.tags === undefined ? GROUP_TAGS : options.tags;
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof DescribeSecurityGroupRulesCommand) {
      return described(rules);
    }
    if (command instanceof DescribeSecurityGroupsCommand) {
      return groupResponse(tags);
    }
    return {};
  });
  return { client: { send }, send };
}

function revoked(send: ReturnType<typeof vi.fn>): unknown[] {
  return send.mock.calls.map((call) => call[0]).filter((command) => command instanceof RevokeSecurityGroupIngressCommand);
}

beforeEach(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('this test must not call fetch');
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('close-open-port handler', () => {
  it('names the one allow-listed close action', () => {
    expect(ACTION).toBe('ec2:RevokeSecurityGroupIngress');
    expect(ACTION).toBe(ALLOWED_FIXES['close-open-port'].action);
    expect(registryKeysMatchAllowList).toBe(true);
    expect(typeof handler).toBe('function');
  });

  it('limits the revoke to groups tagged for this demo', () => {
    const policyPath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../src/fixes/close-open-port/policy.json',
    );
    const policy = JSON.parse(readFileSync(policyPath, 'utf8')) as {
      Statement: Array<{ Action: string[]; Resource: string; Condition?: unknown }>;
    };
    const revoke = policy.Statement.find((statement) => statement.Action.includes(ACTION));
    expect(revoke?.Resource).toBe('arn:aws:ec2:*:*:security-group/*');
    expect(revoke?.Condition).toEqual({
      StringEquals: {
        'aws:ResourceTag/purpose': 'ag-demo-synthetic',
        'aws:ResourceTag/auto-remediate': 'true',
      },
    });
    const reads = policy.Statement.find((statement) => statement.Action.includes('ec2:DescribeSecurityGroupRules'));
    expect(reads?.Action).toEqual(['ec2:DescribeSecurityGroupRules', 'ec2:DescribeSecurityGroups']);
    expect(reads?.Resource).toBe('*');
  });

  it('returns a dry run and does not revoke when apply is omitted', async () => {
    const { client, send } = fakeClient([openRule()]);

    const result = await handleCloseOpenPort(EVENT, client);

    expect(result).toMatchObject({
      ok: true,
      changed: false,
      dryRun: true,
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      reason: 'dry_run',
    });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0]?.[0]).toBeInstanceOf(DescribeSecurityGroupRulesCommand);
    expect(send.mock.calls[1]?.[0]).toBeInstanceOf(DescribeSecurityGroupsCommand);
    expect(revoked(send)).toEqual([]);
  });

  it('does not revoke when apply is false', async () => {
    const { client, send } = fakeClient([openRule()]);

    const result = await handleCloseOpenPort({ ...EVENT, apply: false }, client);

    expect(result).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'dry_run' });
    expect(send).toHaveBeenCalledTimes(2);
    expect(revoked(send)).toEqual([]);
  });

  it('revokes once when apply is true and the rule is present', async () => {
    const { client, send } = fakeClient([openRule(), openRule({ FromPort: 443, ToPort: 443 })]);

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, dryRun: false, reason: 'revoked' });
    expect(send).toHaveBeenCalledTimes(3);
    expect(send.mock.calls[1]?.[0]).toBeInstanceOf(DescribeSecurityGroupsCommand);
    expect(send.mock.calls[1]?.[0].input).toEqual({ GroupIds: ['sg-demo0001'] });
    const revoke = send.mock.calls[2]?.[0];
    expect(revoke).toBeInstanceOf(RevokeSecurityGroupIngressCommand);
    expect(revoke.input).toEqual({
      GroupId: 'sg-demo0001',
      IpPermissions: [
        {
          IpProtocol: 'tcp',
          FromPort: 22,
          ToPort: 22,
          IpRanges: [{ CidrIp: '0.0.0.0/0' }],
        },
      ],
    });
  });

  it('revokes tcp/22 from 0.0.0.0/0 when the group is tagged public=true', async () => {
    const { client, send } = fakeClient([openRule()], {
      tags: [
        { Key: 'purpose', Value: 'ag-demo-synthetic' },
        { Key: 'auto-remediate', Value: 'true' },
        { Key: 'public', Value: 'true' },
      ],
    });

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({
      ok: true,
      changed: true,
      dryRun: false,
      reason: 'revoked',
      protocol: 'tcp',
      port: 22,
      cidr: '0.0.0.0/0',
    });
    const revoke = send.mock.calls[2]?.[0];
    expect(revoke).toBeInstanceOf(RevokeSecurityGroupIngressCommand);
    expect(revoke.input).toEqual({
      GroupId: 'sg-demo0001',
      IpPermissions: [
        {
          IpProtocol: 'tcp',
          FromPort: 22,
          ToPort: 22,
          IpRanges: [{ CidrIp: '0.0.0.0/0' }],
        },
      ],
    });
  });

  it('reports changed false when the rule is already gone', async () => {
    const { client, send } = fakeClient([]);

    const dry = await handleCloseOpenPort(EVENT, client);
    const applied = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(dry).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'already_closed' });
    expect(applied).toMatchObject({ ok: true, changed: false, dryRun: false, reason: 'already_closed' });
    expect(send.mock.calls.every((call) => call[0] instanceof DescribeSecurityGroupRulesCommand)).toBe(true);
  });

  it('uses the given protocol, port, and CIDR', async () => {
    const { client, send } = fakeClient([
      openRule({ IpProtocol: 'udp', FromPort: 53, ToPort: 53, CidrIpv4: '0.0.0.0/0' }),
    ]);
    const event = {
      ...EVENT,
      protocol: 'udp',
      port: 53,
      cidr: '0.0.0.0/0',
      apply: true,
    };

    const result = await handleCloseOpenPort(event, client);

    expect(result).toMatchObject({ ok: true, changed: true, protocol: 'udp', port: 53, cidr: '0.0.0.0/0' });
    const revoke = send.mock.calls[2]?.[0];
    expect(revoke.input.IpPermissions[0]).toMatchObject({
      IpProtocol: 'udp',
      FromPort: 53,
      ToPort: 53,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
  });

  it('refuses tcp/443 from 0.0.0.0/0 on a public=true group and does not revoke', async () => {
    const tags = [
      { Key: 'purpose', Value: 'ag-demo-synthetic' },
      { Key: 'auto-remediate', Value: 'true' },
      { Key: 'public', Value: 'true' },
    ];
    for (const apply of [undefined, false, true] as const) {
      const { client, send } = fakeClient([openRule({ FromPort: 443, ToPort: 443 })], { tags });
      const event = apply === undefined ? { ...EVENT, port: 443 } : { ...EVENT, port: 443, apply };
      const result = await handleCloseOpenPort(event, client);
      expect(result, `apply=${String(apply)}`).toEqual({
        ok: false,
        changed: false,
        status: 'refused',
        reason: 'rule is not a finding under the port rule',
        action: ACTION,
        caseId: 'case-demo-1',
        securityGroupId: 'sg-demo0001',
        protocol: 'tcp',
        port: 443,
        cidr: '0.0.0.0/0',
      });
      expect(revoked(send), `apply=${String(apply)}`).toEqual([]);
    }
  });

  it('revokes tcp/443 from 0.0.0.0/0 when the group is not tagged public=true', async () => {
    const { client, send } = fakeClient([openRule({ FromPort: 443, ToPort: 443 })], {
      tags: [
        { Key: 'purpose', Value: 'ag-demo-synthetic' },
        { Key: 'auto-remediate', Value: 'true' },
      ],
    });

    const result = await handleCloseOpenPort({ ...EVENT, port: 443, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, dryRun: false, reason: 'revoked', port: 443 });
    const revoke = send.mock.calls[2]?.[0];
    expect(revoke).toBeInstanceOf(RevokeSecurityGroupIngressCommand);
    expect(revoke.input.IpPermissions[0]).toMatchObject({
      IpProtocol: 'tcp',
      FromPort: 443,
      ToPort: 443,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
  });

  it('does not revoke when more than one rule matches', async () => {
    const { client, send } = fakeClient([openRule(), openRule()]);

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'NotOneRule',
      errorMessage: 'More than one ingress rule matches this port, protocol, and CIDR',
    });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a short group id', { ...EVENT, securityGroupId: 'sg-short' }],
    ['an uppercase group id', { ...EVENT, securityGroupId: 'SG-DEMO0001' }],
    ['a bad case id', { ...EVENT, caseId: '' }],
    ['TCP in the wrong case', { ...EVENT, protocol: 'TCP' }],
    ['a string port', { ...EVENT, port: '22' }],
    ['a port past the end', { ...EVENT, port: 65536 }],
    ['the word any', { ...EVENT, cidr: 'any' }],
    ['a string apply flag', { ...EVENT, apply: 'true' }],
    ['null', null],
  ])('refuses %s and does not call AWS', async (_label, event) => {
    const { client, send } = fakeClient([openRule()]);

    const result = await handleCloseOpenPort(event, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidInput' });
    expect(send).not.toHaveBeenCalled();
  });

  it('returns the AWS error code and message when describe fails', async () => {
    const send = vi.fn(async () => {
      throw Object.assign(new Error('The security group does not exist'), { name: 'InvalidGroup.NotFound' });
    });

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, { send });

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'InvalidGroup.NotFound',
      errorMessage: 'The security group does not exist',
    });
    expect(JSON.stringify(result)).not.toContain('aws_error');
  });

  it('returns the AWS error from the revoke and does not claim a change', async () => {
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof DescribeSecurityGroupRulesCommand) {
        return described([openRule()]);
      }
      if (command instanceof DescribeSecurityGroupsCommand) {
        return groupResponse(GROUP_TAGS);
      }
      throw Object.assign(new Error('User is not authorized'), { name: 'AccessDenied' });
    });

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, { send });

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDenied',
      errorMessage: 'User is not authorized',
    });
  });

  it.each([
    ['the tag is missing', []],
    ['only the purpose tag is present', [{ Key: 'purpose', Value: 'ag-demo-synthetic' }]],
    ['the value is false', [{ Key: 'auto-remediate', Value: 'false' }]],
    ['the value is True', [{ Key: 'auto-remediate', Value: 'True' }]],
    ['the key is AUTO-REMEDIATE', [{ Key: 'AUTO-REMEDIATE', Value: 'true' }]],
    ['the key is Auto-Remediate', [{ Key: 'Auto-Remediate', Value: 'true' }]],
    ['the value is empty', [{ Key: 'auto-remediate', Value: '' }]],
  ])('refuses when %s and does not revoke', async (_label, tags) => {
    for (const apply of [false, true]) {
      const { client, send } = fakeClient([openRule()], { tags });

      const result = await handleCloseOpenPort({ ...EVENT, apply }, client);

      expect(result).toEqual({
        ok: false,
        changed: false,
        errorCode: 'MissingAutoRemediateTag',
        errorMessage: 'security group must have tag auto-remediate set to true',
      });
      expect(revoked(send)).toEqual([]);
    }
  });

  it('refuses a dry run when the tag list is omitted', async () => {
    const { client, send } = fakeClient([openRule()], { tags: 'omit' });

    const result = await handleCloseOpenPort(EVENT, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'MissingAutoRemediateTag',
      errorMessage: 'security group must have tag auto-remediate set to true',
    });
    expect(revoked(send)).toEqual([]);
    expect(send.mock.calls.some((call) => call[0] instanceof DescribeSecurityGroupsCommand)).toBe(true);
  });

  it('revokes one all-traffic rule when the protocol and CIDR match', async () => {
    const { client, send } = fakeClient([allTrafficRule(), openRule()]);

    const result = await handleCloseOpenPort({ ...ALL_EVENT, apply: true }, client);

    expect(result).toMatchObject({
      ok: true,
      changed: true,
      dryRun: false,
      action: ACTION,
      protocol: '-1',
      cidr: '0.0.0.0/0',
      reason: 'revoked',
    });
    expect(result).not.toHaveProperty('port');
    expect(send).toHaveBeenCalledTimes(3);
    const revoke = send.mock.calls[2]?.[0];
    expect(revoke).toBeInstanceOf(RevokeSecurityGroupIngressCommand);
    expect(revoke.input).toEqual({
      GroupId: 'sg-demo0001',
      IpPermissions: [
        {
          IpProtocol: '-1',
          IpRanges: [{ CidrIp: '0.0.0.0/0' }],
        },
      ],
    });
    expect(revoke.input.IpPermissions[0]).not.toHaveProperty('FromPort');
    expect(revoke.input.IpPermissions[0]).not.toHaveProperty('ToPort');
  });

  it('refuses a private all-traffic rule through the same not-a-finding path', async () => {
    const { client, send } = fakeClient([allTrafficRule({ CidrIpv4: '10.0.0.0/8' })]);

    const result = await handleCloseOpenPort({ ...ALL_EVENT, cidr: '10.0.0.0/8', apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      status: 'refused',
      reason: 'rule is not a finding under the port rule',
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      protocol: '-1',
      cidr: '10.0.0.0/8',
    });
    expect(revoked(send)).toEqual([]);
  });

  it('matches an all-traffic rule that describe returns without ports', async () => {
    const rule: Record<string, unknown> = allTrafficRule();
    delete rule.FromPort;
    delete rule.ToPort;
    const { client, send } = fakeClient([rule]);

    const result = await handleCloseOpenPort({ ...ALL_EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, reason: 'revoked', protocol: '-1', cidr: '0.0.0.0/0' });
    expect(send.mock.calls[2]?.[0].input.IpPermissions[0]).not.toHaveProperty('FromPort');
  });

  it('does not revoke an all-traffic rule on a dry run', async () => {
    const { client, send } = fakeClient([allTrafficRule()]);

    const result = await handleCloseOpenPort(ALL_EVENT, client);

    expect(result).toMatchObject({ ok: true, changed: false, dryRun: true, protocol: '-1', reason: 'dry_run' });
    expect(revoked(send)).toEqual([]);
  });

  it('refuses when more than one all-traffic rule matches the CIDR', async () => {
    const { client, send } = fakeClient([allTrafficRule(), allTrafficRule({ SecurityGroupRuleId: 'sgr-demo0002' })]);

    const result = await handleCloseOpenPort({ ...ALL_EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      status: 'refused',
      reason: 'more than one ingress rule matches this protocol and CIDR',
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      protocol: '-1',
      cidr: '0.0.0.0/0',
    });
    expect(send).toHaveBeenCalledTimes(1);
    expect(revoked(send)).toEqual([]);
  });

  it('refuses when no all-traffic rule matches the CIDR', async () => {
    const { client, send } = fakeClient([
      allTrafficRule({ CidrIpv4: '10.0.0.0/8' }),
      allTrafficRule({ IsEgress: true }),
      openRule(),
    ]);

    const dry = await handleCloseOpenPort(ALL_EVENT, client);
    const applied = await handleCloseOpenPort({ ...ALL_EVENT, apply: true }, client);

    expect(dry).toEqual({
      ok: false,
      changed: false,
      status: 'refused',
      reason: 'no ingress rule matches this protocol and CIDR',
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      protocol: '-1',
      cidr: '0.0.0.0/0',
    });
    expect(applied).toEqual(dry);
    expect(revoked(send)).toEqual([]);
  });

  it('revokes a world-open all-traffic rule when the group is tagged public=true', async () => {
    const { client, send } = fakeClient([allTrafficRule()], {
      tags: [...GROUP_TAGS, { Key: 'public', Value: 'true' }],
    });

    const result = await handleCloseOpenPort({ ...ALL_EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, dryRun: false, reason: 'revoked', protocol: '-1' });
    expect(revoked(send)).toHaveLength(1);
  });

  it('still requires auto-remediate before an all-traffic revoke', async () => {
    const { client, send } = fakeClient([allTrafficRule()], { tags: [] });

    const result = await handleCloseOpenPort({ ...ALL_EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'MissingAutoRemediateTag',
      errorMessage: 'security group must have tag auto-remediate set to true',
    });
    expect(revoked(send)).toEqual([]);
  });

  it('refuses protocol -1 when a port is set and does not call AWS', async () => {
    const { client, send } = fakeClient([allTrafficRule()]);

    const result = await handleCloseOpenPort({ ...ALL_EVENT, port: 0 }, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidInput' });
    expect(send).not.toHaveBeenCalled();
  });

  it('still revokes tcp when an all-traffic rule is also present', async () => {
    const { client, send } = fakeClient([allTrafficRule(), openRule()]);

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, protocol: 'tcp', port: 22, reason: 'revoked' });
    expect(send.mock.calls[2]?.[0].input.IpPermissions[0]).toEqual({
      IpProtocol: 'tcp',
      FromPort: 22,
      ToPort: 22,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
  });

  it('revokes only when the tag is exactly auto-remediate=true', async () => {
    const { client, send } = fakeClient([openRule()], {
      tags: [
        { Key: 'purpose', Value: 'ag-demo-synthetic' },
        { Key: 'auto-remediate', Value: 'true' },
        { Key: 'Auto-Remediate', Value: 'True' },
      ],
    });

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, dryRun: false, reason: 'revoked' });
    expect(revoked(send)).toHaveLength(1);
  });
});

const RANGE_EVENT = {
  caseId: 'case-demo-1',
  securityGroupId: 'sg-demo0001',
  protocol: 'tcp',
  fromPort: 0,
  toPort: 65535,
  cidr: '0.0.0.0/0',
};

function rangeRule(over: Record<string, unknown> = {}) {
  return {
    GroupId: 'sg-demo0001',
    IsEgress: false,
    IpProtocol: 'tcp',
    FromPort: 0,
    ToPort: 65535,
    CidrIpv4: '0.0.0.0/0',
    ...over,
  };
}

describe('close-open-port port ranges', () => {
  it('revokes tcp 0-65535 from 0.0.0.0/0', async () => {
    const { client, send } = fakeClient([
      rangeRule(),
      openRule(),
      rangeRule({ IsEgress: true }),
      rangeRule({ GroupId: 'sg-demo0002' }),
    ]);

    const result = await handleCloseOpenPort({ ...RANGE_EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: true,
      changed: true,
      dryRun: false,
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      protocol: 'tcp',
      fromPort: 0,
      toPort: 65535,
      cidr: '0.0.0.0/0',
      reason: 'revoked',
    });
    expect(result).not.toHaveProperty('port');
    const revoke = send.mock.calls[2]?.[0];
    expect(revoke).toBeInstanceOf(RevokeSecurityGroupIngressCommand);
    expect(revoke.input).toEqual({
      GroupId: 'sg-demo0001',
      IpPermissions: [
        {
          IpProtocol: 'tcp',
          FromPort: 0,
          ToPort: 65535,
          IpRanges: [{ CidrIp: '0.0.0.0/0' }],
        },
      ],
    });
    expect(revoke.input.IpPermissions[0]).not.toHaveProperty('UserIdGroupPairs');
    expect(revoke.input.IpPermissions[0]).not.toHaveProperty('Ipv6Ranges');
  });

  it('a dry run of a port range changes nothing', async () => {
    const { client, send } = fakeClient([rangeRule()]);

    const omitted = await handleCloseOpenPort(RANGE_EVENT, client);
    const explicit = await handleCloseOpenPort({ ...RANGE_EVENT, apply: false }, client);

    expect(omitted).toMatchObject({
      ok: true,
      changed: false,
      dryRun: true,
      reason: 'dry_run',
      fromPort: 0,
      toPort: 65535,
    });
    expect(explicit).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'dry_run' });
    expect(revoked(send)).toEqual([]);
  });

  it('revokes tcp 20-25 from a public CIDR because the range covers 22', async () => {
    const tags = [...GROUP_TAGS, { Key: 'public', Value: 'true' }];
    const { client, send } = fakeClient(
      [rangeRule({ FromPort: 20, ToPort: 25, CidrIpv4: '203.0.113.0/24' })],
      { tags },
    );

    const result = await handleCloseOpenPort(
      { ...RANGE_EVENT, fromPort: 20, toPort: 25, cidr: '203.0.113.0/24', apply: true },
      client,
    );

    expect(result).toMatchObject({
      ok: true,
      changed: true,
      dryRun: false,
      reason: 'revoked',
      protocol: 'tcp',
      fromPort: 20,
      toPort: 25,
      cidr: '203.0.113.0/24',
    });
    expect(send.mock.calls[2]?.[0].input.IpPermissions[0]).toEqual({
      IpProtocol: 'tcp',
      FromPort: 20,
      ToPort: 25,
      IpRanges: [{ CidrIp: '203.0.113.0/24' }],
    });
  });

  it('revokes udp 20-25 from a public CIDR', async () => {
    const { client, send } = fakeClient([
      rangeRule({ IpProtocol: 'udp', FromPort: 20, ToPort: 25, CidrIpv4: '198.51.100.0/24' }),
    ]);

    const result = await handleCloseOpenPort(
      {
        ...RANGE_EVENT,
        protocol: 'udp',
        fromPort: 20,
        toPort: 25,
        cidr: '198.51.100.0/24',
        apply: true,
      },
      client,
    );

    expect(result).toMatchObject({ ok: true, changed: true, reason: 'revoked', protocol: 'udp' });
    expect(send.mock.calls[2]?.[0].input.IpPermissions[0]).toMatchObject({
      IpProtocol: 'udp',
      FromPort: 20,
      ToPort: 25,
      IpRanges: [{ CidrIp: '198.51.100.0/24' }],
    });
  });

  it('tcp 8000-8100 covers 8080, so a public CIDR is revoked', async () => {
    const { client, send } = fakeClient(
      [rangeRule({ FromPort: 8000, ToPort: 8100, CidrIpv4: '203.0.113.0/24' })],
      { tags: [...GROUP_TAGS, { Key: 'public', Value: 'true' }] },
    );

    const result = await handleCloseOpenPort(
      { ...RANGE_EVENT, fromPort: 8000, toPort: 8100, cidr: '203.0.113.0/24', apply: true },
      client,
    );

    expect(result).toMatchObject({
      ok: true,
      changed: true,
      reason: 'revoked',
      fromPort: 8000,
      toPort: 8100,
    });
    expect(revoked(send)).toHaveLength(1);
  });

  it('a range covering no sensitive port follows the non-sensitive rule', async () => {
    const quiet = { FromPort: 10000, ToPort: 10010 };
    const event = { ...RANGE_EVENT, fromPort: 10000, toPort: 10010 };

    const publicCidr = fakeClient([rangeRule({ ...quiet, CidrIpv4: '203.0.113.0/24' })]);
    const publicCidrResult = await handleCloseOpenPort(
      { ...event, cidr: '203.0.113.0/24', apply: true },
      publicCidr.client,
    );
    expect(publicCidrResult).toMatchObject({
      ok: false,
      status: 'refused',
      reason: 'rule is not a finding under the port rule',
    });
    expect(revoked(publicCidr.send)).toEqual([]);

    const worldTagged = fakeClient([rangeRule(quiet)], {
      tags: [...GROUP_TAGS, { Key: 'public', Value: 'true' }],
    });
    const worldTaggedResult = await handleCloseOpenPort({ ...event, apply: true }, worldTagged.client);
    expect(worldTaggedResult).toMatchObject({
      ok: false,
      status: 'refused',
      reason: 'rule is not a finding under the port rule',
    });
    expect(revoked(worldTagged.send)).toEqual([]);

    const worldOpen = fakeClient([rangeRule(quiet)]);
    const worldOpenResult = await handleCloseOpenPort({ ...event, apply: true }, worldOpen.client);
    expect(worldOpenResult).toMatchObject({ ok: true, changed: true, reason: 'revoked' });
    expect(worldOpen.send.mock.calls[2]?.[0].input.IpPermissions[0]).toMatchObject({
      IpProtocol: 'tcp',
      FromPort: 10000,
      ToPort: 10010,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
  });

  it('revokes a ::/0 range', async () => {
    const rule = {
      GroupId: 'sg-demo0001',
      IsEgress: false,
      IpProtocol: 'tcp',
      FromPort: 0,
      ToPort: 65535,
      CidrIpv6: '::/0',
    };
    const { client, send } = fakeClient([rule]);

    const result = await handleCloseOpenPort({ ...RANGE_EVENT, cidr: '::/0', apply: true }, client);

    expect(result).toMatchObject({
      ok: true,
      changed: true,
      dryRun: false,
      reason: 'revoked',
      cidr: '::/0',
      fromPort: 0,
      toPort: 65535,
    });
    const permission = send.mock.calls[2]?.[0].input.IpPermissions[0];
    expect(permission).toEqual({
      IpProtocol: 'tcp',
      FromPort: 0,
      ToPort: 65535,
      Ipv6Ranges: [{ CidrIpv6: '::/0' }],
    });
    expect(permission).not.toHaveProperty('IpRanges');
    expect(permission).not.toHaveProperty('UserIdGroupPairs');
  });

  it('leaves a private CIDR range untouched', async () => {
    const { client, send } = fakeClient([
      rangeRule({ CidrIpv4: '10.0.0.0/8' }),
      rangeRule({ FromPort: 20, ToPort: 25, CidrIpv4: '10.1.0.0/16' }),
    ]);

    const wide = await handleCloseOpenPort({ ...RANGE_EVENT, cidr: '10.0.0.0/8', apply: true }, client);
    const ssh = await handleCloseOpenPort(
      { ...RANGE_EVENT, fromPort: 20, toPort: 25, cidr: '10.1.0.0/16', apply: true },
      client,
    );

    for (const result of [wide, ssh]) {
      expect(result).toMatchObject({
        ok: false,
        changed: false,
        status: 'refused',
        reason: 'rule is not a finding under the port rule',
      });
    }
    expect(revoked(send)).toEqual([]);
  });

  it('leaves a private IPv6 range untouched', async () => {
    const rule = {
      GroupId: 'sg-demo0001',
      IsEgress: false,
      IpProtocol: 'tcp',
      FromPort: 0,
      ToPort: 65535,
      CidrIpv6: 'fd00::/8',
    };
    const { client, send } = fakeClient([rule]);

    const result = await handleCloseOpenPort({ ...RANGE_EVENT, cidr: 'fd00::/8', apply: true }, client);

    expect(result).toMatchObject({
      ok: false,
      status: 'refused',
      reason: 'rule is not a finding under the port rule',
      cidr: 'fd00::/8',
    });
    expect(revoked(send)).toEqual([]);
  });

  it('revokes only the one rule with the same protocol, range, and CIDR', async () => {
    const exact = rangeRule();
    const { client, send } = fakeClient([
      rangeRule({ ToPort: 65534 }),
      rangeRule({ CidrIpv4: '203.0.113.0/24' }),
      rangeRule({ IpProtocol: 'udp' }),
      openRule(),
      rangeRule({ IsEgress: true }),
      {
        GroupId: 'sg-demo0001',
        IsEgress: false,
        IpProtocol: 'tcp',
        FromPort: 0,
        ToPort: 65535,
        CidrIpv6: '::/0',
      },
      {
        GroupId: 'sg-demo0001',
        IsEgress: false,
        IpProtocol: 'tcp',
        FromPort: 0,
        ToPort: 65535,
        PrefixListId: 'pl-demo0001',
      },
      exact,
    ]);

    const result = await handleCloseOpenPort({ ...RANGE_EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, reason: 'revoked' });
    expect(revoked(send)).toHaveLength(1);
    expect(send.mock.calls[2]?.[0].input.IpPermissions).toEqual([
      {
        IpProtocol: 'tcp',
        FromPort: 0,
        ToPort: 65535,
        IpRanges: [{ CidrIp: '0.0.0.0/0' }],
      },
    ]);
  });

  it('does not revoke a rule with a different range or CIDR', async () => {
    const { client, send } = fakeClient([
      rangeRule({ ToPort: 65534 }),
      rangeRule({ CidrIpv4: '10.0.0.0/8' }),
      openRule(),
    ]);

    const dry = await handleCloseOpenPort(RANGE_EVENT, client);
    const applied = await handleCloseOpenPort({ ...RANGE_EVENT, apply: true }, client);

    const refused = {
      ok: false,
      changed: false,
      status: 'refused',
      reason: 'no ingress rule matches this protocol, port range, and CIDR',
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      protocol: 'tcp',
      fromPort: 0,
      toPort: 65535,
      cidr: '0.0.0.0/0',
    };
    expect(dry).toEqual(refused);
    expect(applied).toEqual(refused);
    expect(revoked(send)).toEqual([]);
  });

  it('refuses when more than one range rule matches', async () => {
    const { client, send } = fakeClient([rangeRule(), rangeRule({ SecurityGroupRuleId: 'sgr-demo0002' })]);

    const result = await handleCloseOpenPort({ ...RANGE_EVENT, apply: true }, client);

    expect(result).toMatchObject({
      ok: false,
      status: 'refused',
      reason: 'more than one ingress rule matches this protocol, port range, and CIDR',
    });
    expect(revoked(send)).toEqual([]);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('the old port payload still revokes one matching port', async () => {
    const { client, send } = fakeClient([openRule(), rangeRule()]);

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({
      ok: true,
      changed: true,
      reason: 'revoked',
      protocol: 'tcp',
      port: 22,
      cidr: '0.0.0.0/0',
    });
    expect(result).not.toHaveProperty('fromPort');
    expect(send.mock.calls[2]?.[0].input.IpPermissions[0]).toEqual({
      IpProtocol: 'tcp',
      FromPort: 22,
      ToPort: 22,
      IpRanges: [{ CidrIp: '0.0.0.0/0' }],
    });
  });

  it('the old port payload does not revoke a wider range', async () => {
    const { client, send } = fakeClient([rangeRule()]);

    const result = await handleCloseOpenPort({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: false, reason: 'already_closed', port: 22 });
    expect(revoked(send)).toEqual([]);
  });

  it('never revokes a security-group-sourced rule', async () => {
    const sourced = {
      GroupId: 'sg-demo0001',
      IsEgress: false,
      IpProtocol: 'tcp',
      FromPort: 0,
      ToPort: 65535,
      ReferencedGroupInfo: { GroupId: 'sg-demo0002' },
    };
    const sourcedWithCidr = {
      ...sourced,
      CidrIpv4: '0.0.0.0/0',
    };

    const onlySourced = fakeClient([sourced, sourcedWithCidr]);
    const missed = await handleCloseOpenPort({ ...RANGE_EVENT, apply: true }, onlySourced.client);
    expect(missed).toMatchObject({
      ok: false,
      status: 'refused',
      reason: 'no ingress rule matches this protocol, port range, and CIDR',
    });
    expect(revoked(onlySourced.send)).toEqual([]);

    const alongside = fakeClient([sourced, sourcedWithCidr, rangeRule()]);
    const revokedOne = await handleCloseOpenPort({ ...RANGE_EVENT, apply: true }, alongside.client);
    expect(revokedOne).toMatchObject({ ok: true, changed: true, reason: 'revoked' });
    expect(alongside.send.mock.calls[2]?.[0].input.IpPermissions).toEqual([
      {
        IpProtocol: 'tcp',
        FromPort: 0,
        ToPort: 65535,
        IpRanges: [{ CidrIp: '0.0.0.0/0' }],
      },
    ]);
    expect(JSON.stringify(alongside.send.mock.calls[2]?.[0].input)).not.toContain('sg-demo0002');
  });

  it.each([
    ['fromPort above toPort', { ...RANGE_EVENT, fromPort: 30, toPort: 10 }],
    ['a fractional fromPort', { ...RANGE_EVENT, fromPort: 1.5 }],
    ['a fromPort past the end', { ...RANGE_EVENT, fromPort: 65536, toPort: 65536 }],
    ['a negative toPort', { ...RANGE_EVENT, fromPort: -1, toPort: 22 }],
    ['a string fromPort', { ...RANGE_EVENT, fromPort: '0' }],
    [
      'only fromPort',
      {
        caseId: 'case-demo-1',
        securityGroupId: 'sg-demo0001',
        protocol: 'tcp',
        fromPort: 0,
        cidr: '0.0.0.0/0',
      },
    ],
    ['port and a range together', { ...EVENT, fromPort: 0, toPort: 22 }],
    ['protocol -1 with a range', { ...ALL_EVENT, fromPort: 0, toPort: 65535 }],
    ['a bad IPv6 CIDR', { ...RANGE_EVENT, cidr: 'gggg::/64' }],
    ['a CIDR with no prefix', { ...RANGE_EVENT, cidr: '2001:db8::' }],
    ['protocol icmp', { ...RANGE_EVENT, protocol: 'icmp' }],
  ])('refuses %s and does not call AWS', async (_label, event) => {
    const { client, send } = fakeClient([rangeRule()]);

    const result = await handleCloseOpenPort(event, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidInput' });
    expect(send).not.toHaveBeenCalled();
  });
});
