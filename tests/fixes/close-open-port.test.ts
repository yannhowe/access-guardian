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

  it('refuses a non-world all-traffic rule through the same not-a-finding path', async () => {
    const { client, send } = fakeClient([allTrafficRule({ CidrIpv4: '192.0.2.8/32' })]);

    const result = await handleCloseOpenPort({ ...ALL_EVENT, cidr: '192.0.2.8/32', apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      status: 'refused',
      reason: 'rule is not a finding under the port rule',
      action: ACTION,
      caseId: 'case-demo-1',
      securityGroupId: 'sg-demo0001',
      protocol: '-1',
      cidr: '192.0.2.8/32',
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
