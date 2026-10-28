/**
 * Tests for the starter fix. The AWS client is a fake. These tests do not call AWS.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ALLOWED_FIXES } from '../../src/fixes/allow-list.js';
import {
  ACTION,
  IAM_ACTIONS,
  actionMatchesAllowList,
  closeOpenPort,
  type SecurityGroupClient,
} from '../../src/fixes/close-open-port.js';
import { registryKeysMatchAllowList } from '../../src/fixes/registry.js';

const RULE = {
  securityGroupId: 'sg-demo0001',
  protocol: 'tcp',
  port: 22,
  cidr: '0.0.0.0/0',
};

function fakeClient(impl?: () => Promise<unknown>): {
  client: SecurityGroupClient;
  send: ReturnType<typeof vi.fn>;
} {
  const send = vi.fn(impl ?? (async () => ({})));
  return { client: { send }, send };
}

beforeEach(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('this test must not call fetch');
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('closeOpenPort', () => {
  it('uses the one allow-listed action', () => {
    expect(ACTION).toBe('RevokeSecurityGroupIngress');
    expect(ACTION).toBe(ALLOWED_FIXES['close-open-port'].action);
    expect(actionMatchesAllowList).toBe(true);
    expect(registryKeysMatchAllowList).toBe(true);
    expect(IAM_ACTIONS).toEqual(['ec2:RevokeSecurityGroupIngress']);
  });

  it('returns the revoke plan and does not call AWS by default', async () => {
    const { client, send } = fakeClient();

    const result = await closeOpenPort(RULE, client);

    expect(result).toEqual({
      ok: true,
      applied: false,
      action: ACTION,
      rule: RULE,
      command: {
        action: 'RevokeSecurityGroupIngress',
        input: {
          GroupId: 'sg-demo0001',
          IpPermissions: [
            {
              IpProtocol: 'tcp',
              FromPort: 22,
              ToPort: 22,
              IpRanges: [{ CidrIp: '0.0.0.0/0' }],
            },
          ],
        },
      },
    });
    expect(send).not.toHaveBeenCalled();
  });

  it('does not call AWS when apply is false', async () => {
    const { client, send } = fakeClient();

    const result = await closeOpenPort(RULE, client, { apply: false });

    expect(result.ok && result.applied).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('does not treat apply on the input object as the flag', async () => {
    const { client, send } = fakeClient();
    const input = { ...RULE, apply: true };

    const result = await closeOpenPort(input, client);

    expect(result.ok && result.applied).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('sends exactly one revoke when apply is true', async () => {
    const { client, send } = fakeClient();

    const result = await closeOpenPort(RULE, client, { apply: true });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.applied).toBe(true);
    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith(result.command);
    expect(result.command.action).toBe(ACTION);
    expect(result.command.input.IpPermissions).toHaveLength(1);
  });

  it('revokes the given protocol, port, and CIDR', async () => {
    const { client, send } = fakeClient();
    const input = {
      securityGroupId: 'sg-demo0001',
      protocol: 'udp',
      port: 53,
      cidr: '10.0.0.0/8',
    };

    const result = await closeOpenPort(input, client, { apply: true });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.command.input).toEqual({
      GroupId: 'sg-demo0001',
      IpPermissions: [
        {
          IpProtocol: 'udp',
          FromPort: 53,
          ToPort: 53,
          IpRanges: [{ CidrIp: '10.0.0.0/8' }],
        },
      ],
    });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('ignores a port range and keeps the single port', async () => {
    const { client } = fakeClient();
    const input = { ...RULE, fromPort: 22, toPort: 80 };

    const result = await closeOpenPort(input, client);

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.command.input.IpPermissions[0]).toMatchObject({
      FromPort: 22,
      ToPort: 22,
    });
  });

  it.each([
    ['a short group id', { ...RULE, securityGroupId: 'sg-short' }],
    ['an uppercase group id', { ...RULE, securityGroupId: 'SG-DEMO0001' }],
    ['a missing group id', { ...RULE, securityGroupId: '' }],
    ['TCP in the wrong case', { ...RULE, protocol: 'TCP' }],
    ['icmp', { ...RULE, protocol: 'icmp' }],
    ['a fractional port', { ...RULE, port: 22.5 }],
    ['a port past the end', { ...RULE, port: 65536 }],
    ['a negative port', { ...RULE, port: -1 }],
    ['a string port', { ...RULE, port: '22' }],
    ['a CIDR with no prefix', { ...RULE, cidr: '0.0.0.0' }],
    ['a prefix past 32', { ...RULE, cidr: '10.0.0.0/33' }],
    ['an octet past 255', { ...RULE, cidr: '10.0.0.256/32' }],
    ['ipv6', { ...RULE, cidr: '::/0' }],
    ['the word any', { ...RULE, cidr: 'any' }],
    ['null', null],
    ['a string', 'open port 22'],
  ])('refuses %s and does not call AWS', async (_label, input) => {
    const { client, send } = fakeClient();

    const result = await closeOpenPort(input, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'invalid_input' });
    expect(send).not.toHaveBeenCalled();
  });

  it('accepts port 0 and port 65535 on a dry-run', async () => {
    const { client, send } = fakeClient();

    const low = await closeOpenPort({ ...RULE, port: 0 }, client);
    const high = await closeOpenPort({ ...RULE, port: 65535, cidr: '192.0.2.10/32' }, client);

    expect(low.ok && low.rule.port).toBe(0);
    expect(high.ok && high.rule.port).toBe(65535);
    expect(send).not.toHaveBeenCalled();
  });

  it('returns aws_error when the client throws and hides the error text', async () => {
    const { client, send } = fakeClient(async () => {
      throw new Error('secret-account-detail');
    });

    const result = await closeOpenPort(RULE, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'aws_error' });
    expect(JSON.stringify(result)).not.toContain('secret-account-detail');
    expect(send).toHaveBeenCalledTimes(1);
  });
});
