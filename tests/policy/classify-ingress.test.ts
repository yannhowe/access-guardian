/**
 * classifyIngress is a pure check. These tests do not call AWS or Grok.
 */
import { describe, expect, it } from 'vitest';
import {
  classifyIngress,
  type IngressRule,
  type IngressVerdict,
  type SecurityGroupTag,
} from '../../src/policy/classify-ingress.js';
import { SENSITIVE_PORTS } from '../../src/policy/sensitive-ports.js';

const PUBLIC_TAG: readonly SecurityGroupTag[] = [{ key: 'public', value: 'true' }];

const OTHER_TAGS: readonly SecurityGroupTag[] = [
  { key: 'purpose', value: 'ag-demo-synthetic' },
  { key: 'auto-remediate', value: 'true' },
];

function rule(over: Partial<IngressRule> = {}): IngressRule {
  return {
    protocol: 'tcp',
    fromPort: 443,
    toPort: 443,
    ipv4Cidrs: ['0.0.0.0/0'],
    ipv6Cidrs: [],
    ...over,
  };
}

describe('sensitive ports', () => {
  it('lists every expanded range value', () => {
    expect(SENSITIVE_PORTS).toEqual([
      20, 21, 22, 23, 53, 69, 111, 135, 137, 138, 139, 161, 162, 389, 445, 636, 1433, 1521, 2049, 2181, 2375, 2376,
      2379, 2380, 3306, 3389, 5432, 5672, 5900, 5901, 5902, 5903, 5984, 5985, 5986, 6379, 6443, 7000, 7001, 8080,
      8200, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 10250, 11211, 15672, 27017, 27018,
    ]);
    for (const port of [137, 138, 139, 5900, 5901, 5902, 5903]) {
      expect(SENSITIVE_PORTS).toContain(port);
    }
  });
});

describe('classifyIngress', () => {
  it('public=true never excuses a sensitive port', () => {
    const tags: readonly SecurityGroupTag[] = [{ key: 'public', value: 'true' }];
    expect(classifyIngress(rule({ fromPort: 22, toPort: 22 }), tags)).toBe('finding');
    expect(classifyIngress(rule({ fromPort: 3389, toPort: 3389 }), tags)).toBe('finding');
    expect(classifyIngress(rule({ fromPort: 443, toPort: 443 }), tags)).toBe('ok');
  });

  it('22 tagged gives finding', () => {
    const verdict = classifyIngress(rule({ fromPort: 22, toPort: 22 }), [...OTHER_TAGS, ...PUBLIC_TAG]);
    expect(verdict).toBe('finding');
  });

  it('443 untagged gives finding', () => {
    expect(classifyIngress(rule({ fromPort: 443, toPort: 443 }), OTHER_TAGS)).toBe('finding');
  });

  it('443 tagged gives ok', () => {
    expect(classifyIngress(rule({ fromPort: 443, toPort: 443 }), [...OTHER_TAGS, ...PUBLIC_TAG])).toBe('ok');
  });

  it('80 untagged gives finding', () => {
    expect(classifyIngress(rule({ fromPort: 80, toPort: 80 }), OTHER_TAGS)).toBe('finding');
  });

  it('80 tagged gives ok', () => {
    expect(classifyIngress(rule({ fromPort: 80, toPort: 80 }), PUBLIC_TAG)).toBe('ok');
  });

  it('8080 tagged gives finding', () => {
    expect(classifyIngress(rule({ fromPort: 8080, toPort: 8080 }), [...OTHER_TAGS, ...PUBLIC_TAG])).toBe('finding');
  });

  it('0-65535 gives finding', () => {
    const verdict = classifyIngress(rule({ fromPort: 0, toPort: 65535 }), [...OTHER_TAGS, ...PUBLIC_TAG]);
    expect(verdict).toBe('finding');
  });

  it('protocol -1 gives finding', () => {
    const verdict = classifyIngress(
      rule({ protocol: '-1', fromPort: 80, toPort: 80 }),
      [...OTHER_TAGS, ...PUBLIC_TAG],
    );
    expect(verdict).toBe('finding');
  });

  it('a private CIDR such as 10.0.0.0/8 gives ok', () => {
    const verdict = classifyIngress(
      rule({ fromPort: 22, toPort: 22, ipv4Cidrs: ['10.0.0.0/8'], ipv6Cidrs: [] }),
      PUBLIC_TAG,
    );
    expect(verdict).toBe('ok');
  });

  it('::/0 is handled the same as 0.0.0.0/0', () => {
    const samples: Array<{
      fromPort: number;
      toPort: number;
      tags: readonly SecurityGroupTag[];
      verdict: IngressVerdict;
    }> = [
      { fromPort: 22, toPort: 22, tags: [...OTHER_TAGS, ...PUBLIC_TAG], verdict: 'finding' },
      { fromPort: 443, toPort: 443, tags: OTHER_TAGS, verdict: 'finding' },
      { fromPort: 443, toPort: 443, tags: [...OTHER_TAGS, ...PUBLIC_TAG], verdict: 'ok' },
      { fromPort: 8080, toPort: 8080, tags: PUBLIC_TAG, verdict: 'finding' },
    ];

    for (const sample of samples) {
      const ipv4 = classifyIngress(
        rule({
          fromPort: sample.fromPort,
          toPort: sample.toPort,
          ipv4Cidrs: ['0.0.0.0/0'],
          ipv6Cidrs: [],
        }),
        sample.tags,
      );
      const ipv6 = classifyIngress(
        rule({
          fromPort: sample.fromPort,
          toPort: sample.toPort,
          ipv4Cidrs: [],
          ipv6Cidrs: ['::/0'],
        }),
        sample.tags,
      );
      expect(ipv4).toBe(sample.verdict);
      expect(ipv6).toBe(ipv4);
    }
  });

  it('is a finding when any CIDR is world-open', () => {
    const verdict = classifyIngress(
      rule({
        fromPort: 443,
        toPort: 443,
        ipv4Cidrs: ['10.0.0.0/8', '0.0.0.0/0'],
        ipv6Cidrs: ['2001:db8::/32'],
      }),
      [],
    );
    expect(verdict).toBe('finding');
  });

  it.each([
    ['a missing fromPort', { fromPort: null, toPort: 443 }],
    ['a missing toPort', { fromPort: 443, toPort: undefined }],
    ['a fractional port', { fromPort: 443.5, toPort: 443.5 }],
    ['a port below 0', { fromPort: -1, toPort: -1 }],
    ['a port above 65535', { fromPort: 65536, toPort: 65536 }],
    ['an inverted range', { fromPort: 500, toPort: 400 }],
  ])('%s gives finding', (_label, ports) => {
    expect(classifyIngress(rule(ports), PUBLIC_TAG)).toBe('finding');
  });

  it.each([
    ['intended-public', 'true'],
    ['Intended-public', 'true'],
    ['public', 'True'],
    ['public', 'TRUE'],
    ['PUBLIC', 'true'],
    ['INTENDED-PUBLIC', 'true'],
  ])('tag %s=%s on 443 gives finding', (key, value) => {
    expect(classifyIngress(rule({ fromPort: 443, toPort: 443 }), [{ key, value }])).toBe('finding');
  });
});
