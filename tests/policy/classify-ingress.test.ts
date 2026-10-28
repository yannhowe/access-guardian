/**
 * classifyIngress is a pure check. These tests do not call AWS or Grok.
 */
import { describe, expect, it } from 'vitest';
import {
  cidrFamily,
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

describe('sensitive ports outside private space', () => {
  it('22 from 0.0.0.0/8 is a finding, including on public=true', () => {
    const ports = { fromPort: 22, toPort: 22, ipv4Cidrs: ['0.0.0.0/8'], ipv6Cidrs: [] as string[] };
    expect(classifyIngress(rule(ports), PUBLIC_TAG)).toBe('finding');
    expect(classifyIngress(rule(ports), [])).toBe('finding');
  });

  it('3389 from 203.0.113.0/24 is a finding', () => {
    expect(
      classifyIngress(
        rule({ fromPort: 3389, toPort: 3389, ipv4Cidrs: ['203.0.113.0/24'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
  });

  it('22 from 10.0.0.0/16 is ok', () => {
    expect(
      classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: ['10.0.0.0/16'], ipv6Cidrs: [] }), PUBLIC_TAG),
    ).toBe('ok');
  });

  it('443 from 0.0.0.0/8 is ok', () => {
    expect(classifyIngress(rule({ fromPort: 443, toPort: 443, ipv4Cidrs: ['0.0.0.0/8'], ipv6Cidrs: [] }), [])).toBe(
      'ok',
    );
  });

  it.each([
    ['172.32.0.0/16', ['172.32.0.0/16'], []],
    ['8.0.0.0/4', ['8.0.0.0/4'], []],
    ['10.0.0.0/7', ['10.0.0.0/7'], []],
    ['172.0.0.0/11', ['172.0.0.0/11'], []],
    ['192.168.0.0/15', ['192.168.0.0/15'], []],
    ['100.0.0.0/9', ['100.0.0.0/9'], []],
    ['9.0.0.0/8', ['9.0.0.0/8'], []],
    ['11.0.0.0/8', ['11.0.0.0/8'], []],
    ['172.15.0.0/16', ['172.15.0.0/16'], []],
    ['192.169.0.0/16', ['192.169.0.0/16'], []],
    ['100.128.0.0/16', ['100.128.0.0/16'], []],
  ])('22 from %s is a finding', (_label, ipv4Cidrs, ipv6Cidrs) => {
    expect(classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs, ipv6Cidrs }), PUBLIC_TAG)).toBe('finding');
  });

  it('22 from 2001:db8::/32 is a finding', () => {
    expect(
      classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: [], ipv6Cidrs: ['2001:db8::/32'] }), PUBLIC_TAG),
    ).toBe('finding');
  });

  it.each([
    ['fe80::/10', 'fe80::/10'],
    ['fc00::/6', 'fc00::/6'],
    ['::/0', '::/0'],
  ])('22 from %s is a finding', (_label, cidr) => {
    expect(classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: [], ipv6Cidrs: [cidr] }), PUBLIC_TAG)).toBe(
      'finding',
    );
  });

  it('22 from fd00::/8 is ok', () => {
    expect(
      classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: [], ipv6Cidrs: ['fd00::/8'] }), PUBLIC_TAG),
    ).toBe('ok');
  });

  it.each([
    ['10.0.0.0/8', ['10.0.0.0/8'], []],
    ['172.16.0.0/12', ['172.16.0.0/12'], []],
    ['172.31.255.255/32', ['172.31.255.255/32'], []],
    ['192.168.1.0/24', ['192.168.1.0/24'], []],
    ['100.64.0.0/10', ['100.64.0.0/10'], []],
    ['100.127.255.255/32', ['100.127.255.255/32'], []],
  ])('22 from %s is ok', (_label, ipv4Cidrs, ipv6Cidrs) => {
    expect(classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs, ipv6Cidrs }), PUBLIC_TAG)).toBe('ok');
  });

  it.each([
    ['fc00::/7', 'fc00::/7'],
    ['fd00::/8', 'fd00::/8'],
    ['FD00::/8', 'FD00::/8'],
  ])('22 from %s is ok', (_label, cidr) => {
    expect(classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: [], ipv6Cidrs: [cidr] }), [])).toBe('ok');
  });

  it('22 is a finding when any source range is outside private space', () => {
    expect(
      classifyIngress(
        rule({
          fromPort: 22,
          toPort: 22,
          ipv4Cidrs: ['10.0.0.0/16'],
          ipv6Cidrs: ['fd00::/8', '2001:db8::/32'],
        }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
  });

  it('protocol -1 from 0.0.0.0/8 is a finding on public=true', () => {
    expect(
      classifyIngress(
        rule({ protocol: '-1', fromPort: null, toPort: null, ipv4Cidrs: ['0.0.0.0/8'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
  });

  it('protocol -1 from 10.0.0.0/16 is ok', () => {
    expect(
      classifyIngress(
        rule({ protocol: '-1', fromPort: null, toPort: null, ipv4Cidrs: ['10.0.0.0/16'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('ok');
  });

  it.each(['not-a-cidr', '10.0.0.0/33', '10.0.0.0', '::/129', '', '010.0.0.0/8'])(
    'malformed CIDR %j on port 22 is a finding',
    (cidr) => {
      expect(
        classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: [cidr], ipv6Cidrs: [] }), PUBLIC_TAG),
      ).toBe('finding');
    },
  );

  it('a malformed IPv6 CIDR on port 22 is a finding', () => {
    expect(
      classifyIngress(rule({ fromPort: 22, toPort: 22, ipv4Cidrs: [], ipv6Cidrs: ['gggg::/64'] }), PUBLIC_TAG),
    ).toBe('finding');
  });

  it('443 from a malformed CIDR stays ok', () => {
    expect(classifyIngress(rule({ fromPort: 443, toPort: 443, ipv4Cidrs: ['not-a-cidr'], ipv6Cidrs: [] }), [])).toBe(
      'ok',
    );
  });
});

describe('tcp and udp port ranges', () => {
  it('tcp 20-25 from a public CIDR is a finding because it covers 22', () => {
    expect(
      classifyIngress(
        rule({ protocol: 'tcp', fromPort: 20, toPort: 25, ipv4Cidrs: ['203.0.113.0/24'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
  });

  it('udp 20-25 from a public CIDR is a finding', () => {
    expect(
      classifyIngress(
        rule({ protocol: 'udp', fromPort: 20, toPort: 25, ipv4Cidrs: ['203.0.113.0/24'], ipv6Cidrs: [] }),
        [],
      ),
    ).toBe('finding');
  });

  it('tcp 20-25 from a private CIDR is ok', () => {
    expect(
      classifyIngress(
        rule({ fromPort: 20, toPort: 25, ipv4Cidrs: ['10.1.0.0/16'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('ok');
  });

  it('tcp 20-25 treats ::/0 as world-open and other non-private IPv6 as outside private space', () => {
    expect(
      classifyIngress(rule({ fromPort: 20, toPort: 25, ipv4Cidrs: [], ipv6Cidrs: ['::/0'] }), PUBLIC_TAG),
    ).toBe('finding');
    expect(
      classifyIngress(rule({ fromPort: 20, toPort: 25, ipv4Cidrs: [], ipv6Cidrs: ['2001:db8::/32'] }), []),
    ).toBe('finding');
    expect(
      classifyIngress(rule({ fromPort: 20, toPort: 25, ipv4Cidrs: [], ipv6Cidrs: ['fd00::/8'] }), PUBLIC_TAG),
    ).toBe('ok');
  });

  it('tcp 8000-8100 covers sensitive port 8080, so a public CIDR is a finding', () => {
    expect(SENSITIVE_PORTS).toContain(8080);
    expect(
      classifyIngress(
        rule({ fromPort: 8000, toPort: 8100, ipv4Cidrs: ['203.0.113.0/24'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
    expect(
      classifyIngress(
        rule({ fromPort: 8000, toPort: 8100, ipv4Cidrs: ['0.0.0.0/0'], ipv6Cidrs: [] }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
  });

  it('a range that covers no sensitive port follows the non-sensitive rule', () => {
    expect(SENSITIVE_PORTS.filter((port) => port >= 10000 && port <= 10010)).toEqual([]);
    const quiet = { fromPort: 10000, toPort: 10010 };
    expect(classifyIngress(rule({ ...quiet, ipv4Cidrs: ['203.0.113.0/24'], ipv6Cidrs: [] }), [])).toBe('ok');
    expect(classifyIngress(rule({ ...quiet, ipv4Cidrs: ['0.0.0.0/0'], ipv6Cidrs: [] }), PUBLIC_TAG)).toBe('ok');
    expect(classifyIngress(rule({ ...quiet, ipv4Cidrs: ['0.0.0.0/0'], ipv6Cidrs: [] }), [])).toBe('finding');
    expect(classifyIngress(rule({ ...quiet, ipv4Cidrs: [], ipv6Cidrs: ['::/0'] }), [])).toBe('finding');
    expect(classifyIngress(rule({ ...quiet, ipv4Cidrs: [], ipv6Cidrs: ['::/0'] }), PUBLIC_TAG)).toBe('ok');
    expect(classifyIngress(rule({ ...quiet, ipv4Cidrs: [], ipv6Cidrs: ['2001:db8::/32'] }), [])).toBe('ok');
  });

  it('protocol -1 stays a finding from a public CIDR when the ports would not be sensitive', () => {
    expect(
      classifyIngress(
        rule({
          protocol: '-1',
          fromPort: 10000,
          toPort: 10010,
          ipv4Cidrs: ['203.0.113.0/24'],
          ipv6Cidrs: [],
        }),
        PUBLIC_TAG,
      ),
    ).toBe('finding');
  });
});

describe('cidrFamily', () => {
  it('accepts one IPv4 or IPv6 CIDR and rejects anything else', () => {
    expect(cidrFamily('0.0.0.0/0')).toBe('ipv4');
    expect(cidrFamily('203.0.113.0/24')).toBe('ipv4');
    expect(cidrFamily('10.0.0.0/8')).toBe('ipv4');
    expect(cidrFamily('::/0')).toBe('ipv6');
    expect(cidrFamily('2001:db8::/32')).toBe('ipv6');
    expect(cidrFamily('fd00::/8')).toBe('ipv6');
    expect(cidrFamily('FD00::/8')).toBe('ipv6');
    expect(cidrFamily('any')).toBeUndefined();
    expect(cidrFamily('10.0.0.0/33')).toBeUndefined();
    expect(cidrFamily('010.0.0.0/8')).toBeUndefined();
    expect(cidrFamily('::/129')).toBeUndefined();
    expect(cidrFamily('gggg::/64')).toBeUndefined();
    expect(cidrFamily('2001:db8::')).toBeUndefined();
    expect(cidrFamily('')).toBeUndefined();
  });
});
