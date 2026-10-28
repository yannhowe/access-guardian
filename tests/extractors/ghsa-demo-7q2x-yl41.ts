/**
 * Synthetic advisory for case AG-20261028-03.
 * Dependency finding: dep:vulnerable_package.
 * The prose is demo data. It is not a real vendor advisory.
 */

export const GHSA_DEMO_ID = 'GHSA-demo-7q2x-yl41';
export const GHSA_DEMO_CASE = 'AG-20261028-03';
export const GHSA_DEMO_PACKAGE = '@acme-demo/yaml-lite';
export const GHSA_DEMO_FIXED = '2.4.3';
export const GHSA_DEMO_RANGE = '1.x <=1.9.8; >=2.0.0 <2.4.3';
export const GHSA_DEMO_WORKAROUND =
  "if you can't upgrade, pass { maxAliasCount: 50 } to parseDocument().";

export const GHSA_DEMO_PROSE = [
  `${GHSA_DEMO_ID}: Uncontrolled recursion in ${GHSA_DEMO_PACKAGE}`,
  '',
  'Severity: High (CVSS 7.5)',
  '',
  'A denial of service issue was found in @acme-demo/yaml-lite. When untrusted input contains deeply nested anchors and aliases, parseDocument() and loadAll() recurse without a depth limit and can exhaust the stack, crashing the process. The streaming parseStream() API is not affected because it already enforces a depth limit.',
  '',
  'Versions from 2.0.0 up to but not including 2.4.3 are affected. The 1.x line is also affected through 1.9.8, and no 1.x fix is planned. The issue is fixed in 2.4.3, which adds a default maxDepth of 100.',
  '',
  `Workaround: ${GHSA_DEMO_WORKAROUND}`,
].join('\n');

/** Trusted alert held by code. This object is not sent to the model. */
export const GHSA_DEMO_ALERT = {
  affectedRange: GHSA_DEMO_RANGE,
  patchedVersion: GHSA_DEMO_FIXED,
};

/**
 * Model payload for the happy path.
 * The 2.x range is listed first. Code sorts the canonical text.
 */
export const GHSA_DEMO_MODEL = {
  packageName: GHSA_DEMO_PACKAGE,
  vulnerableFunctions: ['parseDocument', 'loadAll'],
  affectedRanges: [
    {
      minInclusive: '2.0.0',
      maxExclusive: '2.4.3',
      maxInclusive: null,
      majorLine: null,
    },
    {
      minInclusive: null,
      maxExclusive: null,
      maxInclusive: '1.9.8',
      majorLine: 1,
    },
  ],
  fixedVersion: GHSA_DEMO_FIXED,
  workaround: GHSA_DEMO_WORKAROUND,
};
