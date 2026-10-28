/**
 * JSON schema for one advisory extraction.
 * The schema is the request. `isAdvisoryFacts` is the check this code trusts.
 */
import type { JsonSchema } from '../../grok/client.js';
import {
  IDENTIFIER_PATTERN,
  IDENTIFIER_RE,
  MAX_FUNCTIONS,
  MAX_RANGES,
  MAX_WORKAROUND,
  PACKAGE_PATTERN,
  PACKAGE_RE,
  VERSION_PATTERN,
  VERSION_RE,
} from './patterns.js';
import { isWellFormedRange } from './ranges.js';
import type { AdvisoryFacts } from './types.js';

const FACT_KEYS = ['packageName', 'vulnerableFunctions', 'affectedRanges', 'fixedVersion', 'workaround'] as const;

const versionOrNull: JsonSchema = {
  anyOf: [
    { type: 'string', pattern: VERSION_PATTERN, maxLength: 23 },
    { type: 'null' },
  ],
};

const majorOrNull: JsonSchema = {
  anyOf: [
    { type: 'integer', minimum: 0, maximum: 999 },
    { type: 'null' },
  ],
};

export const ADVISORY_SCHEMA_NAME = 'advisory_facts';

export const ADVISORY_SCHEMA: JsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: [...FACT_KEYS],
  properties: {
    packageName: {
      type: 'string',
      pattern: PACKAGE_PATTERN,
      maxLength: 124,
    },
    vulnerableFunctions: {
      type: 'array',
      maxItems: MAX_FUNCTIONS,
      items: {
        type: 'string',
        pattern: IDENTIFIER_PATTERN,
        maxLength: 81,
      },
    },
    affectedRanges: {
      type: 'array',
      minItems: 1,
      maxItems: MAX_RANGES,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['minInclusive', 'maxExclusive', 'maxInclusive', 'majorLine'],
        properties: {
          minInclusive: versionOrNull,
          maxExclusive: versionOrNull,
          maxInclusive: versionOrNull,
          majorLine: majorOrNull,
        },
      },
    },
    fixedVersion: {
      type: 'string',
      pattern: VERSION_PATTERN,
      maxLength: 23,
    },
    workaround: {
      anyOf: [
        { type: 'string', minLength: 1, maxLength: MAX_WORKAROUND },
        { type: 'null' },
      ],
    },
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  if (actual.length !== keys.length) {
    return false;
  }
  return keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isWorkaround(value: unknown): value is string | null {
  if (value === null) {
    return true;
  }
  if (typeof value !== 'string') {
    return false;
  }
  if (value.length < 1 || value.length > MAX_WORKAROUND) {
    return false;
  }
  if (value !== value.trim()) {
    return false;
  }
  return !value.includes('\n') && !value.includes('\r');
}

/** True only for a complete advisory object. A miss is not filled in. */
export function isAdvisoryFacts(value: unknown): value is AdvisoryFacts {
  if (!isRecord(value) || !hasExactKeys(value, FACT_KEYS)) {
    return false;
  }
  if (typeof value.packageName !== 'string' || !PACKAGE_RE.test(value.packageName)) {
    return false;
  }
  if (typeof value.fixedVersion !== 'string' || !VERSION_RE.test(value.fixedVersion)) {
    return false;
  }
  if (!isWorkaround(value.workaround)) {
    return false;
  }
  if (!Array.isArray(value.vulnerableFunctions) || value.vulnerableFunctions.length > MAX_FUNCTIONS) {
    return false;
  }

  const seen = new Set<string>();
  for (const name of value.vulnerableFunctions) {
    if (typeof name !== 'string' || !IDENTIFIER_RE.test(name) || seen.has(name)) {
      return false;
    }
    seen.add(name);
  }

  if (!Array.isArray(value.affectedRanges)) {
    return false;
  }
  if (value.affectedRanges.length === 0 || value.affectedRanges.length > MAX_RANGES) {
    return false;
  }
  for (const range of value.affectedRanges) {
    if (!isWellFormedRange(range)) {
      return false;
    }
  }

  return true;
}
