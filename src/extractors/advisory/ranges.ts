/**
 * Version arithmetic for advisory ranges.
 * This file does not call Grok. A version it cannot read is undefined, not a guess.
 */
import { MAX_RANGES, VERSION_RE } from './patterns.js';
import type { AffectedRange } from './types.js';

const RANGE_KEYS = ['minInclusive', 'maxExclusive', 'maxInclusive', 'majorLine'] as const;

type SemVer = {
  major: number;
  minor: number;
  patch: number;
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

function isVersionOrNull(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && VERSION_RE.test(value));
}

function isMajorOrNull(value: unknown): value is number | null {
  return (
    value === null ||
    (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 999)
  );
}

/** True when the object is one range with exactly one lower bound and one upper bound. */
export function isWellFormedRange(value: unknown): value is AffectedRange {
  if (!isRecord(value) || !hasExactKeys(value, RANGE_KEYS)) {
    return false;
  }
  if (!isVersionOrNull(value.minInclusive) || !isVersionOrNull(value.maxExclusive)) {
    return false;
  }
  if (!isVersionOrNull(value.maxInclusive) || !isMajorOrNull(value.majorLine)) {
    return false;
  }
  const lower = (value.minInclusive !== null ? 1 : 0) + (value.majorLine !== null ? 1 : 0);
  const upper = (value.maxExclusive !== null ? 1 : 0) + (value.maxInclusive !== null ? 1 : 0);
  return lower === 1 && upper === 1;
}

function parseSemVer(value: string): SemVer | undefined {
  const match = value.match(VERSION_RE);
  if (match === null) {
    return undefined;
  }
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (!Number.isInteger(major) || !Number.isInteger(minor) || !Number.isInteger(patch)) {
    return undefined;
  }
  return { major, minor, patch };
}

function compareSemVer(left: SemVer, right: SemVer): number {
  if (left.major !== right.major) {
    return left.major - right.major;
  }
  if (left.minor !== right.minor) {
    return left.minor - right.minor;
  }
  return left.patch - right.patch;
}

/** False when the bounds describe no version. An empty interval is not a usable fact. */
function intervalHasRoom(range: AffectedRange): boolean {
  if (typeof range.minInclusive === 'string' && typeof range.maxExclusive === 'string') {
    const min = parseSemVer(range.minInclusive);
    const max = parseSemVer(range.maxExclusive);
    return min !== undefined && max !== undefined && compareSemVer(min, max) < 0;
  }
  if (typeof range.minInclusive === 'string' && typeof range.maxInclusive === 'string') {
    const min = parseSemVer(range.minInclusive);
    const max = parseSemVer(range.maxInclusive);
    return min !== undefined && max !== undefined && compareSemVer(min, max) <= 0;
  }
  if (typeof range.majorLine === 'number' && typeof range.maxExclusive === 'string') {
    const max = parseSemVer(range.maxExclusive);
    if (max === undefined) {
      return false;
    }
    if (max.major > range.majorLine) {
      return true;
    }
    if (max.major < range.majorLine) {
      return false;
    }
    return compareSemVer(max, { major: range.majorLine, minor: 0, patch: 0 }) > 0;
  }
  if (typeof range.majorLine === 'number' && typeof range.maxInclusive === 'string') {
    const max = parseSemVer(range.maxInclusive);
    if (max === undefined) {
      return false;
    }
    return max.major >= range.majorLine;
  }
  return false;
}

/**
 * One range, rendered the way the trusted alert must spell the whole set.
 * `>=1.2.0 <1.2.3`, `>=1.2.0 <=1.2.3`, or `1.x <=1.9.8`.
 */
export function renderRange(range: AffectedRange): string | undefined {
  if (!isWellFormedRange(range) || !intervalHasRoom(range)) {
    return undefined;
  }

  let lower: string;
  if (typeof range.minInclusive === 'string') {
    lower = `>=${range.minInclusive}`;
  } else if (typeof range.majorLine === 'number') {
    lower = `${range.majorLine}.x`;
  } else {
    return undefined;
  }

  let upper: string;
  if (typeof range.maxExclusive === 'string') {
    upper = `<${range.maxExclusive}`;
  } else if (typeof range.maxInclusive === 'string') {
    upper = `<=${range.maxInclusive}`;
  } else {
    return undefined;
  }

  return `${lower} ${upper}`;
}

function copyRange(range: AffectedRange): AffectedRange {
  return {
    minInclusive: range.minInclusive,
    maxExclusive: range.maxExclusive,
    maxInclusive: range.maxInclusive,
    majorLine: range.majorLine,
  };
}

/** Sorted canonical text, plus the ranges in that same order. */
export function orderRanges(
  ranges: readonly AffectedRange[],
): { ranges: AffectedRange[]; affectedRange: string } | undefined {
  if (ranges.length === 0 || ranges.length > MAX_RANGES) {
    return undefined;
  }

  const rendered: { range: AffectedRange; text: string }[] = [];
  for (const range of ranges) {
    const text = renderRange(range);
    if (text === undefined) {
      return undefined;
    }
    rendered.push({ range: copyRange(range), text });
  }

  rendered.sort((left, right) => (left.text < right.text ? -1 : left.text > right.text ? 1 : 0));
  return {
    ranges: rendered.map((item) => item.range),
    affectedRange: rendered.map((item) => item.text).join('; '),
  };
}

export function canonicalAffectedRange(ranges: readonly AffectedRange[]): string | undefined {
  return orderRanges(ranges)?.affectedRange;
}

function matchesRange(version: SemVer, range: AffectedRange): boolean | undefined {
  if (renderRange(range) === undefined) {
    return undefined;
  }

  if (typeof range.majorLine === 'number') {
    if (version.major !== range.majorLine) {
      return false;
    }
  } else if (typeof range.minInclusive === 'string') {
    const min = parseSemVer(range.minInclusive);
    if (min === undefined || compareSemVer(version, min) < 0) {
      return false;
    }
  } else {
    return undefined;
  }

  if (typeof range.maxExclusive === 'string') {
    const max = parseSemVer(range.maxExclusive);
    if (max === undefined || compareSemVer(version, max) >= 0) {
      return false;
    }
  } else if (typeof range.maxInclusive === 'string') {
    const max = parseSemVer(range.maxInclusive);
    if (max === undefined || compareSemVer(version, max) > 0) {
      return false;
    }
  } else {
    return undefined;
  }

  return true;
}

/**
 * True when `version` sits in any range.
 * Undefined when `version` or a range cannot be read. That is not "outside".
 */
export function versionInsideRanges(
  version: string,
  ranges: readonly AffectedRange[],
): boolean | undefined {
  const parsed = parseSemVer(version);
  if (parsed === undefined || ranges.length === 0) {
    return undefined;
  }

  let inside = false;
  for (const range of ranges) {
    const matched = matchesRange(parsed, range);
    if (matched === undefined) {
      return undefined;
    }
    if (matched) {
      inside = true;
    }
  }
  return inside;
}

/**
 * True when the version is inside a range and is not the fixed version.
 * The fixed version is not affected, including when a range also names it.
 */
export function versionAffected(
  version: string,
  ranges: readonly AffectedRange[],
  fixedVersion: string,
): boolean | undefined {
  if (parseSemVer(fixedVersion) === undefined) {
    return undefined;
  }
  if (version === fixedVersion) {
    return parseSemVer(version) === undefined ? undefined : false;
  }
  return versionInsideRanges(version, ranges);
}
