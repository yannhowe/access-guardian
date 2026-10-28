/** Shared limits and token patterns for the advisory reader. */

/** npm package name, scoped or not. Lower case, bounded length. */
export const PACKAGE_PATTERN =
  '^(?:@[a-z0-9][a-z0-9._-]{0,40}/)?[a-z0-9][a-z0-9._-]{0,80}$';

/** Function names the schema will accept. Same pattern as the folder contract. */
export const IDENTIFIER_PATTERN = '^[A-Za-z_$][A-Za-z0-9_$]{0,80}$';

/** Three numeric components. No leading zeros, no prerelease, no build metadata. */
export const VERSION_PATTERN =
  '^(0|[1-9][0-9]{0,6})\\.(0|[1-9][0-9]{0,6})\\.(0|[1-9][0-9]{0,6})$';

export const PACKAGE_RE = new RegExp(PACKAGE_PATTERN);
export const IDENTIFIER_RE = new RegExp(IDENTIFIER_PATTERN);
export const VERSION_RE = new RegExp(VERSION_PATTERN);

export const MAX_FUNCTIONS = 20;
export const MAX_RANGES = 8;
export const MAX_WORKAROUND = 240;
export const MAX_PROSE = 16_384;
export const MAX_RANGE_TEXT = 400;
