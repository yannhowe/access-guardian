/**
 * Runners for allow-listed fixes.
 * The keys here and the keys in `ALLOWED_FIXES` are the same set.
 * A key with no runner is not a fix this repo can run.
 */
import type { AllowedFixKey } from './allow-list.js';
import { closeOpenPort } from './close-open-port.js';
import { restoreBucketPublicAccessBlock } from './restore-bucket-public-access-block.js';

export const FIX_RUNNERS = {
  'close-open-port': closeOpenPort,
  'restore-bucket-public-access-block': restoreBucketPublicAccessBlock,
} as const;

type KeysMatch =
  keyof typeof FIX_RUNNERS extends AllowedFixKey
    ? AllowedFixKey extends keyof typeof FIX_RUNNERS
      ? true
      : never
    : never;

/** Compile-time check. `true` only when the registry and the allow-list name the same keys. */
export const registryKeysMatchAllowList: KeysMatch = true;
