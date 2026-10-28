/**
 * Finding key to Lambda function name.
 * Built from the allow-list, so a new fix does not edit this file.
 * A bot invokes ag-fix-<name>. It does not import the handler.
 */
import { ALLOWED_FIXES, type AllowedFixKey } from './allow-list.js';

type FixRegistry = {
  readonly [K in AllowedFixKey]: {
    readonly findingKey: (typeof ALLOWED_FIXES)[K]['findingKey'];
    readonly functionName: `ag-fix-${K}`;
  };
};

export const FIX_REGISTRY = Object.fromEntries(
  (Object.keys(ALLOWED_FIXES) as AllowedFixKey[]).map((key) => [
    key,
    {
      findingKey: ALLOWED_FIXES[key].findingKey,
      functionName: `ag-fix-${key}`,
    },
  ]),
) as FixRegistry;

type KeysMatch =
  keyof typeof FIX_REGISTRY extends AllowedFixKey
    ? AllowedFixKey extends keyof typeof FIX_REGISTRY
      ? true
      : never
    : never;

/** Compile-time check. True only when the registry and the allow-list name the same keys. */
export const registryKeysMatchAllowList: KeysMatch = true;
