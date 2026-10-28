/**
 * Facts the advisory reader moves between the model call and the version check.
 * Strings here are data. They are not commands.
 */

export type AffectedRange = {
  readonly minInclusive: string | null;
  readonly maxExclusive: string | null;
  readonly maxInclusive: string | null;
  readonly majorLine: number | null;
};

/** Shape the model may return after validation accepts it. Not yet checked against the prose. */
export type AdvisoryFacts = {
  packageName: string;
  vulnerableFunctions: string[];
  affectedRanges: AffectedRange[];
  fixedVersion: string;
  workaround: string | null;
};

/**
 * Range and patched version the caller already trusts.
 * These strings are not sent to the model.
 * `patchedVersion` null means the alert has no fix, and the reader rejects.
 */
export type TrustedAlert = {
  affectedRange: string;
  patchedVersion: string | null;
};

/** Facts that passed the prose checks and the alert checks. */
export type VerifiedAdvisory = {
  packageName: string;
  vulnerableFunctions: readonly string[];
  affectedRanges: readonly AffectedRange[];
  /** Canonical range text. It must equal `alert.affectedRange`. */
  affectedRange: string;
  fixedVersion: string;
  workaround: string | null;
  /** Set when the prose contains instruction-like phrasing. It does not change the fields. */
  suspicion: string | null;
};
