# Advisory reader

Reads CVE advisory prose into a few facts, then compares those facts with `inventory/services.json`.

Advisory prose is free text. Code cannot parse the ranges out of a sentence. The prose is data. Instructions inside it are not orders. CloudTrail fields are already structured. Do not send those fields to Grok.

Follow `.cursor/skills/writing-extractors/SKILL.md`. Call `extract()` in `src/grok/client.ts`. Do not call the xAI API from this folder.

The tests use synthetic advisory GHSA-demo-7q2x-yl41 for `@acme-demo/yaml-lite` (case AG-20261028-03, `dep:vulnerable_package`).

## Input

- `advisoryProse`: the advisory text, as a string. It is the user message only.
- `alert`: the vulnerable range and the patched version, already trusted by code. Do not paste the alert into the model prompt. `patchedVersion` must be a non-empty `x.y.z` string. When the alert has no patched version, the reader returns `invalid_facts` and does not call the model.

## What the model is asked for

`additionalProperties` is false. Unused range bounds are null.

- `packageName`: the package the advisory names.
- `vulnerableFunctions`: identifier strings, at most 20. Each name matches `^[A-Za-z_$][A-Za-z0-9_$]{0,80}$`. An empty list is allowed.
- `affectedRanges`: each affected version range, at most 8. Use `minInclusive` and `maxExclusive` when the prose names those bounds. Use `majorLine` when the prose names an `N.x` line. Use `maxInclusive` when the prose says the line is affected through a version.
- `fixedVersion`: the version the advisory says contains the fix.
- `workaround`: the single line after `Workaround:`, or null when that label is absent.

What Grok decides: those fields, or a failure from `extract()`.

What code decides: whether each function name is a case-sensitive substring of `advisoryProse`, whether a function the same sentence calls "not affected" is rejected, whether every version and `N.x` token appears in the prose as its own token, whether `packageName` appears in the prose, whether `fixedVersion` appears in the prose and equals the alert, and whether `workaround` equals the labeled line. The canonical `affectedRange` must equal the alert character for character. A miss is `invalid_facts`. The bad name is not dropped. A version the alert does not have is not invented. An empty function list is a result the caller can see. It is not a guess.

The canonical range text is sorted. One range is `>=version <version`, `>=version <=version`, or `N.x <=version` (the same shapes with the other bound). Ranges are joined with `; `. For the demo advisory that text is `1.x <=1.9.8; >=2.0.0 <2.4.3`.

Code then compares each service version in the inventory with those ranges. A service that does not depend on the package is not affected. The fixed version is not affected. A version string that cannot be read fails the report. This comparison does not call Grok.

If the prose contains `ignore previous`, `ignore all`, `system prompt`, `you are now`, or `approve this`, keep a suspicion note for the human and still apply the hard checks. The phrase does not change a field and it does not skip a check.

Tests mock the network. They replace the old empty-slot test.
