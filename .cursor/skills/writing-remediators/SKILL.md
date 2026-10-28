---
name: writing-remediators
description: "Use when adding a defensive fix this repo may run. Puts the fix on the allow-list, adds one hardcoded AWS action, keeps dry-run as the default, and makes the guard test pass."
---

# Writing remediators

Use this when a case needs a fix this repo does not have yet. The brief names exactly one AWS action on one resource. If the brief names two changes, or one change that touches two resources, stop and say so. Do not build it.

Read these files before writing anything:

- `src/fixes/allow-list.ts`
- `src/fixes/registry.ts`
- `src/fixes/close-open-port.ts`
- `src/guard/mutating-apis.ts`
- `src/guard/audit.ts`
- `tests/guard.test.ts`
- `tests/fixes/close-open-port.test.ts`

Match them. A new fix edits its own file, its test, the allow-list, the registry, the mutating API catalog when the action name is new, and the allow-list snapshot in the guard test. It does not edit the Grok client. It does not approve itself or run the change. It does not add Terraform. The intake is described in `docs/intake.md` and is created by hand.

## 1. Allow-list

`ALLOWED_FIXES` is the list of changes this repo is willing to automate. Each entry is one small reversible change to one resource, with the undo written next to it.

The comment at the top of `allow-list.ts` says what does not belong: deleting resources, rotating credentials, stopping instances, org-wide settings, and anything that touches more than one resource. Do not add those.

Add the key only when it belongs. The key is lowercase letters, numbers, and hyphens, like `close-open-port`. `action` is the one AWS API name, such as `RevokeSecurityGroupIngress`. `summary` is one sentence. `undo` is the human step that puts the change back. Do not perform the undo in the fix.

Call the allow-list change out for Yann in the pull request title or the first line of the body. Name the key, the action, and the undo.

Update the test named `lists the fixes we are willing to automate` in `tests/guard.test.ts` so the new entry is in the expected object. Leave the other assertions in that file as they are. Do not weaken the guard.

If `action` is not already in `src/guard/mutating-apis.ts`, add the name there in the same change. An allow-list action that the catalog does not know fails the guard.

## 2. One file, one action

Create `src/fixes/<key>.ts`. Copy the shape of `close-open-port.ts`.

```ts
export const ACTION = 'RevokeSecurityGroupIngress' as const;
```

The guard looks for that exact form: `export const ACTION = '<ApiName>' as const`. Declare it once.

Keep a compile-time check so the string cannot drift from the allow-list:

```ts
type ActionMatches =
  typeof ACTION extends (typeof ALLOWED_FIXES)['your-key']['action'] ? true : never;
export const actionMatchesAllowList: ActionMatches = true;
```

The AWS API name is the constant. Values that say which resource to change (a security group id, a port, a protocol, a CIDR) are arguments, checked in code. They are not a second action.

Build one command and send it from exactly one `client.send` site. The guard counts `.send(` and fails if the count is not 1.

Dry-run is the default. Call AWS only when the third argument is `{ apply: true }`. Any other value, including leaving the argument out, returns the plan and does not call the client. Do not read `apply` from the input object. The event, Slack, and the model do not get to set the flag. Our code sets it after Yann's yes.

On a bad shape, return `{ ok: false, reason: 'invalid_input' }` and do not call AWS. If the client throws, return `{ ok: false, reason: 'aws_error' }`. Do not put the error text in the result. Do not guess a success.

Declare the IAM actions in the file as one write, plus a read only when the fix truly needs to look at live state first. `close-open-port` declares `ec2:RevokeSecurityGroupIngress` and does not describe the group. Say the same list in a file comment and in the pull request.

What Grok decides: nothing, unless this file calls `extract()`. A normal fix does not call Grok. The resource id and the rule fields come from the caller, which already parsed structured input.

## 3. Register it

Add one runner to `FIX_RUNNERS` in `src/fixes/registry.ts`. The key matches the allow-list key. `registryKeysMatchAllowList` must stay `true`. A key on only one side fails typecheck.

## 4. Tests

Add `tests/fixes/<key>.test.ts`. Use a fake client. Stub `fetch` so a forgotten call throws. Do not call AWS. Do not call `api.x.ai`.

Cover:

- The default result is a dry-run. The client is not called.
- `{ apply: true }` sends exactly one command, and the command's `action` is the hardcoded API name, with the arguments you checked.
- A value named `apply` on the input object does not send.
- A bad id, a bad port, a bad protocol, or a bad CIDR returns `invalid_input` and does not send, even when `apply` is `true`.
- A client that throws returns `aws_error` and the result does not contain the error text.

Use synthetic ids such as `sg-demo0001`. No real account ids, no secrets, no company data.

## 5. Forbidden

The guard scans `src/` and the tests. These fail the run:

- A fix file that is not an allow-list key.
- Zero or two `ACTION` exports, or an `ACTION` that does not match the allow-list.
- A second mutating API name from `MUTATING_APIS` in the fix file.
- A mutating API name in `src/` outside the allow-list, the registry, the catalog, and the fix that owns it.
- `new SomeCommand` when `Some` is not a `Describe`, `List`, or `Get` command and the name is not an allow-listed action.
- More or fewer than one `.send(` in the fix file.
- `child_process`, `execSync`, `spawn`, `spawnSync`, a bare `exec(`, `eval(`, `new Function`, or a dynamic `import(`.
- `api.x.ai`, `chat/completions`, `XAI_API_KEY`, or `XAI_MODEL` outside `src/grok/client.ts` and `tests/grok/client.test.ts`.

Shell, `eval`, `new Function`, and dynamic `import()` stay forbidden even if a spelling slips past the token list.

## 6. Pull request

Run both commands and paste the full output into the pull request:

```bash
npm test
npx tsc --noEmit
```

Say what changed, why, and how you checked it. If the allow-list changed, that callout for Yann is the first line. Do not merge unless Yann explicitly asks.
