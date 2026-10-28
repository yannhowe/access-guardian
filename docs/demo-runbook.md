# Demo runbook

Interview: Thursday 29 Oct 2026, 10:00 SGT.

Access Guardian watches for an open security group port and will not close it unless the change is on an allow-list, the plan is a dry-run, Yann says yes, and Yann merges the code. The bots talk. This repo holds the gates.

Use synthetic data only. A safe group id is `sg-demo0001`. A safe account id in examples is `111122223333`. A safe source address is `203.0.113.24`. Do not show a live key, a webhook secret, or the AWS root key.

## Two ways a case reaches AG Lead

1. CloudTrail. Someone calls `AuthorizeSecurityGroupIngress`. The hand-built EventBridge rule matches it. The API destination POSTs the structured body from `docs/intake.md` to the Grok Bot routine webhook. No Lambda, and no code in this repo. The bot reads `eventName`, `time`, `account`, `region`, `actorArn`, `sourceIp`, `securityGroupId`, `portRange`, `cidr`, and `requestId` in code. That path does not call Grok.
2. Slack. A person writes in `#platsec-demo`. The Grok Bot channel listener receives it. No Slack code lives here. If the message is free text that code cannot parse, Lead may extract facts. If the listener already has structured fields, it does not call Grok.

A sample webhook body, all synthetic:

```json
{
  "eventName": "AuthorizeSecurityGroupIngress",
  "time": "2026-10-29T02:00:00Z",
  "account": "111122223333",
  "region": "ap-southeast-1",
  "actorArn": "arn:aws:iam::111122223333:user/demo",
  "sourceIp": "203.0.113.24",
  "securityGroupId": "sg-demo0001",
  "portRange": { "from": "22", "to": "22" },
  "cidr": "0.0.0.0/0",
  "requestId": "example-request-id"
}
```

If `from` and `to` are the same single port, the starter fix can plan a revoke of that port. If they differ, this fix does not apply. The case stays with a human. The fix revokes one port, not a range.

## Bot flow

1. AG Lead opens the case from the webhook body or from Slack.
2. AG Context checks whether a change is reasonable to make now: who owns the resource, who is on call, whether a freeze is active. Context uses structured records. Context does not call Grok and does not change AWS.
3. AG Change checks whether an approved request covers this one finding, and whether the fix key is on the allow-list. One finding, one resource. A wildcard request is too broad. If `close-open-port` is already registered, Change reuses it. If the key is allowed but not built, Change asks Builder to write it. If the key is not on the list, a human handles it. Change does not call Grok and does not run the fix.
4. AG Lead shows Yann the plan: the one action `RevokeSecurityGroupIngress`, the exact rule, and the dry-run result (`applied: false`). Lead does not apply it.
5. Yann's yes. This is the human gate. Our code may then pass `{ apply: true }`. The event JSON cannot set that flag. Without the yes, the client is not called, and Builder does not start.
6. AG Builder, a Cursor cloud agent, opens a pull request in this repo. A new fix follows `.cursor/skills/writing-remediators/SKILL.md`. The advisory reader follows `.cursor/skills/writing-extractors/SKILL.md`. The guard test must pass. Builder does not merge.
7. The pull request goes back to AG Lead, who checks the allow-list entry, the single action, and the pasted `npm test` and `npx tsc --noEmit` output. Yann merges only when he explicitly asks. That merge is the second human gate.

## Every Grok call

Grok is called only for free text that code cannot parse. Each call goes through `extract()` or it does not belong in this repo.

| Call | Where | What Grok decides | What code decides |
| --- | --- | --- | --- |
| `extract()` | `src/grok/client.ts`, the only HTTP call to xAI | Nothing about the case. It returns JSON that passed `validate`, or `no_key`, `timeout`, `http_error`, `bad_json`, or `schema_mismatch`. Temperature is 0. The wait is 15 seconds. | Whether the facts match the source, and whether a fix may run. On failure, do not act. |
| Advisory reader | Not built. `src/extractors/advisory/README.md` | When built: `vulnerableFunctions`, `affectedRange`, and `fixedVersion` from advisory prose. | Whether each function name is in the prose, and whether the range and the fixed version equal the trusted alert. A miss is `invalid_facts`. No guessed version. |
| Slack prose | Grok Bot app, not this repo | The fact fields named in that call's schema, and only when the message is free text code cannot parse. | Whether those facts are complete enough to open a case. A failure opens nothing. |
| CloudTrail webhook | No Grok call | | The bot reads the transformer fields. |
| Context, Change, Yann's yes, merge | No Grok call | | Code and Yann. Grok does not decide that an actor was authorized. |

The client reads `XAI_API_KEY` from the environment. `XAI_MODEL` overrides the default `grok-4.7`. Tests mock `fetch` and pass with no key.

## What to show in the code

- `src/fixes/allow-list.ts`: one entry, one action, one undo.
- `src/fixes/close-open-port.ts`: `ACTION` is `RevokeSecurityGroupIngress`. `closeOpenPort` returns the plan unless `apply` is `true`.
- `tests/fixes/close-open-port.test.ts`: a fake AWS client. Default is dry-run. One `send` when apply is set. Bad input does not send.
- `tests/guard.test.ts`: the tree passes, and a fix off the list, a second action, or an xAI call outside the client fails.
- `src/extractors/advisory/README.md`: the empty slot for the live build.

Commands:

```bash
npm test
npx tsc --noEmit
```

## Live build

Build the advisory reader in `src/extractors/advisory/`, following the writing-extractors skill. Leave the CloudTrail path on structured fields. Do not add a second Grok client. When the module exists, replace the empty-slot test with tests that mock `fetch`.

## Trade-off

The main remaining risk is a false "authorized" verdict. That is a missed alert. If Context or Change treats the open port as allowed when it was not, Lead does not raise it, and the rule stays. The allow-list, the dry-run, Yann's yes, and Yann's merge limit what a fix can do after a case is in motion. They do not catch a case that was dropped as authorized. Grok is not the backstop for that decision, because Grok is not asked to authorize.

A smaller miss sits on the intake. The transformer reads one IPv4 permission. Two rules, or an IPv6-only rule, may never reach the webhook. CloudTrail still has the API call. That is a missed delivery, not a false authorized verdict.

Fail closed everywhere this repo does decide: a bad rule, a guard failure, a Grok timeout, or a schema miss produces no AWS call and no invented fact.
