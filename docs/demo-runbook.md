# Demo runbook

Access Guardian watches an allow-listed finding and will not change AWS unless the fix is on the allow-list, the first invoke is a dry run, Yann says yes, and Yann has merged the code. The bots talk. This repo holds the gates. The three fixes on `main` are `close-open-port`, `restore-bucket-public-access-block`, and `remove-bucket-public-access-block`.

Use synthetic data only. A safe group id is `sg-demo0001`. A safe account id in examples is `111122223333`. A safe source address is `203.0.113.24`. Do not show a live key, a webhook secret, or the AWS root key.

## Two ways a case reaches AG Lead

1. CloudTrail. Someone calls `AuthorizeSecurityGroupIngress`. Rule `ag-cloudtrail-sg-ingress-to-lead` matches that successful call only. The API destination POSTs the structured body to the AG Lead routine webhook. No Lambda, and no code in this repo. The bot reads `eventName`, `eventTime`, `account`, `region`, `actorArn`, `sourceIp`, `groupId`, `protocol`, `fromPort`, `toPort`, `cidr`, `requestId`, `eventId`, and `source` in code. That path does not call Grok. Rule `ag-cloudtrail-s3-public-access-to-lead` is created outside Terraform (manual). Its event pattern is not written in this repo. TODO: move that rule into `infra/`.
2. Slack. A person writes in `#platsec-demo` and tags `@AG-lead`. The Grok Bot channel listener receives that mention. No Slack code lives here. Yann (Slack `U0CAKUDP3L0`) is the only person whose messages count as approvals. If the message is free text that code cannot parse, Lead may extract facts. If the listener already has structured fields, it does not call Grok.

A sample webhook body, all synthetic:

```json
{
  "eventName": "AuthorizeSecurityGroupIngress",
  "eventTime": "2026-03-15T02:34:15Z",
  "account": "111122223333",
  "region": "ap-southeast-1",
  "actorArn": "arn:aws:iam::111122223333:user/demo",
  "sourceIp": "203.0.113.24",
  "groupId": "sg-demo0001",
  "protocol": "tcp",
  "fromPort": "22",
  "toPort": "22",
  "cidr": "0.0.0.0/0",
  "requestId": "example-request-id",
  "eventId": "example-event-id",
  "source": "aws-cloudtrail"
}
```

The rule, connection, destination, and role names are in `docs/intake.md`. The account id is not stored in this repo. This sample uses the same fields with synthetic values. Every field arrives as a string.

If `fromPort` and `toPort` are the same single port, the starter fix can plan a revoke of that port. If they differ, this fix does not apply. The case stays with a human. The fix revokes one port, not a range.

## Bot flow

1. AG Lead opens the case from the webhook body or from a Slack message that tags `@AG-lead`. Lead keeps the case in Notion under `AG cases`.
2. AG Context records who, why, the owner, and the intended state. Identity is merged into AG Context. Context uses structured records. Context does not call Grok and does not change AWS.
3. AG Change picks an allow-listed fix or proposes a build. One finding, one resource. A wildcard request is too broad. If the key is already registered, Change reuses it. If the key is allowed but not built, Change asks Builder to write it. If the key is not on the list, a human handles it. Change does not call Grok and does not run the fix.
4. AG Builder, a Cursor cloud agent, opens a pull request when a new fix is needed. A new fix follows `.cursor/skills/writing-remediators/SKILL.md`. The guard test must pass. Builder does not merge.
5. Yann reviews and merges. That merge is the gate for code. A merge to `main` runs `.github/workflows/terraform-apply.yml`.
6. AG Lead shows Yann the plan: the Lambda for that fix, the one IAM action, and the dry-run result (`changed: false`). Lead assumes `ag-bot-invoker` for the invoke. That role is created outside Terraform (manual), with `lambda:InvokeFunction` on `ag-fix-*`. `ag-reader` handles read-only checks and is created outside Terraform (manual). TODO: move both roles into `infra/`. Lead does not set `apply` until Yann says yes. Without the yes, the invoke stays a dry run.

## Every Grok call

Grok is called only for free text that code cannot parse. Each call goes through `extract()` or it does not belong in this repo.

| Call | Where | What Grok decides | What code decides |
| --- | --- | --- | --- |
| `extract()` | `src/grok/client.ts`, the only HTTP call to xAI | Nothing about the case. It returns JSON that passed `validate`, or `no_key`, `timeout`, `http_error`, `bad_json`, or `schema_mismatch`. Temperature is 0. The wait is 15 seconds. | Whether the facts match the source, and whether a fix may run. On failure, do not act. |
| Slack prose | Grok Bot app, not this repo | The fact fields named in that call's schema, and only when the message is free text code cannot parse. | Whether those facts are complete enough to open a case. A failure opens nothing. |
| CloudTrail webhook | No Grok call | | The bot reads the transformer fields. |
| Context, Change, Yann's yes, merge | No Grok call | | Code and Yann. Grok does not decide that an actor was authorized. |

The client reads `XAI_API_KEY` from the environment. `XAI_MODEL` overrides the default `grok-4.7`. Tests mock `fetch` and pass with no key.

## What to show in the code

- `src/fixes/allow-list.ts`: one entry per fix, one action, one undo line. The fix does not perform the undo.
- `src/fixes/close-open-port/`: revoke one ingress rule. Dry-run unless `apply` is true. IAM on the revoke requires `auto-remediate=true` and `purpose=ag-demo-synthetic`. The handler checks `auto-remediate=true` and does not check `purpose`.
- `src/fixes/restore-bucket-public-access-block/`: turn the four Block Public Access flags on. IAM has no tag condition and is scoped to `arn:aws:s3:::ag-demo-*`. The handler requires `purpose=ag-demo-synthetic` and `auto-remediate=true`, and it refuses `intended-public=true`.
- `src/fixes/remove-bucket-public-access-block/`: remove the block on `ag-demo-public-10281729` only. IAM requires `intended-public=true` on that bucket for the mutating action. The handler also requires `auto-remediate=true` and `purpose=ag-demo-synthetic`. The SDK command is `DeletePublicAccessBlockCommand`. The IAM action is `s3:PutBucketPublicAccessBlock`.
- `infra/main.tf`: one Terraform name per fix. The module always sets the permissions boundary.
- `tests/fixes/`: a fake AWS client per fix. Default is dry-run. One mutating call when apply is set. Bad input does not call AWS.
- `tests/guard.test.ts`: the tree passes, and a fix off the list, a second mutating action, or an xAI call outside the client fails.
- `inventory/services.json`: synthetic services and the exact npm versions they run.

Commands:

```bash
npm test
npx tsc --noEmit
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra init -backend=false
terraform -chdir=infra validate
```

## Service inventory

`inventory/services.json` is synthetic. `@acme-demo/yaml-lite` is on `billing-api` at `2.3.1`, on `ledger-worker` at `1.9.2`, and on `portal-web` at `2.4.3`. `notify-relay` and `directory-sync` do not use it. See `inventory/README.md`.

## Trade-off

The main remaining risk is a false "authorized" verdict. That is a missed alert. If Context or Change treats the finding as allowed when it was not, Lead does not raise it, and the security group rule or the bucket setting stays. The allow-list, the dry-run, Yann's yes, and Yann's merge limit what a fix can do after a case is in motion. They do not catch a case that was dropped as authorized. Grok is not the backstop for that decision, because Grok is not asked to authorize.

A smaller miss sits on the intake. The transformer reads the first permission and the first IPv4 range. Two rules, or an IPv6-only rule, may never reach the webhook. CloudTrail still has the API call. That is a missed delivery, not a false authorized verdict.

Fail closed everywhere this repo does decide: a bad rule, a guard failure, a Grok timeout, or a schema miss produces no AWS call and no invented fact.
