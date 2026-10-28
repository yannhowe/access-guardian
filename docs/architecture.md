# Architecture

Access Guardian is a defensive demo. The picture of a case, from CloudTrail and Slack through the bots to a fix Lambda, is in the repository [README](../README.md). This page is the detail behind that picture.

Four Grok Bot teammates do the judging and the conversation: AG Lead, AG Context, AG Change, and AG Builder. They are not in this repository. AG Context includes Identity, which is merged into that agent. AG Lead keeps cases in Notion under `AG cases`, speaks in Slack as `@AG-lead`, and treats Yann (Slack `U0CAKUDP3L0`) as the only approver. Slack channel `platsec-demo` reaches Lead only when the message tags `@AG-lead`.

This repository is the hard gate in front of a change:

- An allow-list of fixes (`src/fixes/allow-list.ts`).
- One Lambda per fix, under `src/fixes/<name>/`, with its own IAM role `ag-fix-<name>`.
- One hardcoded mutating call per fix. The call returns the resource to its recorded intended state. A fix may open access only when that return is proven both by the intended-public=true tag check in the handler and by the IAM tag condition on the fix role. The only case is `remove-bucket-public-access-block`, on the one bucket that carries `intended-public=true`, `auto-remediate=true`, and `purpose=ag-demo-synthetic`. Every other fix stays close-only.
- A guard in `src/guard/` that fails a fix off the list, a wildcard action, a blocked IAM action, a missing Terraform entry, a missing `auto-remediate` check, and any xAI call outside the Grok client.
- A human yes before `apply` is true, and a human merge before code lands. Merge only when Yann explicitly asks.

Dry-run is the default. The Lambda changes AWS only when the event has `apply` set to boolean `true`.

## How a case arrives

Two triggers, both outside this repository.

1. CloudTrail. EventBridge rule `ag-cloudtrail-sg-ingress-to-lead` matches successful `AuthorizeSecurityGroupIngress` only. API destination `ag-lead-webhook` POSTs a short JSON body to the AG Lead routine webhook. That path has no Lambda. The pieces are listed in [intake.md](intake.md). A second rule, `ag-cloudtrail-s3-public-access-to-lead`, is created outside Terraform (manual). Its event pattern is not written in this repository. TODO: move that rule into `infra/`.
2. Slack. A channel listener on `platsec-demo`, and only for a message that tags `@AG-lead`. No Slack code lives here.

The CloudTrail body is structured, so the bot reads it in code. Grok is not used to parse it. Slack text is free text. Grok is called only when code cannot parse that text, and only through the one client.

## Grok

`src/grok/client.ts` is the only file that calls the xAI API. `extract()` asks for strict JSON at temperature 0, waits at most 15 seconds, and returns the parsed value or a typed failure (`no_key`, `timeout`, `http_error`, `bad_json`, `schema_mismatch`).

What Grok decides: whether the reply is JSON that passed the caller's `validate` function.

What code decides: whether those facts match the source, and whether a fix may run. A failure is not a guess.

The advisory reader in `src/extractors/advisory/` is the Grok-backed extractor. The folder README is the contract. `.cursor/skills/writing-extractors/SKILL.md` is the procedure. Grok returns the package, the functions, the ranges, the fixed version, and any workaround. Code checks those facts against the prose and the trusted alert, then compares the ranges with `inventory/services.json`. Tests live in `tests/extractors/advisory.test.ts`.

## What a fix is allowed to do

Each fix is a folder `src/fixes/<name>/` with `handler.ts`, `policy.json`, and `fix.json`. Terraform in `infra/` creates one role and one function, both named `ag-fix-<name>`. The role's permissions boundary is `ag-fix-boundary`. The inline policy is that folder's `policy.json`. A new fix is the folder plus one name in `local.fix_names`.

`main` has three fixes. See the table in the [README](../README.md).

- `close-open-port` checks a security group id, a protocol (`tcp` or `udp`), one port, and one IPv4 CIDR. It reads the rules. When a matching ingress rule is still there, the handler requires `auto-remediate=true` and revokes that rule only when `apply` is true. The handler does not check `purpose`. IAM on the revoke statement requires both `auto-remediate=true` and `purpose=ag-demo-synthetic` on `arn:aws:ec2:*:*:security-group/*`. The reads have no tag condition. If the rule is already gone, the result is `changed: false` and `reason` `already_closed`. The undo on the allow-list is to authorize that same rule again. The fix does not perform the undo.
- `restore-bucket-public-access-block` accepts one bucket name that starts with `ag-demo-`. The handler requires `purpose=ag-demo-synthetic` and `auto-remediate=true`, and it refuses `intended-public=true`. IAM scopes both statements to `arn:aws:s3:::ag-demo-*` and has no tag condition. The put sets all four Block Public Access flags to true. An already blocked bucket returns `already_blocked`.
- `remove-bucket-public-access-block` accepts only bucket `ag-demo-public-10281729`. The handler requires `intended-public=true`, `auto-remediate=true`, and `purpose=ag-demo-synthetic` before it sends `DeletePublicAccessBlockCommand`. The IAM action is `s3:PutBucketPublicAccessBlock`, which is how AWS authorizes that API. Both policy statements use that one bucket ARN. The mutating statement requires `aws:ResourceTag/intended-public` = `true`. The read statement has no tag condition. If the block is already absent, the result is `already_absent`.

A key that is not on the allow-list is not something Builder may automate. A human handles it.

## How a bot runs a fix

AG Lead assumes `ag-bot-invoker` and invokes the Lambda. That role is created outside Terraform (manual). Its permission is `lambda:InvokeFunction` on `ag-fix-*`. `ag-reader` handles read-only checks and is created outside Terraform (manual). TODO: move both roles into `infra/`. Region `ap-southeast-1`.

Dry run first. Leave `apply` out, or set it to false:

```bash
aws lambda invoke \
  --function-name ag-fix-close-open-port \
  --cli-binary-format raw-in-base64-out \
  --payload '{"caseId":"case-demo-1","securityGroupId":"sg-demo0001","protocol":"tcp","port":22,"cidr":"0.0.0.0/0"}' \
  /tmp/ag-fix-out.json
```

The result has `changed: false`. `reason` is `dry_run` when a revoke would happen, or `already_closed` when the rule is gone.

After Yann's yes, invoke the same function with `"apply": true`. A successful revoke has `changed: true` and `reason` `revoked`. An AWS failure returns that error's code and message.

The same dry-run rule applies to `ag-fix-restore-bucket-public-access-block` and `ag-fix-remove-bucket-public-access-block`. Those events carry `bucket` and `apply`. They do not carry `caseId`.

[aws-setup.md](aws-setup.md) lists the OIDC provider, the plan and apply roles, the boundary, the state bucket, and the bots' invoke-only access. Those are created by hand. Terraform only manages `ag-fix-*`.
