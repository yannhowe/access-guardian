# Architecture

Access Guardian is a defensive demo. Four Grok Bot teammates do the judging and the conversation: AG Lead, AG Context, AG Change, and AG Builder. They are not in this repo.

This repo is the hard gate in front of a change:

- An allow-list of fixes (`src/fixes/allow-list.ts`).
- One Lambda per fix, under `src/fixes/<name>/`, with its own IAM role `ag-fix-<name>`.
- One hardcoded close action per fix. The starter, `close-open-port`, revokes one ingress rule.
- A guard test that fails a fix off the list, a policy that opens or deletes, a wildcard action, or an xAI call outside the Grok client.
- A human yes before a real AWS call, and a human merge before code lands. Merge only when Yann explicitly asks.

Dry-run is the default. The Lambda changes AWS only when the event has `apply: true`.

## How a case arrives

Two triggers, both outside this repo.

1. CloudTrail. An EventBridge rule matches a security group ingress change and an API destination POSTs a short JSON body to the AG Lead routine webhook. That path has no Lambda. The pieces are listed in `docs/intake.md`. They were created by hand with the AWS CLI.
2. Slack. A channel listener on `#platsec-demo`. No Slack code lives here.

The CloudTrail body is structured, so the bot reads it in code. Grok is not used to parse it. Slack text is free text. Grok is called only when code cannot parse that text, and only through the one client.

## Grok

`src/grok/client.ts` is the only file that calls the xAI API. `extract()` asks for strict JSON at temperature 0, waits at most 15 seconds, and returns the parsed value or a typed failure (`no_key`, `timeout`, `http_error`, `bad_json`, `schema_mismatch`).

What Grok decides: whether the reply is JSON that passed the caller's `validate` function.

What code decides: whether those facts match the source, and whether a fix may run. A failure is not a guess.

The advisory reader in `src/extractors/advisory/` is the Grok-backed extractor. It is not implemented. The folder README is the contract. `.cursor/skills/writing-extractors/SKILL.md` is the procedure.

## What a fix is allowed to do

Each fix is a folder `src/fixes/<name>/` with `handler.ts`, `policy.json`, and `fix.json`. Terraform in `infra/` creates one role and one function, both named `ag-fix-<name>`. The role's permissions boundary is `ag-fix-boundary`. The inline policy is that folder's `policy.json`. A new fix is the folder plus one name in `local.fix_names`.

`close-open-port` checks a security group id, a protocol (`tcp` or `udp`), one port, and one IPv4 CIDR. It reads the rules, and it revokes that one ingress rule only when `apply` is true and the rule is still there. If the rule is already gone, the result is `changed: false`. The undo is on the allow-list (authorize that same rule again). The fix does not perform the undo.

A key that is not on the allow-list is not something Builder may automate. A human handles it.

## How a bot runs a fix

The bot invokes the Lambda. It does not call EC2 itself. Region `ap-southeast-1`.

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

`docs/aws-setup.md` lists the OIDC provider, the plan and apply roles, the boundary, the state bucket, and the bots' invoke-only access. Those are created by hand. Terraform only manages `ag-fix-*`.
