# Architecture

Access Guardian is a defensive demo. Four Grok Bot teammates do the judging and the conversation: AG Lead, AG Context, AG Change, and AG Builder. They are not in this repo.

This repo is the hard gate in front of a change:

- An allow-list of fixes (`src/fixes/allow-list.ts`).
- One hardcoded AWS action per fix. The starter, `close-open-port`, revokes one ingress rule.
- A guard test that fails when a fix or a mutating AWS call is not on that list, when a fix has more than one action, or when anything outside `src/grok/client.ts` calls the xAI API.
- A human yes before a real AWS call, and a human merge before code lands. Merge only when Yann explicitly asks.

Dry-run is the default. `closeOpenPort` calls AWS only when the third argument is `{ apply: true }`.

## How a case arrives

Two triggers, both outside this repo.

1. CloudTrail. An EventBridge rule matches a security group ingress change and an API destination POSTs a short JSON body to the AG Lead routine webhook. There is no Lambda. The pieces are listed in `docs/intake.md`. They were created by hand with the AWS CLI. This repo has no Terraform.
2. Slack. A channel listener on `#platsec-demo`. No Slack code lives here.

The CloudTrail body is structured, so the bot reads it in code. Grok is not used to parse it. Slack text is free text. Grok is called only when code cannot parse that text, and only through the one client.

## Grok

`src/grok/client.ts` is the only file that calls the xAI API. `extract()` asks for strict JSON at temperature 0, waits at most 15 seconds, and returns the parsed value or a typed failure (`no_key`, `timeout`, `http_error`, `bad_json`, `schema_mismatch`).

What Grok decides: whether the reply is JSON that passed the caller's `validate` function.

What code decides: whether those facts match the source, and whether a fix may run. A failure is not a guess.

The advisory reader in `src/extractors/advisory/` is the Grok-backed extractor. The folder README is the contract. `.cursor/skills/writing-extractors/SKILL.md` is the procedure. Grok returns the package, the functions, the ranges, the fixed version, and any workaround. Code checks those facts against the prose and the trusted alert, then compares the ranges with `inventory/services.json`.

## What a fix is allowed to do

`close-open-port` takes a security group id, a protocol (`tcp` or `udp`), one port, and one IPv4 CIDR. It checks that shape, then plans a single `RevokeSecurityGroupIngress`. From-port and to-port on the wire are that same port. The undo is written on the allow-list (authorize that same rule again). The fix does not perform the undo.

A key that is not on the allow-list is not something Builder may automate. A human handles it.
