# Presenter prep

This page is the script for the person giving the talk. It is a normal document, not slides. Facts come from this repo or from the demo brief. Where a number, a buyer, a voice setup, a persona line, or a click-path in the Grok Bot app is unknown, it is marked TODO (Yann).

Read this before you present, because a few brief names are not in the repo:

- `README.md` on main has no mermaid diagram. The deck draws one. Keep that picture in sync with the README pull request.
- `docs/intake.md` documents one EventBridge rule, `ag-cloudtrail-sg-ingress-to-lead`, for a successful `AuthorizeSecurityGroupIngress`. The brief also names `ag-cloudtrail-s3-public-access-to-lead` for `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`, `PutBucketPolicy`, and `PutBucketAcl`. That second rule is not in this repo.
- The brief says Slack `#platsec-demo` reaches AG Lead only when `@AG-lead` is tagged. This repo says there is a channel listener on `#platsec-demo` and does not describe that tag filter.
- The brief names an invoke role `ag-bot-invoker`. `docs/aws-setup.md` gives the bots `lambda:InvokeFunction` on `ag-fix-*` and does not name that role.
- The brief names `ag-reader` for read-only checks. This repo has no `ag-reader`. Each fix Lambda does its own reads.
- The brief's three fix Lambdas are on main: `ag-fix-close-open-port`, `ag-fix-restore-bucket-public-access-block`, and `ag-fix-remove-bucket-public-access-block`.
- Yann's Slack id `U0CAKUDP3L0` is from the brief. This repo does not store it.
- `docs/aws-setup.md` says the close-open-port role revokes only a group tagged `purpose=ag-demo-synthetic`. The policy also requires `auto-remediate=true`, and the handler refuses the dry run and the apply unless that tag is exactly `true`. Follow the handler.

## Frame the business problem

Who feels it, what it costs today, and who buys the fix are Yann's call.

TODO (Yann): name the person who feels an open port or a public bucket, the cost in time or money, and the buyer of the fix. Do not invent those numbers on stage.

What this repo does say: the demo watches an access change and will not undo it unless the change is on an allow-list, the plan is a dry run, Yann says yes, and Yann merges the code. The bots talk. This repo holds the gates. Use synthetic data only. A safe group id in the docs is `sg-demo0001`. A safe account id in examples is `111122223333`. A safe source address in the sample is `203.0.113.24`.

## Tell it as a story

### Frame it

An engineer, or a demo click, opens a door that the tags say should stay shut. CloudTrail sees the API call. AG Lead gets a short JSON body, or a Slack line in `#platsec-demo`. The other bots check who owns the resource and whether a fix is allowed. Nobody changes AWS until Yann has seen a dry run.

### Show it live

Pick one incident. Say which one you are showing. The two incidents use different Lambdas.

Security group. Use a demo group already tagged `purpose=ag-demo-synthetic` and `auto-remediate=true`. The docs' synthetic id is `sg-demo0001`. Add one public ingress rule, tcp port 22 or tcp port 443, CIDR `0.0.0.0/0`. `docs/intake.md` matches a successful `AuthorizeSecurityGroupIngress` only. A failed call and a dry-run API call set `errorCode`, and those events are left out. The transformer sends the first permission and the first IPv4 range only. If `fromPort` and `toPort` differ, `close-open-port` does not apply and the case stays with a human.

Bucket that should stay blocked. Use a bucket whose name starts with `ag-demo-`, tagged `purpose=ag-demo-synthetic` and `auto-remediate=true`, and not tagged `intended-public=true`. A name that matches the handler is `ag-demo-walkthrough`. Turn Block Public Access off. That is the incident. The Lambda that turns the four flags back on is `ag-fix-restore-bucket-public-access-block`. Leave the bucket `ag-demo-public-10281729` out of this incident. That bucket is the intended-public case below.

Then walk the same spine for either incident:

1. CloudTrail hits the EventBridge rule, the API destination POSTs to AG Lead's webhook routine, and the routine run shows the case. The security group rule in the repo is `ag-cloudtrail-sg-ingress-to-lead`. The connection and the API destination are both named `ag-lead-webhook`. The target role is `ag-eventbridge-to-ag-lead`. The webhook URL and the API key are not in this repo. The key is held in the EventBridge connection.
2. Open the Slack thread in `#platsec-demo`. The brief says AG Lead sees it when `@AG-lead` is tagged. Show that tag if you are following the brief.
3. AG Context and AG Change speak. If the fix key is already registered, Change reuses it. Context does not change AWS.
4. Show the dry run. Leave `apply` out, or set it to false. For the security group, the command in `docs/architecture.md` is:

```bash
aws lambda invoke \
  --function-name ag-fix-close-open-port \
  --cli-binary-format raw-in-base64-out \
  --payload '{"caseId":"case-demo-1","securityGroupId":"sg-demo0001","protocol":"tcp","port":22,"cidr":"0.0.0.0/0"}' \
  /tmp/ag-fix-out.json
```

Expect `changed: false`. `reason` is `dry_run` when a revoke would happen, or `already_closed` when the rule is already gone. For port 443, use `"port":443` in that same shape.

For the restore, the handler takes `bucket` and `apply`:

```bash
aws lambda invoke \
  --function-name ag-fix-restore-bucket-public-access-block \
  --cli-binary-format raw-in-base64-out \
  --payload '{"bucket":"ag-demo-walkthrough"}' \
  /tmp/ag-fix-out.json
```

Expect `changed: false` and `reason` `dry_run` when the four flags are not all true. When they are already true, `reason` is `already_blocked`. The four flags the put would send are all true: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`.

5. Yann says yes. The brief says Yann, Slack id `U0CAKUDP3L0`, is the only approver. The bot may then invoke the same function with `apply` set to true. Lead does not set `apply` before that yes.
6. A successful revoke has `changed: true` and `reason` `revoked`. A successful restore has `changed: true` and `reason` `restored`. Run it once more. The second run finds the desired state and returns `changed: false`.
7. Notion closes the case. TODO (Yann): what the Notion page is called, who writes it, and what "closed" looks like. This repo does not describe Notion.

There is a third Lambda, and it is a different story. `ag-fix-remove-bucket-public-access-block` deletes Block Public Access only on the bucket `ag-demo-public-10281729`, and only when that bucket has all three tags `intended-public=true`, `auto-remediate=true`, and `purpose=ag-demo-synthetic`. The intended state comes from the `intended-public=true` tag. The handler does not read case text. AWS authorizes `DeletePublicAccessBlock` with `s3:PutBucketPublicAccessBlock`, which is the action on the allow-list. A dry run omits `apply`. `reason` is `dry_run` when a block configuration is present, `already_absent` when it is not, and `removed` after a successful apply. Do not use this function to open an arbitrary bucket. `ag-fix-restore-bucket-public-access-block` refuses a bucket tagged `intended-public=true` with `IntendedPublicBucket`.

If the bucket incident never arrives on its own, check the diagnose list. The S3 EventBridge rule from the brief is not in `docs/intake.md`.

### Land the value

The dry run named the one action and changed nothing. Yann's yes was the gate for `apply: true`. The second run was safe. The allow-list is what made that action something the repo will automate. A key that is not on the list stays with a human.

TODO (Yann): the sentence that ties this to a buyer's budget. The repo has no cost figure.

## Trigger the workflow live

Use this when the demo stalls. Check them in order.

1. EventBridge rule. For the security group path, confirm `ag-cloudtrail-sg-ingress-to-lead` on the default bus, a successful `AuthorizeSecurityGroupIngress`, connection `ag-lead-webhook`, API destination `ag-lead-webhook` (HTTP POST, 1 request per second), role `ag-eventbridge-to-ag-lead` with `events:InvokeApiDestination` on that destination, and 3 retries within 1 hour. The input transformer fields are `eventName`, `eventTime`, `account`, `region`, `actorArn`, `sourceIp`, `groupId`, `protocol`, `fromPort`, `toPort`, `cidr`, `requestId`, `eventId`, and `source` (the constant `aws-cloudtrail`). A call that adds two rules, or only an IPv6 range, does not fill `cidr`. That delivery does not become a half-parsed case. The older rule `platsec-cloudtrail-open-ssh` and its Lambda are disabled and are not part of this repo. For the bucket path, the brief's rule is `ag-cloudtrail-s3-public-access-to-lead`. It is not documented here. If you cannot find it in the account, the bucket case will not arrive through EventBridge.
2. Webhook routine run. AG Lead has a routine for the CloudTrail webhook. TODO (Yann): where that run is shown in the Grok Bot app. The URL is not in the repo.
3. Slack keyword trigger. The brief says the channel reaches AG Lead only when `@AG-lead` is tagged. The repo documents a channel listener on `#platsec-demo` and no Slack code. If a message does nothing, confirm the tag from the brief and that you are in that channel.
4. Assume the invoke role. The brief calls it `ag-bot-invoker`. The repo does not. What the repo does say: the bots get `lambda:InvokeFunction` on `ag-fix-*` only. They do not get `ec2:*`, `iam:*`, or permission to change the function. Region `ap-southeast-1`. An access denied on invoke is this check.
5. Lambda logs. Terraform creates `/aws/lambda/ag-fix-<name>` and keeps it for 14 days. The functions on main are `ag-fix-close-open-port`, `ag-fix-restore-bucket-public-access-block`, and `ag-fix-remove-bucket-public-access-block`. The handler returns the AWS error code and message on a failed call.
6. Missing tags. Match the error string.
   - Security group, rule still present: `MissingAutoRemediateTag`, `security group must have tag auto-remediate set to true`. The handler checks this on a dry run and on an apply. The IAM condition on the revoke also requires `purpose=ag-demo-synthetic`. A missing purpose tag can pass the handler's dry run and fail on apply with the AWS error.
   - Security group, rule already gone: `already_closed`, and the tag check is not reached.
   - More than one matching ingress rule: `NotOneRule`.
   - Restore, purpose tag missing or wrong: `BucketNotTagged`, `bucket must be tagged purpose=ag-demo-synthetic`.
   - Restore, `auto-remediate` not exactly `true`: `MissingAutoRemediateTag`.
   - Restore, `intended-public=true`: `IntendedPublicBucket`, `bucket tagged intended-public=true is left unchanged`.
   - Restore, bad bucket name: `InvalidInput`. The name must be 9 to 63 characters, start with `ag-demo-`, and use only lowercase letters, digits, dots, and hyphens.
   - Remove, any of the three tags missing or not exact: `MissingRequiredTags`, `bucket must have tags intended-public=true, auto-remediate=true, and purpose=ag-demo-synthetic`.
   - Remove, any other bucket: `InvalidInput`, and the message names `ag-demo-public-10281729`.

There is no `ag-reader` Lambda in this repo to consult. The reads are `ec2:DescribeSecurityGroupRules` and `ec2:DescribeSecurityGroups` on the port fix, and `s3:GetBucketTagging` plus `s3:GetBucketPublicAccessBlock` on the bucket fixes.

## Open the system

The four bots are Grok Bot teammates. They are not in this repo. Persona lines beyond the jobs below, and every voice setup, are unknown.

TODO (Yann): voice on or off for each bot, the voice name, and any spoken intro. This repo does not mention voice.

TODO (Yann): a persona paragraph for each bot, in your words. The jobs below are the ones the repo and the brief support.

### AG Lead

Routines, from the brief: one for the CloudTrail webhook, and one for Slack keyword tags. Connectors, from the brief: Slack, Notion, and GitHub.

From the runbook: Lead opens the case from the webhook body or from Slack. Lead shows the plan, the Lambda name, the one action, and the dry-run result. Lead does not set `apply`. After the pull request exists, Lead checks the allow-list entry, the single action, and the pasted `npm test` and `npx tsc --noEmit` output.

### AG Context

The brief: who, why, owner, intended state. Identity is merged into Context.

From the runbook: Context checks whether a change is reasonable to make now, who owns the resource, who is on call, and whether a freeze is active. Context uses structured records. Context does not call Grok and does not change AWS.

TODO (Yann): where the owner record, the on-call record, and the freeze flag live. They are not in this repo. `inventory/services.json` is a synthetic package list for the advisory reader. It is not a cloud inventory of intended state.

### AG Change

The brief: Change picks the fix or proposes a build.

From the runbook: Change checks whether an approved request covers this one finding, and whether the fix key is on the allow-list. One finding, one resource. A wildcard request is too broad. If the key is already registered, Change reuses it. If the key is allowed but not built, Change asks Builder to write it. If the key is not on the list, a human handles it. Change does not call Grok and does not run the fix.

### AG Builder

The brief: Builder writes the fix PR through a Cursor cloud agent.

From the runbook: a new fix follows `.cursor/skills/writing-remediators/SKILL.md`. The advisory reader follows `.cursor/skills/writing-extractors/SKILL.md`. The guard test must pass. Builder does not merge.

### The repo, the rules, and the skills

- `AGENTS.md` is the agent contract: one fix per pull request, dry run by default, Grok only through `extract()`, no merge unless Yann asks, no AWS from the agent.
- `.cursor/rules/core.mdc` applies to every change: plain English, no em dashes, synthetic data, no secrets, and the same intended-state rule as the allow-list.
- `.cursor/rules/fixes.mdc` is the shape of one fix.
- `.cursor/rules/grok.mdc` is the Grok call rule.
- `.cursor/rules/protected.mdc` lists paths an agent must not edit. The matching check is `scripts/check-protected-paths.mjs`. Protected paths are `src/guard/`, `tests/guard*`, `infra/modules/`, `.github/`, `src/fixes/allow-list.ts`, and `.cursor/`. Yann adds the `guard-change` label. An agent does not.
- `.cursor/skills/writing-remediators/SKILL.md` is the procedure for a new fix folder.
- `.cursor/skills/writing-extractors/SKILL.md` is the procedure when free text has to be read.

The allow-list on main has three keys:

| Key | Finding | Action | What it does |
| --- | --- | --- | --- |
| `close-open-port` | `cloud:open_port` | `ec2:RevokeSecurityGroupIngress` | Revoke one ingress rule on one security group. Undo is a human authorize of that same rule. The fix does not perform the undo. |
| `restore-bucket-public-access-block` | `cloud:s3_public_access_block_removed` | `s3:PutBucketPublicAccessBlock` | Turn on all four Block Public Access flags for one `ag-demo-*` bucket. |
| `remove-bucket-public-access-block` | `cloud:s3_public_access_block_drift_intended_public` | `s3:PutBucketPublicAccessBlock` | Remove Block Public Access on the one bucket tagged `intended-public=true`. The handler calls `DeletePublicAccessBlockCommand`. |

`src/fixes/registry.ts` builds `ag-fix-<name>` from that list. Terraform in `infra/main.tf` names the same three. Each role is `ag-fix-<name>` with permissions boundary `ag-fix-boundary`. The close-only list in `src/guard/mutating-apis.ts` is `ec2:RevokeSecurityGroupIngress` and `s3:PutBucketPublicAccessBlock`.

A Cursor cloud agent run is how Builder opens the pull request. TODO (Yann): the run URL you want on the slide, and any screen you show of the agent. This repo does not record a run id.

### Where the Grok API is called

`extract()` in `src/grok/client.ts` is the only HTTP call to xAI. Temperature is 0. The wait is 15 seconds. The key is `XAI_API_KEY`. The model is `XAI_MODEL`, or `grok-4.7` when that variable is unset. A missing key returns `no_key` and does not call the network. Other failures are `timeout`, `http_error`, `bad_json`, and `schema_mismatch`. The client does not log the key, the prompt, or the reply.

The only non-test caller is `readAdvisory()` in `src/extractors/advisory/read.ts`. `assessAdvisory()` in the same file calls `readAdvisory()`, then compares the verified ranges with the inventory in code. What Grok decides there: the package name, the vulnerable functions, the affected ranges, the fixed version, and the workaround, and only when `validate` passes. What code decides: whether each fact is supported by the prose and the trusted alert, and which inventory services sit inside the ranges. A miss is `invalid_facts`.

No fix handler imports `extract()`. The three Lambdas do not call Grok. No workflow calls it. The CloudTrail webhook is structured, so that path does not call Grok. The Slack prose call, when the message is free text code cannot parse, is in the Grok Bot app, not in this repo.

So the remediation path does not call the Grok API at runtime. The advisory functions will call it when some caller invokes them. In this repo those functions are invoked by tests, and the tests mock `fetch`.

## Walk trigger to output

Handoffs, in the order the runbook gives them:

1. CloudTrail or Slack reaches AG Lead.
2. AG Lead asks AG Context whether the change is reasonable now.
3. AG Context hands the case to AG Change.
4. AG Change either reuses a registered fix or asks AG Builder to write one. A key off the allow-list stops here, with a human.
5. For a fix that already exists, Lead shows the dry run. The bot invokes the Lambda. It does not call EC2 or S3 itself.
6. For a fix that has to be written, AG Builder hands a Cursor cloud agent a brief. The agent opens a pull request. The plan workflow runs `scripts/check-protected-paths.mjs` and, when `src/fixes/` or `infra/` changed, posts a Terraform plan.
7. The pull request goes back to AG Lead, who checks the allow-list entry, the single action, and the pasted test output.
8. Yann merges. A push to `main` runs `.github/workflows/terraform-apply.yml`, which applies Terraform for `ag-fix-*`.
9. After the yes on the run, the same Lambda is invoked with `apply` set to true.
10. Notion closes the case. TODO (Yann): the handoff into Notion. The brief says AG Lead uses the Notion connector. The page shape is not in the repo.

Human approvals, as the brief lists them, and what the repo actually enforces:

- Build approval. The runbook says that without Yann's yes, the invoke stays a dry run and Builder does not start. TODO (Yann): whether "build approval" is that same yes or a separate click. The repo has no second flag for it.
- Pull request review and merge. Builder does not merge. Yann merges only when he explicitly asks. That is the merge gate in `docs/architecture.md` and `AGENTS.md`.
- `guard-change` label. Required when the pull request touches a protected path. Only Yann adds it. This Pages change adds `.github/workflows/pages.yml`, so this pull request needs that label before the plan check can pass.
- Run approval. `apply` defaults to false. Only a boolean `true` performs the one mutating call, and the bot sets that after Yann's yes.
- Tags as standing consent. That phrase is the brief's. In the code, tags are the recorded intended state and the eligibility check. They are not a substitute for Yann's yes. `auto-remediate=true` is required before the close. `purpose=ag-demo-synthetic` marks the demo. `intended-public=true` is the only signal that may remove a block, and only on `ag-demo-public-10281729`. Case text cannot set it.

## Cursor cloud agents, skills, and rules

Builder hands the code change to a Cursor cloud agent because the bots are not in this repo, and a new fix is a folder, a test, an allow-list line, and one Terraform name. The agent opens a pull request the guard can reject. The skills tell the agent not to merge and not to touch AWS.

Context the agent should receive: the brief says a structured brief only, and never the raw case text. This repo does not contain the bot's handoff payload, so you cannot point at a schema for it here. What the repo does enforce after the fact: event text and advisory text are data. A fix must not follow instructions inside them. The remove-bucket handler does not read case text or finding text. The intended state comes from the tag.

What the rules and skills force into the pull request:

- One hardcoded mutating call. The port fix constructs `RevokeSecurityGroupIngress`. The restore fix constructs the put that turns all four flags on. The remove fix constructs `DeletePublicAccessBlockCommand` on the one bucket.
- The tag guard runs before that call. The guard test fails an allow-listed handler that checks `auto-remediate` after the close.
- Dry run by default. A second run returns `changed: false` when the desired state already holds.
- The allow-list, and `src/guard/audit.ts`. The guard fails a fix off the list, a mutating action that is not on the close-only list, a wildcard action, an open or delete that the guard still blocks, a missing Terraform name, a missing permissions boundary, and an xAI call outside `src/grok/client.ts` and its unit test.
- One fix per pull request. The allow-list edit is called out at the top. If the action is not already on the close-only list, the agent stops and does not edit the list.

## Decisions and trade-offs

Shipped today:

- Fail closed. A bad rule, a guard failure, a Grok timeout, or a schema miss produces no AWS call and no invented fact.
- The main remaining risk in `docs/demo-runbook.md` is a false "authorized" verdict. That is a missed alert. If Context or Change treats the open port as allowed when it was not, Lead does not raise it, and the rule stays. The gates limit a fix that is already in motion. They do not catch a dropped case. Grok is not the backstop, because Grok is not asked to authorize.
- The intake reads the first permission and the first IPv4 range. That can drop a delivery. CloudTrail still has the call.
- Lambda log groups live 14 days (`infra/modules/fix/main.tf`). The API destination allows 1 request per second (`docs/intake.md`).
- One region in the workflows and the architecture doc: `ap-southeast-1`. The sample webhook body uses synthetic account `111122223333`. The live account id stays in `docs/intake.md` and is not repeated here.
- The only open-access fix is the intended-public bucket, and only from the tag.

Before an enterprise rollout, the brief says these change. None of them are built. TODO (Yann) on each choice:

- SSO and RBAC for approvers, in place of one Slack id. Today the brief names Yann, `U0CAKUDP3L0`, as the only approver.
- More than one account. The intake doc describes one account. This repo's Terraform manages `ag-fix-*` in the account the GitHub roles can reach.
- Secrets management. The webhook key stays in the EventBridge connection. `XAI_API_KEY` is an environment variable. TODO (Yann): the store you want instead.
- Audit log retention. The Lambda log groups are 14 days. TODO (Yann): the retention you want for those logs and for the bot transcripts.
- Rate limits. The documented limit is 1 API destination request per second, with 3 retries in 1 hour. TODO (Yann): any other limit.
- An inventory of intended state, in place of tags. Today the intended-public tag is that record for one bucket, and `purpose` plus `auto-remediate` scope the demo. `inventory/services.json` is packages and versions, not buckets and security groups.

## Handling questions that need live changes to the bots

Someone will ask to change a bot during the Q&A. The Grok Bot app click-path is not in this repo.

TODO (Yann): the screens for editing a profile, a skill, or a routine in the Grok Bot app. Do not invent the clicks on stage. What follows is the change itself, and where it actually lives.

Profile. The approver in the brief is Yann, `U0CAKUDP3L0`. The channel in the repo is `#platsec-demo`. The connectors in the brief are Slack, Notion, and GitHub. Changing who may say yes is a change to whatever the bot stores for that id. This repo has no approver list. An example you can say out loud: "Adding a second approver means editing AG Lead's profile or routine where that Slack id is kept. I will not do it from this repo, because the id is not here."

Skills. Two different things share the word.

- A skill file in this repo (`.cursor/skills/writing-remediators/SKILL.md` or `writing-extractors/SKILL.md`) changes by pull request. `.cursor/` is protected, so Yann adds the `guard-change` label before that check can pass. An example: "If we want every new fix to require a second tag, that is an edit to the remediator skill and to the guard. The guard is a protected path. It is a pull request, not a live toggle."
- A skill attached to a bot in the Grok Bot app is the live list. TODO (Yann): how that list is edited. An example of the request, not the clicks: "Detach the extractor skill from AG Change if Change must never read free text." The runbook already says Change does not call Grok.

Routines. AG Lead's CloudTrail webhook routine and the Slack keyword routine are the two the brief names. The webhook endpoint was created by hand. It is not Terraform. The URL is not in the repo. An example: "Pointing the webhook at a new routine means updating the EventBridge API destination `ag-lead-webhook`, which `docs/intake.md` says was created with the AWS CLI, and updating the routine on AG Lead. I do not have the URL in this repo." Another example: "A new CloudTrail event, such as the S3 rule named in the brief, needs a hand-built EventBridge rule plus a routine that accepts that body's fields. This repo will not gain that rule from a bot profile edit."

Voice. TODO (Yann): how voice is turned on, and which bot has it. If someone asks, say you will confirm it in the app after the talk rather than guessing a menu.
