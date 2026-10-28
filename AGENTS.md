# Agent rules

Repo code changes go through Cursor cloud agent pull requests. Paste the full output of `npm test` and `npx tsc --noEmit` in the pull request. Merge only when Yann explicitly asks.

Write plain English. Do not use em dashes in docs or code comments.

Synthetic data only. Defensive remediation only. A fix removes or tightens access. It does not include exploit payloads or attack steps.

Keep secrets out of code, logs, tests, fixtures, and pull requests. Do not print them. The xAI key is the environment variable `XAI_API_KEY`. Tests mock the network and must pass with no key set.

Use a scoped IAM principal. Do not use the AWS account root key.

Grok is called only through `extract()` in `src/grok/client.ts`. That call returns schema-valid JSON or a typed failure. It does not decide a verdict. A new call site must say what Grok decides and what code decides.

A new fix must be on the allow-list in `src/fixes/allow-list.ts`, with exactly one hardcoded action, and it must pass the guard test. Dry-run is the default. A real AWS call needs an explicit apply flag set by our code after Yann's yes.

There is no Terraform in this repo. The EventBridge intake is created by hand. Read `docs/intake.md` before describing it. Do not add infrastructure code to stand that intake up.

When you finish a task, say in plain English what changed, why, and how you checked it.
