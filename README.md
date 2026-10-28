# Access Guardian

Defensive cloud security demo. Grok Bot teammates (AG Lead, AG Context, AG Change, AG Builder) do the judging and the conversation. This repo keeps the hard gates.

- `src/grok/client.ts` is the only xAI call. Strict JSON schema, temperature 0, 15 second timeout, fails closed.
- `src/fixes/` is the allow-list, the registry, and one starter fix: revoke one security group ingress rule. Dry-run unless `apply` is `true`.
- `tests/guard.test.ts` blocks a fix that is not on the list, a fix with more than one action, and any xAI call outside the Grok client.
- `src/extractors/advisory/` reads advisory prose through `extract()` and compares the verified ranges with `inventory/services.json`. Follow `.cursor/skills/writing-extractors/SKILL.md`.
- `docs/intake.md` describes the EventBridge intake. It was created by hand with the AWS CLI. There is no Terraform here.
- `docs/demo-runbook.md` is the runbook.

Node 20 or newer.

```bash
npm test
npx tsc --noEmit
```

`XAI_API_KEY` is read from the environment only when you mean to call the live API. `XAI_MODEL` is optional (default `grok-4.7`). Tests do not need either value. Do not commit them.
