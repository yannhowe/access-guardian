# Access Guardian

Automated triage and fixes for risky cloud changes.

---

## Problem and assumptions

**Problem**

- Cloud teams already have too many changes to review, and agentic tools will keep adding more.
- Checking whether a change is legitimate is slow, so real risk gets lost in the volume.
- Red flags: a user on leave or not in HR making changes, a bucket's public or private state flipped against its intent, a sensitive port opened to any outside range.

**Assumptions**

- If someone on leave is making changes, their keys or session were probably stolen.
- Tags record intended state (`public=true`, `auto-remediate=true`).
- CloudTrail, IAM and HR are the source of truth, not what anyone claims.

---

## Architecture

```mermaid
flowchart TD
  subgraph intakeBox [Intake]
    cloudtrail[CloudTrail]
    sgRule["ag-cloudtrail<br/>sg-ingress-to-lead"]
    s3Rule["ag-cloudtrail<br/>s3-public-access<br/>to-lead"]
    apiDest["API destination<br/>ag-lead-webhook"]
    cloudtrail --> sgRule --> apiDest
    cloudtrail --> s3Rule --> apiDest
  end

  subgraph botsBox [Bots]
    lead[AG Lead]
    notion["Notion<br/>AG cases"]
    slackCases["Slack<br/>#platform-security"]
    context["AG Context<br/>IAM, HR, tags"]
    changeBot[AG Change]
    builder[AG Builder]
    slackBuild["Slack<br/>#platform-security-<br/>build"]
    yann["Yann<br/>human"]
  end

  subgraph deployBox [Deploy]
    pr[GitHub PR]
    merges[Yann merges]
    applyWf["terraform-<br/>apply.yml"]
    terraform["Terraform deploys<br/>the Lambdas"]
    pr --> merges --> applyWf --> terraform
  end

  subgraph runBox [Run a fix]
    closeFn["ag-fix-<br/>close-open-port<br/>one exact rule"]
    restoreFn["ag-fix-restore-<br/>bucket-public-<br/>access-block"]
    removeFn["ag-fix-remove-<br/>bucket-public-<br/>access-block"]
    containFn["ag-fix-<br/>contain-iam-user<br/>On leave or<br/>Not in HR"]
  end

  subgraph gatesBox [Guardrails]
    allowList[allow-list]
    guardAudit["src/guard audit"]
    optIn["opt-in tags<br/>auto-remediate=true<br/>purpose<br/>ag-demo-synthetic"]
    portRule["sensitive port,<br/>covering range,<br/>or protocol -1<br/>outside private<br/>space is a finding"]
    publicTag["public=true<br/>with both<br/>opt-in tags<br/>opens one bucket"]
    autoRun["auto-remediate when<br/>guards and tags pass<br/>dry run, then apply"]
    humanAsk["A human is asked<br/>only for intent,<br/>a build, a merge,<br/>or a guard change"]
    allowList --> guardAudit --> optIn --> autoRun
  end

  apiDest --> lead
  lead --> notion
  lead <--> slackCases
  slackCases <--> yann
  yann --- humanAsk
  lead --> context --> changeBot
  changeBot -->|"fix exists"| autoRun
  autoRun -->|"matching fix"| runBox
  changeBot -->|"no fix"| builder
  builder --> slackBuild
  builder --> pr
  terraform -->|"deploys"| runBox
  portRule --> closeFn
  publicTag --> removeFn
```

<p class="fine">Same diagram as the README. The EventBridge rules are created by hand and are not in this repo. A fix runs when the guards and the opt-in tags pass. The handler dry-runs unless apply is true. A human is asked for intent, a build, a merge, or a guard change.</p>

---

## On main

- **close-open-port.** One exact revoke: a single port or a from-to range, IPv4 or IPv6, or protocol -1 with no port. A sensitive port, a range that covers one, or protocol -1 is a finding when the source is outside private space.
- **contain-iam-user.** On leave (`identity:on_leave_user_activity`) or Not in HR (`identity:suspicious_user_activity`). The boundary allows only the six IAM user actions.
- **Rule edits.** The daily report reads `ModifySecurityGroupRules` and judges each rule with `classifyIngress()`. A malformed edit is `ingress unparsed` and is not treated as ok. The hand-built EventBridge rule is not in this repo.
- **Daily report.** After apply, set the secret `ag-report-daily-slack-bot-token`. Terraform creates the name and does not set the value.

---

## Trade-offs and what's next

**Trade-offs**

- Writing, vetting and testing every rule takes real effort, but it pays off quickly in cases that close themselves.
- It depends on correct tags. Anything untagged gets reverted to private.
- Each fix does exactly one hardcoded action, which is safe but narrow.

**What's next**

- Analyse CloudTrail for the most frequent changes and build the highest-leverage rules first.
- Block bad changes before they happen, such as public buckets and untagged deploys, with deny policies.
