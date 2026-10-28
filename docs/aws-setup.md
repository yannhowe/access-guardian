# AWS setup

This is the one-time bootstrap. It is not created by the Terraform in `infra/`. Do it by hand in `ap-southeast-1`, with a scoped principal. Do not use the account root key. Do not commit account ids, bucket names, role ARNs, or keys.

The fix Lambdas and their roles are created later by `terraform apply`. The boundary, the state backend, and the two GitHub roles must already exist.

## GitHub OIDC

Create an IAM OIDC provider for GitHub Actions if the account does not have one. Use GitHub's Actions OIDC issuer and the audience `sts.amazonaws.com`.

Trust the plan role and the apply role only for this repository. Restrict the plan role to pull request workflows, and the apply role to pushes on `main`.

## Plan role and apply role

Create two roles.

- `AG_TF_PLAN_ROLE_ARN` can read. It needs to read the state bucket and the lock table, and to read `ag-fix-*` roles, role policies, functions, and log groups. It does not create, change, or delete them.
- `AG_TF_APPLY_ROLE_ARN` can change only `ag-fix-*` roles, their inline policies, `ag-fix-*` functions, and `/aws/lambda/ag-fix-*` log groups. It can write the state object and the lock table. It can pass `ag-fix-*` roles to `lambda.amazonaws.com`. It cannot change the boundary policy, other roles, or other functions.

Put the two ARNs in the repository variables of those names.

## Boundary policy

Create a customer managed policy named `ag-fix-boundary`. Every fix role is created with this policy as its permissions boundary. The boundary is the ceiling. The document in git is `bootstrap/boundary.json`. Terraform does not create or update that policy. A merge does not publish it.

It may allow:

- `ec2:DescribeSecurityGroupRules` and `ec2:DescribeSecurityGroups`
- `ec2:RevokeSecurityGroupIngress` on security groups (`arn:aws:ec2:*:*:security-group/*`)
- `s3:GetBucketTagging` and `s3:GetBucketPublicAccessBlock` on `arn:aws:s3:::ag-demo-*`
- `s3:PutBucketPublicAccessBlock` on `arn:aws:s3:::ag-demo-*` for the bucket public access block fixes. AWS authorizes `DeletePublicAccessBlock` with this same action. A fix may open access only when it returns a resource to its intended state, proven both by the public=true tag check in the handler and by the IAM tag condition on the fix role. The only fix that may remove the block is the one for a bucket tagged `public=true`, `auto-remediate=true`, and `purpose=ag-demo-synthetic`. Every other fix stays close-only.
- `logs:CreateLogStream` and `logs:PutLogEvents` on `/aws/lambda/ag-fix-*`
- These six IAM actions, and no other IAM actions, on `arn:aws:iam::*:user/*` only. The resource is users. It is not roles, groups, or policies.
  - `iam:GetUser`
  - `iam:ListUserTags`
  - `iam:GetUserPolicy`
  - `iam:ListAttachedUserPolicies`
  - `iam:ListGroupsForUser`
  - `iam:PutUserPolicy`

That IAM allow is the ceiling for `contain-iam-user`. The role policy still requires `auto-remediate=true` and `purpose=ag-demo-synthetic` on every one of those actions except `iam:ListUserTags`.

The exact exception to the old `iam:*` and `Put*Policy` ban is those six actions on users. `iam:PutUserPolicy` is the only `Put*Policy` action the boundary allows, and only on `arn:aws:iam::*:user/*`.

An explicit deny on `arn:aws:iam::*:user/*` uses `NotAction` for exactly those six. Every other action on a user stays denied, including `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:DeleteUser`, `iam:CreateUser`, and `iam:DeleteUserPolicy`. A second explicit deny is `iam:*` with `NotResource` `arn:aws:iam::*:user/*`, so `iam:PassRole` and `iam:PutRolePolicy` stay denied on roles and on every other non-user resource. There is no wildcard IAM allow.

`s3:PutBucketPolicy` stays on its own explicit deny, with the other S3 `Put*Policy` actions (`s3:PutAccessPointPolicy`, `s3:PutAccessPointPolicyForObjectLambda`, and `s3:PutMultiRegionAccessPointPolicy`). That deny does not name `iam:PutUserPolicy` or `s3:PutBucketPublicAccessBlock`. The boundary does not gain `s3:DeleteBucketPublicAccessBlock`.

It must not allow `Authorize*`, `Delete*PublicAccessBlock`, any IAM action outside the six, or any `Put*Policy` action other than `iam:PutUserPolicy` on users.

`iam:DeleteUserPolicy` is not one of the six. The allow-list undo for `contain-iam-user` is to delete the inline policy `ag-containment-deny`. That undo needs `iam:DeleteUserPolicy`. This boundary does not grant it. A person deletes that inline policy. The fix does not.

Put the policy ARN in the repository variable `AG_FIX_BOUNDARY_ARN`. Terraform refuses any other policy name. Do not write the ARN in git.

### Publishing a new version

This policy stays outside `terraform apply`. The apply role would need rights to publish a new version of the boundary on the fix roles, including its own ceiling. That is a privilege-escalation path. The apply role still cannot change the boundary. Yann publishes a new version by hand, with a scoped principal. Do not use the account root key.

There is no bootstrap script in this repository. The hand command is `aws iam create-policy-version` with `--set-as-default`. IAM keeps at most 5 versions of a customer managed policy. When 5 versions already exist, delete the oldest version that is not the default, then create the new one. The policy ARN is `$AG_FIX_BOUNDARY_ARN`.

```bash
aws iam create-policy-version \
  --policy-arn "$AG_FIX_BOUNDARY_ARN" \
  --policy-document file://bootstrap/boundary.json \
  --set-as-default
```

When that call reports a version limit, list the versions, delete one non-default version, and run the create command again:

```bash
aws iam list-policy-versions --policy-arn "$AG_FIX_BOUNDARY_ARN"
aws iam delete-policy-version \
  --policy-arn "$AG_FIX_BOUNDARY_ARN" \
  --version-id <oldest-non-default>
```

The boundary ARN has no version id, so the existing fix roles use the default version. Setting the new version as default applies it without a Terraform apply and without editing the roles.

## State

Create an S3 bucket for Terraform state and a DynamoDB table for the lock. Turn on bucket encryption and block public access. Do not put the bucket name in git.

Repository variables:

- `AG_TF_STATE_BUCKET`
- `AG_TF_STATE_KEY`
- `AG_TF_STATE_REGION` (use `ap-southeast-1`)
- `AG_TF_LOCK_TABLE`

The workflows pass those through `-backend-config`.

## Bots

The Grok Bot teammates invoke a fix. They do not deploy it. Give them `lambda:InvokeFunction` on `ag-fix-*` only. They do not get `ec2:*`, `iam:*`, or permission to change the function.

`ag-bot-invoker` is created outside Terraform (manual). AG Lead assumes it. Its permission is `lambda:InvokeFunction` on `ag-fix-*`. `ag-reader` handles read-only checks and is created outside Terraform (manual). TODO: move both roles into `infra/`.

A dry run omits `apply` or sets it to false. After Yann's yes, the bot invokes the same function with `apply` set to true.

## Demo resources

Tag any security group this demo may change with `purpose=ag-demo-synthetic` and `auto-remediate=true`. The close-open-port role can revoke ingress only when both tags match. The handler refuses, including on a dry run that would revoke, unless `auto-remediate=true` exactly, and it returns `MissingAutoRemediateTag`. It also calls `classifyIngress()` on the named rule and returns `status` `refused` without revoking when the verdict is `ok`. A sensitive port on a `public=true` group is still revoked. A missing `purpose` tag fails the revoke in IAM, and the Lambda returns that AWS error.

A bucket the restore fix may change uses a name that starts with `ag-demo-`. The handler requires `purpose=ag-demo-synthetic` and `auto-remediate=true`, and it leaves a bucket tagged `public=true` unchanged. The restore role is scoped to `arn:aws:s3:::ag-demo-*` and has no tag condition in IAM.

The remove fix accepts only bucket `ag-demo-public-10281729`. The handler requires `public=true`, `auto-remediate=true`, and `purpose=ag-demo-synthetic`. IAM on that role requires `public=true` for the mutating action, on that one bucket ARN.
