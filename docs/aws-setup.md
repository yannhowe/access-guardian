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

Create a customer managed policy named `ag-fix-boundary`. Every fix role is created with this policy as its permissions boundary. The boundary is the ceiling.

It may allow:

- `ec2:DescribeSecurityGroupRules`
- `ec2:RevokeSecurityGroupIngress` on security groups
- `s3:PutBucketPublicAccessBlock` for the bucket public access block fixes. AWS authorizes DeletePublicAccessBlock with this same action. The only fix that may remove the block is the one for a bucket tagged intended-public=true, auto-remediate=true, and purpose=ag-demo-synthetic
- `logs:CreateLogStream` and `logs:PutLogEvents` on `/aws/lambda/ag-fix-*`

It must not allow `Authorize*`, `Delete*PublicAccessBlock`, `iam:*`, or `Put*Policy`.

Put the policy ARN in the repository variable `AG_FIX_BOUNDARY_ARN`. Terraform refuses any other policy name.

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

A dry run omits `apply` or sets it to false. After Yann's yes, the bot invokes the same function with `apply` set to true.

## Demo resources

Tag any security group this demo may change with `purpose=ag-demo-synthetic`. The close-open-port role can revoke ingress only on a group with that tag. A group without the tag fails the revoke, and the Lambda returns that AWS error.
