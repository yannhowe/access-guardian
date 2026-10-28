# Intake

Rule `ag-cloudtrail-sg-ingress-to-lead` and its one target are Terraform in `infra/intake.tf`. They were created by hand in `ap-southeast-1` and are imported. There is no Lambda on this path. The account id is not stored in this repo. Pass the account the live rule already filters as `ag_cloudtrail_sg_ingress_account_id`.

The webhook URL and the API key are not in this repo. The key is held only in the EventBridge connection. Terraform does not create, update, or rotate connection `ag-lead-webhook`, the secret inside it, or API destination `ag-lead-webhook`. The connection is a read-only data source. The destination ARN is the variable `ag_lead_webhook_api_destination_arn`. Apply cannot change webhook auth.

The target id and the role ARN are not in this repo. Pass `ag_cloudtrail_sg_ingress_target_id` and `ag_eventbridge_to_ag_lead_role_arn` at plan time.

## Rule

EventBridge rule `ag-cloudtrail-sg-ingress-to-lead` on the default bus.

It matches successful `AuthorizeSecurityGroupIngress` and `ModifySecurityGroupRules` CloudTrail events. A failed call and a dry-run set `errorCode`, and those events are left out.

The pattern keeps `source` `aws.ec2`, `detail-type` `AWS API Call via CloudTrail`, the account passed at plan time, `detail.eventSource` `ec2.amazonaws.com`, and `detail.errorCode` exists false. `detail.eventName` is `AuthorizeSecurityGroupIngress` and `ModifySecurityGroupRules`.

Description and tags on the live rule are left as they are. Terraform does not rewrite them.

## Connection

EventBridge connection `ag-lead-webhook`.

Authorization is an API key. The header is `Authorization: Bearer <key>`. The key stays in the connection. `infra/intake.tf` reads the connection by name and refuses to plan unless that connection is still an API key connection with a secret. It does not read the key.

## API destination

API destination `ag-lead-webhook`. HTTP method POST. Invocation rate is 1 request per second. The endpoint is the AG Lead Grok Bot routine webhook. The destination id is `6d9dbab1-d10f-4dd6-9951-f505036e202f`. Terraform does not manage the destination. The target ARN variable must be that destination.

## Target role and retries

The rule target uses IAM role `ag-eventbridge-to-ag-lead`. That role may call `events:InvokeApiDestination` on destination `ag-lead-webhook` and nothing else.

The target retries 3 times within 1 hour.

The input transformer and the retry policy stay as they are on the live target. Terraform ignores those fields so apply does not rewrite them. The fields are described below.

## Input transformer

Every value below is sent as a string. `protocol`, `fromPort`, `toPort`, and `cidr` come from the first permission and the first IP range only. `source` is the constant `aws-cloudtrail`, not a field copied from the event.

| Field | Where it comes from |
| --- | --- |
| eventName | `$.detail.eventName` |
| eventTime | `$.detail.eventTime` |
| account | `$.account` |
| region | `$.region` |
| actorArn | `$.detail.userIdentity.arn` |
| sourceIp | `$.detail.sourceIPAddress` |
| groupId | `$.detail.requestParameters.groupId` |
| protocol | `$.detail.requestParameters.ipPermissions.items[0].ipProtocol` |
| fromPort | `$.detail.requestParameters.ipPermissions.items[0].fromPort` |
| toPort | `$.detail.requestParameters.ipPermissions.items[0].toPort` |
| cidr | `$.detail.requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp` |
| requestId | `$.detail.requestID` |
| eventId | `$.detail.eventID` |
| source | constant `aws-cloudtrail` |

A call that adds two rules, or only an IPv6 range, does not fill `cidr` from these paths. EventBridge then has nothing complete to POST. That delivery does not become a half-parsed case.

`ModifySecurityGroupRules` uses a different request shape. The transformer is unchanged, so a modify event may leave `groupId`, `protocol`, `fromPort`, `toPort`, and `cidr` empty. That delivery does not become a half-parsed case. The daily report reads `ModifySecurityGroupRules` from CloudTrail on its own. It does not depend on this transformer.

## Apply role

`ag-tf-apply` needs these actions to plan and apply this rule. Scope them to rule `ag-cloudtrail-sg-ingress-to-lead` on the default bus in `ap-southeast-1`, and to connection `ag-lead-webhook`.

- `events:DescribeRule` reads the rule.
- `events:ListTagsForResource` reads the rule tags. Terraform does not change tags, so this apply does not call `events:TagResource` or `events:UntagResource`.
- `events:PutRule` updates the event pattern. The call does not set a rule role, so it does not need `iam:PassRole`.
- `events:ListTargetsByRule` reads the target. There is no separate describe call for a target.
- `events:DescribeConnection` reads connection `ag-lead-webhook`. It does not read the secret value.

`events:PutTargets` and `iam:PassRole` on `ag-eventbridge-to-ag-lead` are not used when the target matches. Do not apply a plan that changes the target. `events:DescribeApiDestination` is not used. The destination ARN is a variable. No connection, secret, or destination write is used.

The plan role needs the same reads (`events:DescribeRule`, `events:ListTagsForResource`, `events:ListTargetsByRule`, `events:DescribeConnection`) and does not need `events:PutRule`.

## Second rule

EventBridge rule `ag-cloudtrail-s3-public-access-to-lead` is created outside Terraform (manual). Its event pattern is not written in this repository. This change does not add it.

TODO: move `ag-cloudtrail-s3-public-access-to-lead` into `infra/`.

## Not part of this repo

The older rule `platsec-cloudtrail-open-ssh` and its Lambda are disabled. They are not part of this repo. The `platsec-cloudtrail-intake` Lambda is not part of this repo. This change does not add either Lambda.
