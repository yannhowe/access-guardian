# Intake

The intake is not code in this repo. It was created by hand with the AWS CLI in `ap-southeast-1`. The account id is not stored in this repo. There is no Terraform here, and there is no Lambda on this path. An end-to-end test on a throwaway security group was delivered successfully.

The webhook URL and the API key are not in this repo. The key is held only in the EventBridge connection.

## Rule

EventBridge rule `ag-cloudtrail-sg-ingress-to-lead` on the default bus.

It matches successful `AuthorizeSecurityGroupIngress` CloudTrail events. A failed call and a dry-run set `errorCode`, and those events are left out. This file does not document a second rule.

## Connection

EventBridge connection `ag-lead-webhook`.

Authorization is an API key. The header is `Authorization: Bearer <key>`. The key stays in the connection.

## API destination

API destination `ag-lead-webhook`. HTTP method POST. Invocation rate is 1 request per second. The endpoint is the AG Lead Grok Bot routine webhook.

## Target role and retries

The rule target uses IAM role `ag-eventbridge-to-ag-lead`. That role may call `events:InvokeApiDestination` on destination `ag-lead-webhook` and nothing else.

The target retries 3 times within 1 hour.

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

## Not part of this repo

The older rule `platsec-cloudtrail-open-ssh` and its Lambda are disabled. They are not part of this repo.
