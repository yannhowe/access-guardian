# Intake

The intake is not in this repo. Create it by hand in the AWS console, in `ap-southeast-1`. Use a scoped IAM principal. Do not use the account root key. Do not commit the webhook URL or the API key.

There is no Lambda. CloudTrail reaches the Grok Bot as an EventBridge API destination POST.

The account must already send management events to EventBridge. This setup does not create a trail.

## 1. Rule

EventBridge rule on the default bus. A workable name is `access-guardian-sg-ingress`.

Set the state to `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. The state `ENABLED` drops CloudTrail events.

Match a successful `AuthorizeSecurityGroupIngress` from EC2. A failed call and a dry-run set `errorCode`, and those events are left out.

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["AuthorizeSecurityGroupIngress"],
    "errorCode": [{ "exists": false }]
  }
}
```

The starter fix closes one IPv4 rule. The transformer below reads that shape. Other ingress APIs use a different request body, so they are not in this rule.

## 2. Connection

EventBridge connection. Authorization type is API key.

The header name is the name the Grok Bot routine expects. The header value is the secret. Type both into the connection. The value stays in AWS. It does not go in git, in a log, or in chat.

## 3. API destination

EventBridge API destination. HTTP method POST. Endpoint is the Grok Bot routine webhook URL (https).

The rule's target is this destination. Give the target an IAM role that may call `events:InvokeApiDestination` on this destination and nothing else.

## 4. Input transformer

The target sends only these fields. In the console, each variable name maps to one path. The template below uses those names. `eventTime` is written out as `time`. `fromPort` and `toPort` are written out together as `portRange`.

| Variable | Path |
| --- | --- |
| eventName | `$.detail.eventName` |
| eventTime | `$.detail.eventTime` |
| account | `$.account` |
| region | `$.region` |
| actorArn | `$.detail.userIdentity.arn` |
| sourceIp | `$.detail.sourceIPAddress` |
| securityGroupId | `$.detail.requestParameters.groupId` |
| fromPort | `$.detail.requestParameters.ipPermissions.items[0].fromPort` |
| toPort | `$.detail.requestParameters.ipPermissions.items[0].toPort` |
| cidr | `$.detail.requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp` |
| requestId | `$.detail.requestID` |

Console template. EventBridge fills each `<variable>` from the path above. It quotes string values, so the bot should accept strings. `from` and `to` may arrive as strings or numbers.

```text
{
  "eventName": <eventName>,
  "time": <eventTime>,
  "account": <account>,
  "region": <region>,
  "actorArn": <actorArn>,
  "sourceIp": <sourceIp>,
  "securityGroupId": <securityGroupId>,
  "portRange": { "from": <fromPort>, "to": <toPort> },
  "cidr": <cidr>,
  "requestId": <requestId>
}
```

The paths assume one permission item and one IPv4 CIDR. A call that adds two rules, or only an IPv6 range, does not fill these paths. EventBridge then has nothing complete to POST. That delivery does not become a half-parsed case.
