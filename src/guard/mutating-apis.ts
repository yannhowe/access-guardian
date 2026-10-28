/**
 * Close-only IAM actions a fix policy may use.
 *
 * A mutating action in policy.json must be one of these strings.
 * Reads (Describe, List, Get) are not listed here.
 * This file only lists names. It does not call AWS.
 *
 * s3:PutBucketPublicAccessBlock stays on this list because AWS authorizes
 * DeletePublicAccessBlock with that same action. A fix may open access only
 * when it returns a resource to its intended state. That has to be proven
 * both by the intended-public=true tag check in the handler and by the IAM
 * tag condition on the fix role. Every other fix stays close-only. Do not
 * add an action that opens or deletes.
 */
export const CLOSE_ONLY_ACTIONS = [
  'ec2:RevokeSecurityGroupIngress',
  's3:PutBucketPublicAccessBlock',
] as const;
