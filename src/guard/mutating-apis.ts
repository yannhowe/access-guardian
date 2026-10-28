/**
 * Close-only IAM actions a fix policy may use.
 *
 * A mutating action in policy.json must be one of these strings.
 * Reads (Describe, List, Get) are not listed here.
 * This file only lists names. It does not call AWS.
 *
 * s3:PutBucketPublicAccessBlock is here so a later fix can turn public
 * access off. Do not add an action that opens or deletes.
 */
export const CLOSE_ONLY_ACTIONS = [
  'ec2:RevokeSecurityGroupIngress',
  's3:PutBucketPublicAccessBlock',
] as const;
