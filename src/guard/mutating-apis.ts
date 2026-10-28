/**
 * Mutating AWS API names the guard knows how to see.
 *
 * A fix action must be one of these strings, and it must also be on the allow-list.
 * Add a name here in the same pull request that adds a new action.
 * This file only lists names. It does not call AWS.
 *
 * The list is not every AWS API. A command constructor that is not a
 * Describe, List, or Get still fails the guard when its name is missing here.
 */
export const MUTATING_APIS = [
  'RevokeSecurityGroupIngress',
  'AuthorizeSecurityGroupIngress',
  'RevokeSecurityGroupEgress',
  'AuthorizeSecurityGroupEgress',
  'ModifySecurityGroupRules',
  'UpdateSecurityGroupRuleDescriptionsIngress',
  'UpdateSecurityGroupRuleDescriptionsEgress',
  'CreateSecurityGroup',
  'DeleteSecurityGroup',
  'PutBucketPolicy',
  'PutBucketAcl',
  'PutPublicAccessBlock',
  'PutBucketPublicAccessBlock',
  'DeleteBucketPublicAccessBlock',
  'DeleteBucket',
  'AttachRolePolicy',
  'AttachUserPolicy',
  'AttachGroupPolicy',
  'PutRolePolicy',
  'PutUserPolicy',
  'DeleteRolePolicy',
  'CreateAccessKey',
  'DeleteAccessKey',
  'UpdateAccessKey',
  'CreateUser',
  'DeleteUser',
  'TerminateInstances',
  'StopInstances',
  'StartInstances',
  'RunInstances',
  'ModifyVpcAttribute',
  'CreateRoute',
  'DeleteRoute',
] as const;
