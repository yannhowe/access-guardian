/**
 * Fixes this repo is willing to automate.
 *
 * Each key is a folder under src/fixes. The guard checks that folder's
 * fix.json and policy.json against this list.
 *
 * A fix returns a resource to its recorded intended state. A fix may open
 * access only when that return is proven both by the public=true
 * tag check in the handler and by the IAM tag condition on the fix role.
 * The only case is removing Block Public Access on an S3 bucket that
 * carries all three tags public=true, auto-remediate=true, and
 * purpose=ag-demo-synthetic (exact key and value, case-sensitive). The
 * intended state comes only from the public=true tag, never from
 * case or finding text. Every other fix stays close-only.
 *
 * Does not belong: deleting resources, rotating credentials, stopping
 * instances, or anything that touches more than one resource. The fix does
 * not perform an undo.
 *
 * Adding a key is a human-reviewed change. Call it out at the top of the pull request.
 */
export const ALLOWED_FIXES = {
  'close-open-port': {
    findingKey: 'cloud:open_port',
    action: 'ec2:RevokeSecurityGroupIngress',
    summary: 'Revoke one ingress rule on one security group',
    undo: 'Authorize that same ingress rule again',
  },
  'restore-bucket-public-access-block': {
    findingKey: 'cloud:s3_public_access_block_removed',
    action: 's3:PutBucketPublicAccessBlock',
    summary: 'Turn on all four Block Public Access flags for one bucket',
    undo: 'There is no undo',
  },
  'remove-bucket-public-access-block': {
    findingKey: 'cloud:s3_public_access_block_drift_public',
    action: 's3:PutBucketPublicAccessBlock',
    summary: 'Remove Block Public Access on the one bucket tagged public=true',
    undo: 'There is no undo',
  },
  'contain-iam-user': {
    findingKey: 'identity:on_leave_user_activity',
    action: 'iam:PutUserPolicy',
    summary: 'Attach a deny-all inline policy to one on-leave IAM user',
    undo: 'Delete the inline policy ag-containment-deny',
  },
} as const satisfies Record<
  string,
  {
    readonly findingKey: string;
    readonly action: string;
    readonly summary: string;
    readonly undo: string;
  }
>;

export type AllowedFixKey = keyof typeof ALLOWED_FIXES;
