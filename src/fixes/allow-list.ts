/**
 * Fixes this repo is willing to automate.
 *
 * Each key is a folder under src/fixes. The guard checks that folder's
 * fix.json and policy.json against this list.
 *
 * A fix returns a resource to its recorded intended state. The only case
 * where that opens access: a fix may remove Block Public Access on an S3
 * bucket that carries all three tags intended-public=true,
 * auto-remediate=true, and purpose=ag-demo-synthetic (exact key and value,
 * case-sensitive). The intended state comes only from the intended-public=true
 * tag, never from case or finding text.
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
    findingKey: 'cloud:s3_public_access_block_drift_intended_public',
    action: 's3:PutBucketPublicAccessBlock',
    summary: 'Remove Block Public Access on the one bucket tagged intended-public=true',
    undo: 'There is no undo',
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
