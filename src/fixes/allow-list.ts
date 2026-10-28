/**
 * Fixes this repo is willing to automate.
 *
 * Each key is a folder under src/fixes. The guard checks that folder's
 * fix.json and policy.json against this list.
 *
 * Belongs on the list: one close or tighten action on one resource, with an
 * obvious undo, and no data loss.
 *
 * Does not belong: opening access, deleting resources, rotating credentials,
 * stopping instances, or anything that touches more than one resource.
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
