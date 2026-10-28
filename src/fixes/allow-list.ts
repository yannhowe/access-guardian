/**
 * Fixes this repo is willing to automate.
 *
 * Each entry is one small change to one resource, with the undo written next to it.
 * A fix that is not on this list must not be built or run here. A human handles it.
 *
 * Belongs on the list: one hardcoded AWS action, an obvious undo, and no data loss.
 * The starter is closing one ingress rule on one security group.
 *
 * Does not belong: deleting resources, rotating credentials, stopping instances,
 * changing VPCs or routes, account-wide settings, or anything that touches
 * more than one resource.
 *
 * Adding a key is a human-reviewed change. Call it out at the top of the pull request.
 */
export const ALLOWED_FIXES = {
  'close-open-port': {
    action: 'RevokeSecurityGroupIngress',
    summary: 'Revoke one ingress rule on one security group',
    undo: 'Authorize that same ingress rule again',
  },
  'restore-bucket-public-access-block': {
    action: 'PutPublicAccessBlock',
    summary: 'Turn on all four public access block settings for one bucket',
    undo: 'Put the recorded bucket public access block back, or remove it if none was recorded',
  },
} as const satisfies Record<string, { readonly action: string; readonly summary: string; readonly undo: string }>;

export type AllowedFixKey = keyof typeof ALLOWED_FIXES;
