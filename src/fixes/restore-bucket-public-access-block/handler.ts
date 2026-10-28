/**
 * Lambda ag-fix-restore-bucket-public-access-block.
 *
 * One close call: s3:PutBucketPublicAccessBlock.
 * Two reads: s3:GetBucketTagging and s3:GetBucketPublicAccessBlock.
 *
 * The S3 SDK class for that put is PutPublicAccessBlockCommand. The IAM
 * action name is PutBucketPublicAccessBlock. The import alias is that same
 * SDK class under the IAM name, so the guard can match the call to the policy.
 * The read alias is the same kind of rename for GetPublicAccessBlockCommand.
 *
 * apply defaults to false. Only a boolean true writes. This file does not
 * call Grok. It does not remove the block, and it does not change account
 * settings.
 *
 * What Grok decides: nothing.
 * What code decides: whether the bucket name is valid, whether the bucket
 * is tagged purpose=ag-demo-synthetic, whether all four Block Public Access
 * flags are already true, and whether the one put is sent.
 *
 * The four flags on that put are hardcoded true. This file never sends false.
 */
import {
  GetBucketTaggingCommand,
  GetPublicAccessBlockCommand as GetBucketPublicAccessBlockCommand,
  PutPublicAccessBlockCommand as PutBucketPublicAccessBlockCommand,
  S3Client,
} from '@aws-sdk/client-s3';

export const ACTION = 's3:PutBucketPublicAccessBlock' as const;

/** Hardcoded on. Every put and every dry-run report uses this object. */
export const PUBLIC_ACCESS_BLOCK = {
  BlockPublicAcls: true,
  IgnorePublicAcls: true,
  BlockPublicPolicy: true,
  RestrictPublicBuckets: true,
} as const;

const PURPOSE = 'ag-demo-synthetic';
const MISSING_TAGS = 'NoSuchTagSet';
const MISSING_BLOCK = 'NoSuchPublicAccessBlockConfiguration';

/**
 * ag-demo- plus a legal bucket tail. 9 to 63 characters, lowercase, no
 * adjacent dots, and not an access-point alias suffix.
 */
const BUCKET_NAME = /^ag-demo-[a-z0-9](?:[a-z0-9.-]{0,53}[a-z0-9])?$/;

export type AwsClient = {
  send(command: unknown): Promise<unknown>;
};

export type RestoreBucketPublicAccessBlockInput = {
  bucket: string;
  apply: boolean;
};

export type FixResult =
  | {
      ok: true;
      changed: boolean;
      dryRun: boolean;
      action: typeof ACTION;
      bucket: string;
      publicAccessBlock: typeof PUBLIC_ACCESS_BLOCK;
      reason: 'dry_run' | 'already_blocked' | 'restored';
    }
  | {
      ok: false;
      changed: false;
      errorCode: string;
      errorMessage: string;
    };

type Planned = RestoreBucketPublicAccessBlockInput;

type Failure = {
  ok: false;
  changed: false;
  errorCode: string;
  errorMessage: string;
};

export async function handler(event: unknown): Promise<FixResult> {
  const client = new S3Client({});
  return handleRestoreBucketPublicAccessBlock(event, client);
}

/**
 * Validate the event, require the demo tag, and put the four true flags
 * only when apply is true and the bucket is not already blocked.
 */
export async function handleRestoreBucketPublicAccessBlock(
  event: unknown,
  client: AwsClient,
): Promise<FixResult> {
  const parsed = parseEvent(event);
  if (!parsed.ok) {
    return { ok: false, changed: false, errorCode: 'InvalidInput', errorMessage: parsed.message };
  }

  const input = parsed.value;
  const tagged = await bucketIsTagged(client, input.bucket);
  if (!tagged.ok) {
    return tagged.failure;
  }

  const blocked = await bucketIsFullyBlocked(client, input.bucket);
  if (!blocked.ok) {
    return blocked.failure;
  }

  const body = {
    action: ACTION,
    bucket: input.bucket,
    publicAccessBlock: { ...PUBLIC_ACCESS_BLOCK },
  };

  if (blocked.fullyBlocked) {
    return { ok: true, changed: false, dryRun: !input.apply, ...body, reason: 'already_blocked' };
  }

  if (!input.apply) {
    return { ok: true, changed: false, dryRun: true, ...body, reason: 'dry_run' };
  }

  try {
    await client.send(
      new PutBucketPublicAccessBlockCommand({
        Bucket: input.bucket,
        PublicAccessBlockConfiguration: { ...PUBLIC_ACCESS_BLOCK },
      }),
    );
  } catch (err) {
    return { ok: false, changed: false, ...readAwsError(err) };
  }

  return { ok: true, changed: true, dryRun: false, ...body, reason: 'restored' };
}

function parseEvent(event: unknown): { ok: true; value: Planned } | { ok: false; message: string } {
  if (typeof event !== 'object' || event === null || Array.isArray(event)) {
    return { ok: false, message: 'input must be an object' };
  }
  const record = event as Record<string, unknown>;

  if (typeof record.bucket !== 'string' || !isDemoBucket(record.bucket)) {
    return {
      ok: false,
      message:
        'bucket must be a lowercase name from 9 to 63 characters that starts with ag-demo- and uses only letters, digits, dots, and hyphens',
    };
  }
  if ('apply' in record && typeof record.apply !== 'boolean') {
    return { ok: false, message: 'apply must be a boolean' };
  }

  return {
    ok: true,
    value: {
      bucket: record.bucket,
      apply: record.apply === true,
    },
  };
}

/** A synthetic demo bucket name. The role can only touch the ag-demo- prefix. */
function isDemoBucket(value: string): boolean {
  if (!BUCKET_NAME.test(value)) {
    return false;
  }
  if (value.includes('..')) {
    return false;
  }
  if (value.endsWith('-s3alias') || value.endsWith('--ol-s3')) {
    return false;
  }
  return true;
}

async function bucketIsTagged(
  client: AwsClient,
  bucket: string,
): Promise<{ ok: true } | { ok: false; failure: Failure }> {
  let described: unknown;
  try {
    described = await client.send(new GetBucketTaggingCommand({ Bucket: bucket }));
  } catch (err) {
    if (hasErrorCode(err, MISSING_TAGS)) {
      return { ok: false, failure: notTagged() };
    }
    return { ok: false, failure: { ok: false, changed: false, ...readAwsError(err) } };
  }

  const purpose = readPurpose(described);
  if (purpose === 'bad') {
    return {
      ok: false,
      failure: {
        ok: false,
        changed: false,
        errorCode: 'InvalidResponse',
        errorMessage: 'GetBucketTagging did not return a tag set',
      },
    };
  }
  if (purpose !== PURPOSE) {
    return { ok: false, failure: notTagged() };
  }
  return { ok: true };
}

function notTagged(): Failure {
  return {
    ok: false,
    changed: false,
    errorCode: 'BucketNotTagged',
    errorMessage: 'bucket must be tagged purpose=ag-demo-synthetic',
  };
}

/**
 * The purpose tag value, when there is exactly one. undefined means the key
 * is absent. 'bad' means the payload cannot be trusted.
 */
function readPurpose(payload: unknown): string | undefined | 'bad' {
  if (typeof payload !== 'object' || payload === null) {
    return 'bad';
  }
  const tagSet = (payload as { TagSet?: unknown }).TagSet;
  if (!Array.isArray(tagSet)) {
    return 'bad';
  }

  let purpose: string | undefined;
  for (const item of tagSet) {
    if (typeof item !== 'object' || item === null) {
      return 'bad';
    }
    const tag = item as { Key?: unknown; Value?: unknown };
    if (typeof tag.Key !== 'string' || typeof tag.Value !== 'string') {
      return 'bad';
    }
    if (tag.Key !== 'purpose') {
      continue;
    }
    if (purpose !== undefined) {
      return 'bad';
    }
    purpose = tag.Value;
  }
  return purpose;
}

async function bucketIsFullyBlocked(
  client: AwsClient,
  bucket: string,
): Promise<{ ok: true; fullyBlocked: boolean } | { ok: false; failure: Failure }> {
  let described: unknown;
  try {
    described = await client.send(new GetBucketPublicAccessBlockCommand({ Bucket: bucket }));
  } catch (err) {
    if (hasErrorCode(err, MISSING_BLOCK)) {
      return { ok: true, fullyBlocked: false };
    }
    return { ok: false, failure: { ok: false, changed: false, ...readAwsError(err) } };
  }

  const fullyBlocked = readFullyBlocked(described);
  if (fullyBlocked === 'bad') {
    return {
      ok: false,
      failure: {
        ok: false,
        changed: false,
        errorCode: 'InvalidResponse',
        errorMessage: 'GetBucketPublicAccessBlock did not return a configuration',
      },
    };
  }
  return { ok: true, fullyBlocked };
}

/** True when every flag is boolean true. 'bad' means the payload cannot be trusted. */
function readFullyBlocked(payload: unknown): boolean | 'bad' {
  if (typeof payload !== 'object' || payload === null) {
    return 'bad';
  }
  const config = (payload as { PublicAccessBlockConfiguration?: unknown }).PublicAccessBlockConfiguration;
  if (typeof config !== 'object' || config === null) {
    return 'bad';
  }
  const record = config as Record<string, unknown>;
  return (
    record.BlockPublicAcls === true &&
    record.IgnorePublicAcls === true &&
    record.BlockPublicPolicy === true &&
    record.RestrictPublicBuckets === true
  );
}

function hasErrorCode(err: unknown, code: string): boolean {
  if (typeof err !== 'object' || err === null) {
    return false;
  }
  const record = err as { name?: unknown; Code?: unknown };
  return record.name === code || record.Code === code;
}

function readAwsError(err: unknown): { errorCode: string; errorMessage: string } {
  if (typeof err === 'string' && err.length > 0) {
    return { errorCode: 'Unknown', errorMessage: err };
  }
  if (typeof err !== 'object' || err === null) {
    return { errorCode: 'Unknown', errorMessage: 'AWS call failed' };
  }
  const record = err as { name?: unknown; Code?: unknown; message?: unknown; Message?: unknown };
  const errorCode = stringField(record.name) ?? stringField(record.Code) ?? 'Unknown';
  const errorMessage = stringField(record.message) ?? stringField(record.Message) ?? 'AWS call failed';
  return { errorCode, errorMessage };
}

function stringField(value: unknown): string | undefined {
  if (typeof value === 'string' && value.length > 0) {
    return value;
  }
  return undefined;
}
