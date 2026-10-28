/**
 * Lambda ag-fix-remove-bucket-public-access-block.
 *
 * One mutating call: DeletePublicAccessBlockCommand on one bucket. The
 * command is imported and constructed under that real name. AWS authorizes
 * that API with s3:PutBucketPublicAccessBlock. ACTION is that IAM action.
 * It is not an alias for the command.
 *
 * Two reads: s3:GetBucketTagging and s3:GetBucketPublicAccessBlock.
 * The read alias renames GetPublicAccessBlockCommand to the IAM action
 * name so the guard can match that read. The delete is not renamed.
 *
 * apply defaults to false. Only a boolean true deletes the block. This file
 * does not call Grok. It does not put a block. It does not change bucket
 * policies, ACLs, objects, or account-level settings.
 *
 * What Grok decides: nothing.
 * What code decides: whether the bucket is ag-demo-public-10281729, whether
 * the three tags are exactly present, whether a block configuration exists,
 * and whether the one delete is sent. Case text and finding text are not read.
 * The intended state comes only from the public=true tag.
 */
import {
  DeletePublicAccessBlockCommand,
  GetBucketTaggingCommand,
  GetPublicAccessBlockCommand as GetBucketPublicAccessBlockCommand,
  S3Client,
} from '@aws-sdk/client-s3';

export const ACTION = 's3:PutBucketPublicAccessBlock' as const;
export const OPERATION = 'DeletePublicAccessBlock' as const;
export const TARGET_BUCKET = 'ag-demo-public-10281729' as const;

const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';
const AUTO_REMEDIATE_TAG_VALUE = 'true';
const PUBLIC_TAG_KEY = 'public';
const PUBLIC_TAG_VALUE = 'true';
const PURPOSE_TAG_KEY = 'purpose';
const PURPOSE_TAG_VALUE = 'ag-demo-synthetic';
const MISSING_TAGS = 'NoSuchTagSet';
const MISSING_BLOCK = 'NoSuchPublicAccessBlockConfiguration';

type Tag = { Key?: unknown; Value?: unknown };

function hasExactTag(tags: readonly Tag[], key: string, value: string): boolean {
  for (const tag of tags) {
    if (tag.Key === key && tag.Value === value) {
      return true;
    }
  }
  return false;
}

function hasAutoRemediateTag(tags: readonly Tag[]): boolean {
  return hasExactTag(tags, AUTO_REMEDIATE_TAG_KEY, AUTO_REMEDIATE_TAG_VALUE);
}

function hasPublicTag(tags: readonly Tag[]): boolean {
  return hasExactTag(tags, PUBLIC_TAG_KEY, PUBLIC_TAG_VALUE);
}

function hasDemoPurpose(tags: readonly Tag[]): boolean {
  return hasExactTag(tags, PURPOSE_TAG_KEY, PURPOSE_TAG_VALUE);
}

export type AwsClient = {
  send(command: unknown): Promise<unknown>;
};

export type RemoveBucketPublicAccessBlockInput = {
  bucket: string;
  apply: boolean;
};

export type FixResult =
  | {
      ok: true;
      changed: boolean;
      dryRun: boolean;
      action: typeof ACTION;
      operation: typeof OPERATION;
      bucket: typeof TARGET_BUCKET;
      reason: 'dry_run' | 'already_absent' | 'removed';
    }
  | {
      ok: false;
      changed: false;
      errorCode: string;
      errorMessage: string;
    };

type Planned = RemoveBucketPublicAccessBlockInput;

type Failure = {
  ok: false;
  changed: false;
  errorCode: string;
  errorMessage: string;
};

type ParsedTag = { Key: string; Value: string };

export async function handler(event: unknown): Promise<FixResult> {
  const client = new S3Client({});
  return handleRemoveBucketPublicAccessBlock(event, client);
}

/**
 * Validate the bucket, require the three exact tags, and delete the block
 * only when apply is true and a configuration is present.
 */
export async function handleRemoveBucketPublicAccessBlock(
  event: unknown,
  client: AwsClient,
): Promise<FixResult> {
  const parsed = parseEvent(event);
  if (!parsed.ok) {
    return { ok: false, changed: false, errorCode: 'InvalidInput', errorMessage: parsed.message };
  }

  const input = parsed.value;
  const tagged = await readBucketTags(client);
  if (!tagged.ok) {
    return tagged.failure;
  }
  if (!hasPublicTag(tagged.tags)) {
    return missingRequiredTags();
  }
  if (!hasAutoRemediateTag(tagged.tags)) {
    return missingRequiredTags();
  }
  if (!hasDemoPurpose(tagged.tags)) {
    return missingRequiredTags();
  }

  const block = await readBlock(client);
  if (!block.ok) {
    return block.failure;
  }

  const body = {
    action: ACTION,
    operation: OPERATION,
    bucket: TARGET_BUCKET,
  };

  if (!block.exists) {
    return { ok: true, changed: false, dryRun: !input.apply, ...body, reason: 'already_absent' };
  }

  if (!input.apply) {
    return { ok: true, changed: false, dryRun: true, ...body, reason: 'dry_run' };
  }

  try {
    await client.send(new DeletePublicAccessBlockCommand({ Bucket: TARGET_BUCKET }));
  } catch (err) {
    if (hasErrorCode(err, MISSING_BLOCK)) {
      return { ok: true, changed: false, dryRun: false, ...body, reason: 'already_absent' };
    }
    return { ok: false, changed: false, ...readAwsError(err) };
  }

  return { ok: true, changed: true, dryRun: false, ...body, reason: 'removed' };
}

function parseEvent(event: unknown): { ok: true; value: Planned } | { ok: false; message: string } {
  if (typeof event !== 'object' || event === null || Array.isArray(event)) {
    return { ok: false, message: 'input must be an object' };
  }
  const record = event as Record<string, unknown>;

  if (record.bucket !== TARGET_BUCKET) {
    return { ok: false, message: `bucket must be ${TARGET_BUCKET}` };
  }
  if ('apply' in record && typeof record.apply !== 'boolean') {
    return { ok: false, message: 'apply must be a boolean' };
  }

  return {
    ok: true,
    value: {
      bucket: TARGET_BUCKET,
      apply: record.apply === true,
    },
  };
}

function missingRequiredTags(): Failure {
  return {
    ok: false,
    changed: false,
    errorCode: 'MissingRequiredTags',
    errorMessage:
      'bucket must have tags public=true, auto-remediate=true, and purpose=ag-demo-synthetic',
  };
}

async function readBucketTags(
  client: AwsClient,
): Promise<{ ok: true; tags: ParsedTag[] } | { ok: false; failure: Failure }> {
  let described: unknown;
  try {
    described = await client.send(new GetBucketTaggingCommand({ Bucket: TARGET_BUCKET }));
  } catch (err) {
    if (hasErrorCode(err, MISSING_TAGS)) {
      return { ok: false, failure: missingRequiredTags() };
    }
    return { ok: false, failure: { ok: false, changed: false, ...readAwsError(err) } };
  }

  const tags = readTagRecords(described);
  if (tags === 'bad') {
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
  return { ok: true, tags };
}

function readTagRecords(payload: unknown): ParsedTag[] | 'bad' {
  if (typeof payload !== 'object' || payload === null) {
    return 'bad';
  }
  const tagSet = (payload as { TagSet?: unknown }).TagSet;
  if (!Array.isArray(tagSet)) {
    return 'bad';
  }
  const tags: ParsedTag[] = [];
  for (const item of tagSet) {
    if (typeof item !== 'object' || item === null) {
      return 'bad';
    }
    const tag = item as { Key?: unknown; Value?: unknown };
    if (typeof tag.Key !== 'string' || typeof tag.Value !== 'string') {
      return 'bad';
    }
    tags.push({ Key: tag.Key, Value: tag.Value });
  }
  return tags;
}

async function readBlock(
  client: AwsClient,
): Promise<{ ok: true; exists: boolean } | { ok: false; failure: Failure }> {
  let described: unknown;
  try {
    described = await client.send(new GetBucketPublicAccessBlockCommand({ Bucket: TARGET_BUCKET }));
  } catch (err) {
    if (hasErrorCode(err, MISSING_BLOCK)) {
      return { ok: true, exists: false };
    }
    return { ok: false, failure: { ok: false, changed: false, ...readAwsError(err) } };
  }

  if (!blockConfigurationPresent(described)) {
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
  return { ok: true, exists: true };
}

function blockConfigurationPresent(payload: unknown): boolean {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }
  const config = (payload as { PublicAccessBlockConfiguration?: unknown }).PublicAccessBlockConfiguration;
  return typeof config === 'object' && config !== null;
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
