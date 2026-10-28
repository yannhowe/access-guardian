/**
 * One action: PutPublicAccessBlock.
 *
 * Finding: cloud:s3_public_access_block_removed.
 * Fix key: restore-bucket-public-access-block.
 *
 * The bucket is requestParameters.bucketName on a CloudTrail removal event.
 * All four public access block flags are hardcoded true. This is the bucket
 * API. It does not set an account public access block.
 *
 * Dry-run is the default. options.apply must be exactly true or this function
 * does not call AWS. Set that flag in our own code after Yann's yes.
 * Do not copy it from the event, from Slack, or from a model reply.
 * The read runs only on that apply path, immediately before the write.
 *
 * Undo puts the recorded flags back. If the read found no bucket
 * configuration, undo removes the setting this fix wrote. Undo is also a
 * dry-run unless its own options.apply is exactly true.
 *
 * IAM, on arn:aws:s3:::<bucket> for that one bucket:
 * s3:GetBucketPublicAccessBlock and s3:PutBucketPublicAccessBlock.
 * No wildcard and no account-level permission.
 * Removing the setting on undo is covered by s3:PutBucketPublicAccessBlock.
 * AWS does not define a separate delete permission for this bucket setting.
 *
 * What Grok decides: nothing. This file does not call Grok.
 * What code decides: whether the bucket name is one valid bucket, whether
 * the one put is sent, and whether undo writes the recorded flags or
 * removes the setting.
 */
import { ALLOWED_FIXES } from './allow-list.js';

export const ACTION = 'PutPublicAccessBlock' as const;

type ActionMatches =
  typeof ACTION extends (typeof ALLOWED_FIXES)['restore-bucket-public-access-block']['action'] ? true : never;

/** Compile-time check. The hardcoded action and the allow-list entry stay the same string. */
export const actionMatchesAllowList: ActionMatches = true;

/**
 * CloudTrail names the bucket removal with this API name.
 * Undo calls it only when the bucket had no configuration to put back.
 */
export const UNDO_ACTION = 'DeleteBucketPublicAccessBlock' as const;

export const IAM_ACTIONS = [
  's3:GetBucketPublicAccessBlock',
  's3:PutBucketPublicAccessBlock',
] as const;

/** One bucket ARN. Substitute the bucket from the event. No wildcard. */
export const IAM_RESOURCE = 'arn:aws:s3:::<bucket>' as const;

const EVENT_SOURCE = 's3.amazonaws.com';
const MISSING_BLOCK = 'NoSuchPublicAccessBlockConfiguration';

export type PublicAccessBlockFlags = {
  BlockPublicAcls: boolean;
  IgnorePublicAcls: boolean;
  BlockPublicPolicy: boolean;
  RestrictPublicBuckets: boolean;
};

export type RecordedBucketPublicAccessBlock =
  | { bucket: string; present: false }
  | { bucket: string; present: true; configuration: PublicAccessBlockFlags };

export type GetPublicAccessBlockCommand = {
  action: 'GetPublicAccessBlock';
  input: { Bucket: string };
};

export type PutPublicAccessBlockCommand = {
  action: typeof ACTION;
  input: {
    Bucket: string;
    PublicAccessBlockConfiguration: PublicAccessBlockFlags;
  };
};

export type DeleteBlockCommand = {
  action: typeof UNDO_ACTION;
  input: { Bucket: string };
};

export type BucketCommand = GetPublicAccessBlockCommand | PutPublicAccessBlockCommand | DeleteBlockCommand;

export type BucketPublicAccessBlockClient = {
  send(command: BucketCommand): Promise<unknown>;
};

export type RestoreBucketPublicAccessBlockResult =
  | {
      ok: true;
      applied: false;
      action: typeof ACTION;
      bucket: string;
      command: PutPublicAccessBlockCommand;
    }
  | {
      ok: true;
      applied: true;
      action: typeof ACTION;
      bucket: string;
      command: PutPublicAccessBlockCommand;
      recorded: RecordedBucketPublicAccessBlock;
    }
  | { ok: false; reason: 'invalid_input' | 'aws_error' };

export type UndoRestoreBucketPublicAccessBlockResult =
  | {
      ok: true;
      applied: false;
      bucket: string;
      command: PutPublicAccessBlockCommand | DeleteBlockCommand;
    }
  | {
      ok: true;
      applied: true;
      bucket: string;
      command: PutPublicAccessBlockCommand | DeleteBlockCommand;
    }
  | { ok: false; reason: 'invalid_input' | 'aws_error' };

const BUCKET_NAME = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const IPV4_SHAPE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const RESERVED_PREFIXES = ['xn--', 'sthree-', 'amzn-s3-demo-'] as const;
const RESERVED_SUFFIXES = ['-s3alias', '--ol-s3', '.mrap', '--x-s3', '--table-s3'] as const;

/**
 * Plan the one put, and send it only when options.apply is true.
 * input is untrusted. A bad shape returns invalid_input and does not call AWS.
 */
export async function restoreBucketPublicAccessBlock(
  input: unknown,
  client: BucketPublicAccessBlockClient,
  options?: { apply?: boolean },
): Promise<RestoreBucketPublicAccessBlockResult> {
  const bucket = parseRemovalEvent(input);
  if (bucket === undefined) {
    return { ok: false, reason: 'invalid_input' };
  }

  const command = buildBlockAll(bucket);
  if (options?.apply !== true) {
    return { ok: true, applied: false, action: ACTION, bucket, command };
  }

  let recorded: RecordedBucketPublicAccessBlock;
  try {
    recorded = await readCurrent(client, bucket);
  } catch (error) {
    if (!isMissingPublicAccessBlock(error)) {
      return { ok: false, reason: 'aws_error' };
    }
    recorded = { bucket, present: false };
  }

  try {
    await sendBucketCommand(client, command);
  } catch {
    return { ok: false, reason: 'aws_error' };
  }

  return { ok: true, applied: true, action: ACTION, bucket, command, recorded };
}

/**
 * Put the recorded flags back, or remove the setting if none was recorded.
 * Dry-run unless options.apply is true. The snapshot is not allowed to set that flag.
 */
export async function undoRestoreBucketPublicAccessBlock(
  recorded: unknown,
  client: BucketPublicAccessBlockClient,
  options?: { apply?: boolean },
): Promise<UndoRestoreBucketPublicAccessBlockResult> {
  const parsed = parseRecorded(recorded);
  if (parsed === undefined) {
    return { ok: false, reason: 'invalid_input' };
  }

  const command = parsed.present ? buildRecordedPut(parsed.bucket, parsed.configuration) : buildDelete(parsed.bucket);
  if (options?.apply !== true) {
    return { ok: true, applied: false, bucket: parsed.bucket, command };
  }

  try {
    await sendBucketCommand(client, command);
  } catch (error) {
    if (!parsed.present && isMissingPublicAccessBlock(error)) {
      return { ok: true, applied: true, bucket: parsed.bucket, command };
    }
    return { ok: false, reason: 'aws_error' };
  }

  return { ok: true, applied: true, bucket: parsed.bucket, command };
}

function buildBlockAll(bucket: string): PutPublicAccessBlockCommand {
  return {
    action: ACTION,
    input: {
      Bucket: bucket,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
    },
  };
}

function buildRecordedPut(bucket: string, configuration: PublicAccessBlockFlags): PutPublicAccessBlockCommand {
  return {
    action: ACTION,
    input: {
      Bucket: bucket,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: configuration.BlockPublicAcls,
        IgnorePublicAcls: configuration.IgnorePublicAcls,
        BlockPublicPolicy: configuration.BlockPublicPolicy,
        RestrictPublicBuckets: configuration.RestrictPublicBuckets,
      },
    },
  };
}

function buildDelete(bucket: string): DeleteBlockCommand {
  return {
    action: UNDO_ACTION,
    input: { Bucket: bucket },
  };
}

/** The read, the one put, and the undo all go through this single send. */
function sendBucketCommand(client: BucketPublicAccessBlockClient, command: BucketCommand): Promise<unknown> {
  return client.send(command);
}

async function readCurrent(
  client: BucketPublicAccessBlockClient,
  bucket: string,
): Promise<RecordedBucketPublicAccessBlock> {
  const response = await sendBucketCommand(client, {
    action: 'GetPublicAccessBlock',
    input: { Bucket: bucket },
  });
  const configuration = configurationFrom(response);
  if (configuration === undefined) {
    throw new Error('invalid_configuration');
  }
  return { bucket, present: true, configuration };
}

function parseRemovalEvent(input: unknown): string | undefined {
  if (!isRecord(input)) {
    return undefined;
  }
  if (input.eventSource !== EVENT_SOURCE) {
    return undefined;
  }
  if (input.eventName !== UNDO_ACTION) {
    return undefined;
  }
  if ('errorCode' in input && input.errorCode !== null && input.errorCode !== undefined) {
    return undefined;
  }
  if (!isRecord(input.requestParameters)) {
    return undefined;
  }
  const params = input.requestParameters;
  if ('accountId' in params || 'AccountId' in params) {
    return undefined;
  }
  const bucketName = params.bucketName;
  if (typeof bucketName !== 'string' || !isBucketName(bucketName)) {
    return undefined;
  }
  return bucketName;
}

function parseRecorded(value: unknown): RecordedBucketPublicAccessBlock | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const bucket = value.bucket;
  if (typeof bucket !== 'string' || !isBucketName(bucket)) {
    return undefined;
  }
  if (value.present === false) {
    if ('configuration' in value) {
      return undefined;
    }
    return { bucket, present: false };
  }
  if (value.present !== true) {
    return undefined;
  }
  const configuration = parseFlags(value.configuration);
  if (configuration === undefined) {
    return undefined;
  }
  return { bucket, present: true, configuration };
}

function configurationFrom(response: unknown): PublicAccessBlockFlags | undefined {
  if (!isRecord(response)) {
    return undefined;
  }
  return parseFlags(response.PublicAccessBlockConfiguration);
}

function parseFlags(value: unknown): PublicAccessBlockFlags | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const BlockPublicAcls = value.BlockPublicAcls;
  const IgnorePublicAcls = value.IgnorePublicAcls;
  const BlockPublicPolicy = value.BlockPublicPolicy;
  const RestrictPublicBuckets = value.RestrictPublicBuckets;
  if (
    typeof BlockPublicAcls !== 'boolean' ||
    typeof IgnorePublicAcls !== 'boolean' ||
    typeof BlockPublicPolicy !== 'boolean' ||
    typeof RestrictPublicBuckets !== 'boolean'
  ) {
    return undefined;
  }
  return { BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets };
}

function isMissingPublicAccessBlock(error: unknown): boolean {
  if (!isRecord(error)) {
    return false;
  }
  return error.name === MISSING_BLOCK || error.code === MISSING_BLOCK || error.Code === MISSING_BLOCK;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** General purpose bucket name. A bad name is refused. */
function isBucketName(value: string): boolean {
  if (!BUCKET_NAME.test(value) || value.includes('..') || IPV4_SHAPE.test(value)) {
    return false;
  }
  if (RESERVED_PREFIXES.some((prefix) => value.startsWith(prefix))) {
    return false;
  }
  return !RESERVED_SUFFIXES.some((suffix) => value.endsWith(suffix));
}
