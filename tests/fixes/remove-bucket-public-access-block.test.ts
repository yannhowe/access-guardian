/**
 * Tests for the remove-bucket-public-access-block Lambda. The S3 client is a fake.
 * These tests do not call AWS.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DeletePublicAccessBlockCommand,
  GetBucketTaggingCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import { ALLOWED_FIXES } from '../../src/fixes/allow-list.js';
import { FIX_REGISTRY, registryKeysMatchAllowList } from '../../src/fixes/registry.js';
import {
  ACTION,
  OPERATION,
  TARGET_BUCKET,
  handleRemoveBucketPublicAccessBlock,
  handler,
  type AwsClient,
} from '../../src/fixes/remove-bucket-public-access-block/handler.js';

const EVENT = { bucket: TARGET_BUCKET };
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const HANDLER_PATH = path.join(ROOT, 'src/fixes/remove-bucket-public-access-block/handler.ts');
const REQUIRED_MESSAGE =
  'bucket must have tags intended-public=true, auto-remediate=true, and purpose=ag-demo-synthetic';

const REQUIRED_TAGS = {
  TagSet: [
    { Key: 'intended-public', Value: 'true' },
    { Key: 'auto-remediate', Value: 'true' },
    { Key: 'purpose', Value: 'ag-demo-synthetic' },
  ],
};

const BLOCKED = {
  PublicAccessBlockConfiguration: {
    BlockPublicAcls: true,
    IgnorePublicAcls: true,
    BlockPublicPolicy: true,
    RestrictPublicBuckets: true,
  },
};

type FakeOptions = {
  tags?: unknown;
  block?: unknown;
  taggingError?: unknown;
  blockError?: unknown;
  deleteError?: unknown;
};

function fakeClient(options: FakeOptions = {}): { client: AwsClient; send: ReturnType<typeof vi.fn> } {
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof GetBucketTaggingCommand) {
      if (options.taggingError !== undefined) {
        throw options.taggingError;
      }
      return options.tags ?? REQUIRED_TAGS;
    }
    if (command instanceof GetPublicAccessBlockCommand) {
      if (options.blockError !== undefined) {
        throw options.blockError;
      }
      return options.block ?? BLOCKED;
    }
    if (command instanceof DeletePublicAccessBlockCommand) {
      if (options.deleteError !== undefined) {
        throw options.deleteError;
      }
      return {};
    }
    throw new Error(`unexpected command ${command instanceof Object ? command.constructor.name : typeof command}`);
  });
  return { client: { send }, send };
}

function deletes(send: ReturnType<typeof vi.fn>): unknown[] {
  return send.mock.calls
    .map((call) => call[0])
    .filter((command) => command instanceof DeletePublicAccessBlockCommand);
}

function awsError(name: string, message: string): Error {
  return Object.assign(new Error(message), { name });
}

function tagsWithout(key: string): Array<{ Key: string; Value: string }> {
  return REQUIRED_TAGS.TagSet.filter((tag) => tag.Key !== key);
}

function tagsReplacing(key: string, value: string, keyOverride = key): Array<{ Key: string; Value: string }> {
  return REQUIRED_TAGS.TagSet.map((tag) => (tag.Key === key ? { Key: keyOverride, Value: value } : tag));
}

beforeEach(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('this test must not call fetch');
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('remove-bucket-public-access-block handler', () => {
  it('names the one allow-listed action and the same registry key', () => {
    expect(ACTION).toBe('s3:PutBucketPublicAccessBlock');
    expect(OPERATION).toBe('DeletePublicAccessBlock');
    expect(TARGET_BUCKET).toBe('ag-demo-public-10281729');
    expect(ALLOWED_FIXES['remove-bucket-public-access-block']).toEqual({
      findingKey: 'cloud:s3_public_access_block_drift_intended_public',
      action: ACTION,
      summary: 'Remove Block Public Access on the one bucket tagged intended-public=true',
      undo: 'There is no undo',
    });
    expect(FIX_REGISTRY['remove-bucket-public-access-block']).toEqual({
      findingKey: 'cloud:s3_public_access_block_drift_intended_public',
      functionName: 'ag-fix-remove-bucket-public-access-block',
    });
    expect(Object.keys(FIX_REGISTRY).sort()).toEqual(Object.keys(ALLOWED_FIXES).sort());
    expect(registryKeysMatchAllowList).toBe(true);
    expect(typeof handler).toBe('function');
  });

  it('allows the two reads and the one delete action on the one bucket ARN', () => {
    const policy = JSON.parse(
      readFileSync(path.join(ROOT, 'src/fixes/remove-bucket-public-access-block/policy.json'), 'utf8'),
    ) as {
      Statement: Array<{
        Effect: string;
        Action: string[];
        Resource: string;
        Condition?: { StringEquals: Record<string, string> };
      }>;
    };
    const actions = policy.Statement.flatMap((statement) => statement.Action);
    expect(actions).toEqual([
      's3:GetBucketTagging',
      's3:GetBucketPublicAccessBlock',
      's3:PutBucketPublicAccessBlock',
    ]);
    expect(JSON.stringify(policy)).not.toContain('*');
    for (const statement of policy.Statement) {
      expect(statement.Effect).toBe('Allow');
      expect(statement.Resource).toBe('arn:aws:s3:::ag-demo-public-10281729');
    }
    const reads = policy.Statement[0];
    const mutating = policy.Statement[1];
    expect(reads?.Condition).toBeUndefined();
    expect(mutating?.Condition).toEqual({
      StringEquals: { 'aws:ResourceTag/intended-public': 'true' },
    });
    const fix = JSON.parse(
      readFileSync(path.join(ROOT, 'src/fixes/remove-bucket-public-access-block/fix.json'), 'utf8'),
    );
    expect(fix).toMatchObject({
      name: 'remove-bucket-public-access-block',
      findingKey: 'cloud:s3_public_access_block_drift_intended_public',
      action: ACTION,
      callsGrok: false,
    });
  });

  it('returns a dry run and does not delete when apply is omitted', async () => {
    const { client, send } = fakeClient();

    const result = await handleRemoveBucketPublicAccessBlock(EVENT, client);

    expect(result).toEqual({
      ok: true,
      changed: false,
      dryRun: true,
      action: ACTION,
      operation: OPERATION,
      bucket: TARGET_BUCKET,
      reason: 'dry_run',
    });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0]?.[0]).toBeInstanceOf(GetBucketTaggingCommand);
    expect(send.mock.calls[1]?.[0]).toBeInstanceOf(GetPublicAccessBlockCommand);
    expect((send.mock.calls[0]?.[0] as GetBucketTaggingCommand).input).toEqual({ Bucket: TARGET_BUCKET });
    expect(deletes(send)).toEqual([]);
  });

  it('does not delete when apply is false', async () => {
    const { client, send } = fakeClient();

    const result = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: false }, client);

    expect(result).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'dry_run' });
    expect(deletes(send)).toEqual([]);
  });

  it('deletes once when apply is true and the three tags match', async () => {
    const { client, send } = fakeClient();

    const result = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: true,
      changed: true,
      dryRun: false,
      action: ACTION,
      operation: OPERATION,
      bucket: TARGET_BUCKET,
      reason: 'removed',
    });
    expect(send).toHaveBeenCalledTimes(3);
    const removed = deletes(send);
    expect(removed).toHaveLength(1);
    expect(removed[0]).toBeInstanceOf(DeletePublicAccessBlockCommand);
    expect((removed[0] as DeletePublicAccessBlockCommand).input).toEqual({ Bucket: TARGET_BUCKET });
    expect((removed[0] as { constructor: { name: string } }).constructor.name).toBe(
      'DeletePublicAccessBlockCommand',
    );
  });

  it('deletes when the configuration exists with any flag values', async () => {
    const { client, send } = fakeClient({
      block: {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          IgnorePublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
        },
      },
    });

    const result = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, reason: 'removed' });
    expect(deletes(send)).toHaveLength(1);
  });

  it('reports changed false when no block configuration exists', async () => {
    const { client, send } = fakeClient({
      blockError: awsError('NoSuchPublicAccessBlockConfiguration', 'The public access block configuration was not found'),
    });

    const dry = await handleRemoveBucketPublicAccessBlock(EVENT, client);
    const applied = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(dry).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'already_absent' });
    expect(applied).toMatchObject({ ok: true, changed: false, dryRun: false, reason: 'already_absent' });
    expect(deletes(send)).toEqual([]);
  });

  it('treats a missing block Code as already absent and does not match that code in the message text', async () => {
    const byCode = fakeClient({
      blockError: { Code: 'NoSuchPublicAccessBlockConfiguration', message: 'missing' },
    });
    const byText = fakeClient({
      blockError: awsError('AccessDenied', 'NoSuchPublicAccessBlockConfiguration'),
    });

    const absent = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, byCode.client);
    const denied = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, byText.client);

    expect(absent).toMatchObject({ ok: true, changed: false, reason: 'already_absent' });
    expect(deletes(byCode.send)).toEqual([]);
    expect(denied).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDenied',
      errorMessage: 'NoSuchPublicAccessBlockConfiguration',
    });
    expect(deletes(byText.send)).toEqual([]);
  });

  it('is safe to run twice', async () => {
    let exists = true;
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof GetBucketTaggingCommand) {
        return REQUIRED_TAGS;
      }
      if (command instanceof GetPublicAccessBlockCommand) {
        if (!exists) {
          throw awsError('NoSuchPublicAccessBlockConfiguration', 'missing');
        }
        return BLOCKED;
      }
      if (command instanceof DeletePublicAccessBlockCommand) {
        exists = false;
        return {};
      }
      throw new Error('unexpected command');
    });

    const first = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, { send });
    const second = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, { send });

    expect(first).toMatchObject({ ok: true, changed: true, reason: 'removed' });
    expect(second).toMatchObject({ ok: true, changed: false, reason: 'already_absent' });
    expect(deletes(send)).toHaveLength(1);
  });

  it('is safe to run twice when the block is already gone', async () => {
    const { client, send } = fakeClient({
      blockError: awsError('NoSuchPublicAccessBlockConfiguration', 'missing'),
    });

    const first = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);
    const second = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(first).toMatchObject({ ok: true, changed: false, reason: 'already_absent' });
    expect(second).toMatchObject({ ok: true, changed: false, reason: 'already_absent' });
    expect(deletes(send)).toEqual([]);
  });

  it.each([
    ['ag-demo-assets-a-10281729'],
    ['ag-demo-assets-b-10281729'],
    ['ag-demo-private-10281729'],
    ['ag-demo-public-10281729-extra'],
    ['AG-demo-public-10281729'],
  ])('refuses %s and does not call AWS', async (bucket) => {
    const { client, send } = fakeClient();

    const result = await handleRemoveBucketPublicAccessBlock({ bucket, apply: true }, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidInput' });
    expect(send).not.toHaveBeenCalled();
  });

  it.each([
    ['a string apply flag', { ...EVENT, apply: 'true' }],
    ['null', null],
    ['an array', []],
    ['a numeric bucket', { bucket: 1 }],
  ])('refuses %s and does not call AWS', async (_label, event) => {
    const { client, send } = fakeClient();

    const result = await handleRemoveBucketPublicAccessBlock(event, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidInput' });
    expect(send).not.toHaveBeenCalled();
  });

  it('refuses a dry run and an apply when a required tag is missing, mistyped, or wrong', async () => {
    const cases: Array<{ label: string; tags: Array<{ Key: string; Value: string }> }> = [
      { label: 'empty tag set', tags: [] },
      { label: 'missing intended-public', tags: tagsWithout('intended-public') },
      { label: 'missing auto-remediate', tags: tagsWithout('auto-remediate') },
      { label: 'missing purpose', tags: tagsWithout('purpose') },
      { label: 'intended-public false', tags: tagsReplacing('intended-public', 'false') },
      { label: 'intended-public True', tags: tagsReplacing('intended-public', 'True') },
      { label: 'intended-public TRUE', tags: tagsReplacing('intended-public', 'TRUE') },
      { label: 'Intended-Public key', tags: tagsReplacing('intended-public', 'true', 'Intended-Public') },
      { label: 'auto-remediate false', tags: tagsReplacing('auto-remediate', 'false') },
      { label: 'auto-remediate True', tags: tagsReplacing('auto-remediate', 'True') },
      { label: 'AUTO-REMEDIATE key', tags: tagsReplacing('auto-remediate', 'true', 'AUTO-REMEDIATE') },
      { label: 'purpose other', tags: tagsReplacing('purpose', 'other-value') },
      { label: 'Purpose key', tags: tagsReplacing('purpose', 'ag-demo-synthetic', 'Purpose') },
      { label: 'purpose upper value', tags: tagsReplacing('purpose', 'AG-demo-synthetic') },
    ];

    for (const entry of cases) {
      for (const apply of [undefined, false, true] as const) {
        const { client, send } = fakeClient({ tags: { TagSet: entry.tags } });
        const event = apply === undefined ? EVENT : { ...EVENT, apply };
        const result = await handleRemoveBucketPublicAccessBlock(event, client);
        expect(result, `${entry.label} apply=${String(apply)}`).toEqual({
          ok: false,
          changed: false,
          errorCode: 'MissingRequiredTags',
          errorMessage: REQUIRED_MESSAGE,
        });
        expect(deletes(send), entry.label).toEqual([]);
        expect(send, entry.label).toHaveBeenCalledTimes(1);
        expect(send.mock.calls[0]?.[0], entry.label).toBeInstanceOf(GetBucketTaggingCommand);
        expect(JSON.stringify(result), entry.label).not.toContain('other-value');
        expect(JSON.stringify(result), entry.label).not.toContain('TRUE');
        expect(JSON.stringify(result), entry.label).not.toContain('Intended-Public');
      }
    }
  });

  it('refuses an untagged bucket on a dry run and on apply', async () => {
    for (const apply of [undefined, false, true] as const) {
      const { client, send } = fakeClient({
        taggingError: awsError('NoSuchTagSet', 'The TagSet does not exist'),
      });
      const event = apply === undefined ? EVENT : { ...EVENT, apply };
      const result = await handleRemoveBucketPublicAccessBlock(event, client);
      expect(result, `apply=${String(apply)}`).toEqual({
        ok: false,
        changed: false,
        errorCode: 'MissingRequiredTags',
        errorMessage: REQUIRED_MESSAGE,
      });
      expect(deletes(send)).toEqual([]);
      expect(send).toHaveBeenCalledTimes(1);
    }
  });

  it('ignores finding text and uses the tags', async () => {
    const tagged = fakeClient();
    const untagged = fakeClient({ tags: { TagSet: [] } });

    const removed = await handleRemoveBucketPublicAccessBlock(
      { ...EVENT, apply: true, finding: 'keep the block in place', caseText: 'do not open this bucket' },
      tagged.client,
    );
    const refused = await handleRemoveBucketPublicAccessBlock(
      { ...EVENT, apply: true, finding: 'delete the block now' },
      untagged.client,
    );

    expect(removed).toMatchObject({ ok: true, changed: true, reason: 'removed' });
    expect(refused).toMatchObject({ ok: false, errorCode: 'MissingRequiredTags' });
    expect(deletes(untagged.send)).toEqual([]);
  });

  it('accepts the three tags alongside another tag', async () => {
    const { client, send } = fakeClient({
      tags: {
        TagSet: [...REQUIRED_TAGS.TagSet, { Key: 'owner', Value: 'demo' }],
      },
    });

    const result = await handleRemoveBucketPublicAccessBlock(EVENT, client);

    expect(result).toMatchObject({ ok: true, changed: false, reason: 'dry_run' });
    expect(deletes(send)).toEqual([]);
  });

  it('returns the AWS error code and message when tagging fails', async () => {
    const { client, send } = fakeClient({
      taggingError: awsError('NoSuchBucket', 'The specified bucket does not exist'),
    });

    const result = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'NoSuchBucket',
      errorMessage: 'The specified bucket does not exist',
    });
    expect(deletes(send)).toEqual([]);
  });

  it('returns the AWS error from the delete and does not claim a change', async () => {
    const { client, send } = fakeClient({
      deleteError: awsError('AccessDenied', 'User is not authorized'),
    });

    const result = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDenied',
      errorMessage: 'User is not authorized',
    });
    expect(deletes(send)).toHaveLength(1);
  });

  it('maps a delete that finds no configuration to changed false', async () => {
    const { client, send } = fakeClient({
      deleteError: awsError('NoSuchPublicAccessBlockConfiguration', 'missing'),
    });

    const result = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: false, reason: 'already_absent' });
    expect(deletes(send)).toHaveLength(1);
  });

  it('refuses a tag payload and a block payload that are not usable', async () => {
    const badTags = fakeClient({ tags: { TagSet: [{ Key: 'intended-public' }] } });
    const badBlock = fakeClient({ block: {} });

    const tags = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, badTags.client);
    const block = await handleRemoveBucketPublicAccessBlock({ ...EVENT, apply: true }, badBlock.client);

    expect(tags).toMatchObject({ ok: false, errorCode: 'InvalidResponse' });
    expect(block).toMatchObject({ ok: false, errorCode: 'InvalidResponse' });
    expect(deletes(badTags.send)).toEqual([]);
    expect(deletes(badBlock.send)).toEqual([]);
  });

  it('constructs DeletePublicAccessBlockCommand under its real name', () => {
    const source = readFileSync(HANDLER_PATH, 'utf8');
    const importBlock = source.slice(source.indexOf('import {'), source.indexOf("} from '@aws-sdk/client-s3'"));

    expect(importBlock).toContain('DeletePublicAccessBlockCommand');
    expect(importBlock).not.toMatch(/DeletePublicAccessBlockCommand\s+as\s+/);
    expect(importBlock).toContain('GetPublicAccessBlockCommand as GetBucketPublicAccessBlockCommand');
    expect(importBlock).toContain('GetBucketTaggingCommand');
    expect(importBlock).not.toContain('PutPublicAccessBlockCommand');
    expect(importBlock).not.toContain('s3control');
    expect(source).toContain("const ACTION = 's3:PutBucketPublicAccessBlock'");
    expect(source).toContain("const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate'");
    expect(source).toContain("const AUTO_REMEDIATE_TAG_VALUE = 'true'");
    expect(source).toContain("const INTENDED_PUBLIC_TAG_KEY = 'intended-public'");
    expect(source).toContain("const INTENDED_PUBLIC_TAG_VALUE = 'true'");
    expect(source).toContain("const PURPOSE_TAG_KEY = 'purpose'");
    expect(source).toContain("const PURPOSE_TAG_VALUE = 'ag-demo-synthetic'");
    const intendedAt = source.indexOf('if (!hasIntendedPublicTag(');
    const autoAt = source.indexOf('if (!hasAutoRemediateTag(');
    const purposeAt = source.indexOf('if (!hasDemoPurpose(');
    const deleteAt = source.indexOf('new DeletePublicAccessBlockCommand');
    expect(intendedAt).toBeGreaterThan(-1);
    expect(autoAt).toBeGreaterThan(intendedAt);
    expect(purposeAt).toBeGreaterThan(autoAt);
    expect(deleteAt).toBeGreaterThan(purposeAt);
    expect(source.match(/new DeletePublicAccessBlockCommand\b/g)).toEqual(['new DeletePublicAccessBlockCommand']);
    expect(source).not.toMatch(/new PutBucketPublicAccessBlockCommand\b/);
    expect(source).not.toMatch(/new PutPublicAccessBlockCommand\b/);
    expect(source).not.toMatch(/PutBucketPolicy|PutBucketAcl|PutObject|DeleteObject|GetObject/);
    expect(source).not.toMatch(/PutAccountPublicAccessBlock|DeleteAccountPublicAccessBlock|s3control/);
    expect(source).not.toMatch(/extract\(/);
  });
});
