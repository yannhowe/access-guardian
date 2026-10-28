/**
 * Tests for the restore-bucket-public-access-block Lambda. The S3 client is a fake.
 * These tests do not call AWS.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  GetBucketTaggingCommand,
  GetPublicAccessBlockCommand,
  PutPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import { ALLOWED_FIXES } from '../../src/fixes/allow-list.js';
import {
  ACTION,
  PUBLIC_ACCESS_BLOCK,
  handleRestoreBucketPublicAccessBlock,
  handler,
  type AwsClient,
} from '../../src/fixes/restore-bucket-public-access-block/handler.js';
import { registryKeysMatchAllowList } from '../../src/fixes/registry.js';

const BUCKET = 'ag-demo-bucket';
const EVENT = { bucket: BUCKET };
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const HANDLER_PATH = path.join(ROOT, 'src/fixes/restore-bucket-public-access-block/handler.ts');
const FLAGS = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'] as const;

const TAGGED = {
  TagSet: [
    { Key: 'purpose', Value: 'ag-demo-synthetic' },
    { Key: 'auto-remediate', Value: 'true' },
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

/** Current bucket state with the block off. The put must not copy these values. */
const OPEN = {
  PublicAccessBlockConfiguration: {
    BlockPublicAcls: false,
    IgnorePublicAcls: false,
    BlockPublicPolicy: false,
    RestrictPublicBuckets: false,
  },
};

type FakeOptions = {
  tags?: unknown;
  block?: unknown;
  taggingError?: unknown;
  blockError?: unknown;
  putError?: unknown;
};

function fakeClient(options: FakeOptions = {}): { client: AwsClient; send: ReturnType<typeof vi.fn> } {
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof GetBucketTaggingCommand) {
      if (options.taggingError !== undefined) {
        throw options.taggingError;
      }
      return options.tags ?? TAGGED;
    }
    if (command instanceof GetPublicAccessBlockCommand) {
      if (options.blockError !== undefined) {
        throw options.blockError;
      }
      return options.block ?? OPEN;
    }
    if (command instanceof PutPublicAccessBlockCommand) {
      if (options.putError !== undefined) {
        throw options.putError;
      }
      return {};
    }
    throw new Error(`unexpected command ${command instanceof Object ? command.constructor.name : typeof command}`);
  });
  return { client: { send }, send };
}

function puts(send: ReturnType<typeof vi.fn>): unknown[] {
  return send.mock.calls
    .map((call) => call[0])
    .filter((command) => command instanceof PutPublicAccessBlockCommand);
}

function awsError(name: string, message: string): Error {
  return Object.assign(new Error(message), { name });
}

beforeEach(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('this test must not call fetch');
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('restore-bucket-public-access-block handler', () => {
  it('names the one allow-listed close action', () => {
    expect(ACTION).toBe('s3:PutBucketPublicAccessBlock');
    expect(ALLOWED_FIXES['restore-bucket-public-access-block']).toEqual({
      findingKey: 'cloud:s3_public_access_block_removed',
      action: ACTION,
      summary: 'Turn on all four Block Public Access flags for one bucket',
      undo: 'There is no undo',
    });
    expect(registryKeysMatchAllowList).toBe(true);
    expect(typeof handler).toBe('function');
    for (const flag of FLAGS) {
      expect(PUBLIC_ACCESS_BLOCK[flag]).toBe(true);
    }
  });

  it('allows only the three bucket reads and the one put on the demo prefix', () => {
    const policy = JSON.parse(
      readFileSync(path.join(ROOT, 'src/fixes/restore-bucket-public-access-block/policy.json'), 'utf8'),
    ) as {
      Statement: Array<{ Effect: string; Action: string[]; Resource: string }>;
    };
    const actions = policy.Statement.flatMap((statement) => statement.Action);
    expect(actions).toEqual([
      's3:GetBucketTagging',
      's3:GetBucketPublicAccessBlock',
      's3:PutBucketPublicAccessBlock',
    ]);
    for (const statement of policy.Statement) {
      expect(statement.Effect).toBe('Allow');
      expect(statement.Resource).toBe('arn:aws:s3:::ag-demo-*');
      expect(statement.Resource).not.toBe('*');
    }
    const fix = JSON.parse(
      readFileSync(path.join(ROOT, 'src/fixes/restore-bucket-public-access-block/fix.json'), 'utf8'),
    );
    expect(fix).toMatchObject({
      name: 'restore-bucket-public-access-block',
      findingKey: 'cloud:s3_public_access_block_removed',
      action: ACTION,
      callsGrok: false,
    });
  });

  it('returns a dry run and does not put when apply is omitted', async () => {
    const { client, send } = fakeClient();

    const result = await handleRestoreBucketPublicAccessBlock(EVENT, client);

    expect(result).toEqual({
      ok: true,
      changed: false,
      dryRun: true,
      action: ACTION,
      bucket: BUCKET,
      publicAccessBlock: { ...PUBLIC_ACCESS_BLOCK },
      reason: 'dry_run',
    });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0]?.[0]).toBeInstanceOf(GetBucketTaggingCommand);
    expect(send.mock.calls[1]?.[0]).toBeInstanceOf(GetPublicAccessBlockCommand);
    expect(puts(send)).toEqual([]);
  });

  it('does not put when apply is false', async () => {
    const { client, send } = fakeClient();

    const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: false }, client);

    expect(result).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'dry_run' });
    expect(puts(send)).toEqual([]);
  });

  it('puts once when apply is true and a flag is not true', async () => {
    const { client, send } = fakeClient({
      block: {
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          IgnorePublicAcls: true,
          BlockPublicPolicy: true,
          RestrictPublicBuckets: true,
        },
      },
    });

    const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: true,
      changed: true,
      dryRun: false,
      action: ACTION,
      bucket: BUCKET,
      publicAccessBlock: { ...PUBLIC_ACCESS_BLOCK },
      reason: 'restored',
    });
    expect(send).toHaveBeenCalledTimes(3);
    const put = puts(send);
    expect(put).toHaveLength(1);
    expect(put[0]).toBeInstanceOf(PutPublicAccessBlockCommand);
    expect((put[0] as PutPublicAccessBlockCommand).input).toEqual({
      Bucket: BUCKET,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
    });
  });

  it('reports changed false when all four flags are already true', async () => {
    const { client, send } = fakeClient({ block: BLOCKED });

    const dry = await handleRestoreBucketPublicAccessBlock(EVENT, client);
    const applied = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(dry).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'already_blocked' });
    expect(applied).toMatchObject({ ok: true, changed: false, dryRun: false, reason: 'already_blocked' });
    expect(puts(send)).toEqual([]);
    expect(send.mock.calls.every((call) => !(call[0] instanceof PutPublicAccessBlockCommand))).toBe(true);
  });

  it('puts once when the block configuration is missing', async () => {
    const { client, send } = fakeClient({
      blockError: awsError('NoSuchPublicAccessBlockConfiguration', 'The public access block configuration was not found'),
    });

    const dry = await handleRestoreBucketPublicAccessBlock(EVENT, client);
    const applied = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(dry).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'dry_run' });
    expect(applied).toMatchObject({ ok: true, changed: true, dryRun: false, reason: 'restored' });
    expect(puts(send)).toHaveLength(1);
    const configuration = (puts(send)[0] as PutPublicAccessBlockCommand).input.PublicAccessBlockConfiguration;
    expect(configuration).toEqual({ ...PUBLIC_ACCESS_BLOCK });
  });

  it('treats a missing block Code as open and does not match that code in the message text', async () => {
    const byCode = fakeClient({
      blockError: { Code: 'NoSuchPublicAccessBlockConfiguration', message: 'missing' },
    });
    const byText = fakeClient({
      blockError: awsError('AccessDenied', 'NoSuchPublicAccessBlockConfiguration'),
    });

    const restored = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, byCode.client);
    const denied = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, byText.client);

    expect(restored).toMatchObject({ ok: true, changed: true, reason: 'restored' });
    expect(puts(byCode.send)).toHaveLength(1);
    expect(denied).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDenied',
      errorMessage: 'NoSuchPublicAccessBlockConfiguration',
    });
    expect(puts(byText.send)).toEqual([]);
  });

  it('refuses an untagged bucket and a wrong purpose value', async () => {
    const cases: Array<{ label: string; options: FakeOptions }> = [
      { label: 'empty tag set', options: { tags: { TagSet: [] } } },
      { label: 'missing purpose', options: { tags: { TagSet: [{ Key: 'env', Value: 'ag-demo-synthetic' }] } } },
      { label: 'wrong value', options: { tags: { TagSet: [{ Key: 'purpose', Value: 'other-value' }] } } },
      { label: 'wrong case', options: { tags: { TagSet: [{ Key: 'Purpose', Value: 'ag-demo-synthetic' }] } } },
      {
        label: 'missing tag set error',
        options: { taggingError: awsError('NoSuchTagSet', 'The TagSet does not exist') },
      },
      {
        label: 'missing tag set code',
        options: { taggingError: { Code: 'NoSuchTagSet', Message: 'The TagSet does not exist' } },
      },
    ];

    for (const entry of cases) {
      const { client, send } = fakeClient(entry.options);
      const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);
      expect(result, entry.label).toEqual({
        ok: false,
        changed: false,
        errorCode: 'BucketNotTagged',
        errorMessage: 'bucket must be tagged purpose=ag-demo-synthetic',
      });
      expect(JSON.stringify(result), entry.label).not.toContain('other-value');
      expect(send, entry.label).toHaveBeenCalledTimes(1);
      expect(send.mock.calls[0]?.[0], entry.label).toBeInstanceOf(GetBucketTaggingCommand);
      expect(puts(send), entry.label).toEqual([]);
    }
  });

  it('refuses a dry run and an apply when auto-remediate is not exactly true', async () => {
    const cases = [
      { label: 'missing', tags: [{ Key: 'purpose', Value: 'ag-demo-synthetic' }] },
      {
        label: 'false',
        tags: [
          { Key: 'purpose', Value: 'ag-demo-synthetic' },
          { Key: 'auto-remediate', Value: 'false' },
        ],
      },
      {
        label: 'True',
        tags: [
          { Key: 'purpose', Value: 'ag-demo-synthetic' },
          { Key: 'auto-remediate', Value: 'True' },
        ],
      },
    ];
    for (const entry of cases) {
      for (const apply of [false, true]) {
        const { client, send } = fakeClient({ tags: { TagSet: entry.tags } });
        const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply }, client);
        expect(result, `${entry.label} apply=${apply}`).toEqual({
          ok: false,
          changed: false,
          errorCode: 'MissingAutoRemediateTag',
          errorMessage: 'bucket must have tag auto-remediate set to true',
        });
        expect(puts(send), entry.label).toEqual([]);
      }
    }
  });

  it('accepts the demo tag alongside another tag', async () => {
    const { client, send } = fakeClient({
      tags: {
        TagSet: [
          { Key: 'owner', Value: 'demo' },
          { Key: 'purpose', Value: 'ag-demo-synthetic' },
          { Key: 'auto-remediate', Value: 'true' },
        ],
      },
    });

    const result = await handleRestoreBucketPublicAccessBlock(EVENT, client);

    expect(result).toMatchObject({ ok: true, changed: false, reason: 'dry_run' });
    expect(puts(send)).toEqual([]);
  });

  it('is safe to run twice', async () => {
    let fullyBlocked = false;
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof GetBucketTaggingCommand) {
        return TAGGED;
      }
      if (command instanceof GetPublicAccessBlockCommand) {
        return fullyBlocked ? BLOCKED : OPEN;
      }
      if (command instanceof PutPublicAccessBlockCommand) {
        fullyBlocked = true;
        return {};
      }
      throw new Error('unexpected command');
    });

    const first = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, { send });
    const second = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, { send });

    expect(first).toMatchObject({ ok: true, changed: true, reason: 'restored' });
    expect(second).toMatchObject({ ok: true, changed: false, reason: 'already_blocked' });
    expect(puts(send)).toHaveLength(1);
  });

  it.each([
    ['a short name', { bucket: 'ag-demo-' }],
    ['no prefix', { bucket: 'demo-bucket' }],
    ['uppercase', { bucket: 'AG-demo-bucket' }],
    ['a slash', { bucket: 'ag-demo-bucket/object' }],
    ['adjacent dots', { bucket: 'ag-demo-a..b' }],
    ['an alias suffix', { bucket: 'ag-demo-bucket-s3alias' }],
    ['an object lambda suffix', { bucket: 'ag-demo-bucket--ol-s3' }],
    ['a name past 63 characters', { bucket: `ag-demo-${'a'.repeat(56)}` }],
    ['a string apply flag', { ...EVENT, apply: 'true' }],
    ['null', null],
    ['an array', []],
  ])('refuses %s and does not call AWS', async (_label, event) => {
    const { client, send } = fakeClient();

    const result = await handleRestoreBucketPublicAccessBlock(event, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidInput' });
    expect(send).not.toHaveBeenCalled();
  });

  it('accepts a 63 character demo bucket and a dotted name', async () => {
    const names = [`ag-demo-${'a'.repeat(55)}`, 'ag-demo-a.b'];
    for (const bucket of names) {
      const { client, send } = fakeClient();
      const result = await handleRestoreBucketPublicAccessBlock({ bucket }, client);
      expect(result).toMatchObject({ ok: true, bucket, reason: 'dry_run' });
      expect(send.mock.calls[0]?.[0]).toBeInstanceOf(GetBucketTaggingCommand);
      expect((send.mock.calls[0]?.[0] as GetBucketTaggingCommand).input).toEqual({ Bucket: bucket });
    }
  });

  it('returns the AWS error code and message when tagging fails', async () => {
    const { client, send } = fakeClient({
      taggingError: awsError('NoSuchBucket', 'The specified bucket does not exist'),
    });

    const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'NoSuchBucket',
      errorMessage: 'The specified bucket does not exist',
    });
    expect(puts(send)).toEqual([]);
    expect(JSON.stringify(result)).not.toContain('aws_error');
  });

  it('returns the AWS error from the block read and does not put', async () => {
    const { client, send } = fakeClient({
      blockError: awsError('AccessDenied', 'User is not authorized'),
    });

    const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDenied',
      errorMessage: 'User is not authorized',
    });
    expect(puts(send)).toEqual([]);
  });

  it('returns the AWS error from the put and does not claim a change', async () => {
    const { client, send } = fakeClient({
      putError: awsError('AccessDenied', 'User is not authorized'),
    });

    const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDenied',
      errorMessage: 'User is not authorized',
    });
    expect(puts(send)).toHaveLength(1);
  });

  it('refuses a tag payload and a block payload that are not usable', async () => {
    const badTags = fakeClient({ tags: { TagSet: [{ Key: 'purpose' }] } });
    const badBlock = fakeClient({ block: {} });

    const tags = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, badTags.client);
    const block = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, badBlock.client);

    expect(tags).toMatchObject({ ok: false, errorCode: 'InvalidResponse' });
    expect(block).toMatchObject({ ok: false, errorCode: 'InvalidResponse' });
    expect(puts(badTags.send)).toEqual([]);
    expect(puts(badBlock.send)).toEqual([]);
  });

  it('refuses two purpose tags', async () => {
    const { client, send } = fakeClient({
      tags: {
        TagSet: [
          { Key: 'purpose', Value: 'ag-demo-synthetic' },
          { Key: 'purpose', Value: 'ag-demo-synthetic' },
        ],
      },
    });

    const result = await handleRestoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: false, changed: false, errorCode: 'InvalidResponse' });
    expect(puts(send)).toEqual([]);
  });

  it('guard: the handler only ever sends true for all four flags', async () => {
    const source = readFileSync(HANDLER_PATH, 'utf8');
    const importBlock = source.slice(source.indexOf('import {'), source.indexOf("} from '@aws-sdk/client-s3'"));

    expect(importBlock).toContain('PutPublicAccessBlockCommand as PutBucketPublicAccessBlockCommand');
    expect(importBlock).toContain('GetPublicAccessBlockCommand as GetBucketPublicAccessBlockCommand');
    expect(importBlock).toContain('GetBucketTaggingCommand');
    expect(importBlock).not.toContain('Delete');
    expect(importBlock).not.toContain('s3control');
    expect(source.match(/new PutBucketPublicAccessBlockCommand\b/g)).toEqual([
      'new PutBucketPublicAccessBlockCommand',
    ]);
    expect(source.match(/new GetBucketPublicAccessBlockCommand\b/g)).toEqual([
      'new GetBucketPublicAccessBlockCommand',
    ]);
    expect(source.match(/new GetBucketTaggingCommand\b/g)).toEqual(['new GetBucketTaggingCommand']);
    expect(source).not.toMatch(/new PutPublicAccessBlockCommand\b/);
    expect(source).not.toMatch(/new GetPublicAccessBlockCommand\b/);
    expect(source).not.toMatch(/DeletePublicAccessBlock/);
    expect(source).not.toMatch(/s3control/);
    expect(source).not.toMatch(/PutBucketPolicy/);
    expect(source).not.toMatch(/PutBucketAcl/);
    expect(source).not.toMatch(/PutAccountPublicAccessBlock/);

    for (const flag of FLAGS) {
      const writes = [...source.matchAll(new RegExp(`\\b${flag}\\s*:\\s*([^,}\\n]+)`, 'g'))];
      expect(writes.length).toBeGreaterThan(0);
      for (const write of writes) {
        expect(write[1]?.trim()).toBe('true');
      }
    }

    const scenarios: FakeOptions[] = [
      {},
      { block: BLOCKED },
      { block: OPEN },
      {
        block: {
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: false,
            IgnorePublicAcls: true,
            BlockPublicPolicy: true,
            RestrictPublicBuckets: true,
          },
        },
      },
      { block: { PublicAccessBlockConfiguration: { BlockPublicAcls: true } } },
      { blockError: awsError('NoSuchPublicAccessBlockConfiguration', 'missing') },
      { tags: { TagSet: [] } },
      { tags: { TagSet: [{ Key: 'purpose', Value: 'other-value' }] } },
      { taggingError: awsError('NoSuchTagSet', 'The TagSet does not exist') },
    ];

    let putCount = 0;
    for (const options of scenarios) {
      for (const apply of [undefined, false, true] as const) {
        const { client, send } = fakeClient(options);
        const event = apply === undefined ? EVENT : { ...EVENT, apply };
        await handleRestoreBucketPublicAccessBlock(event, client);
        for (const command of puts(send)) {
          putCount += 1;
          const put = command as PutPublicAccessBlockCommand;
          expect(put.input.PublicAccessBlockConfiguration).toEqual({
            BlockPublicAcls: true,
            IgnorePublicAcls: true,
            BlockPublicPolicy: true,
            RestrictPublicBuckets: true,
          });
          expect(put.constructor.name).toBe('PutPublicAccessBlockCommand');
        }
        for (const call of send.mock.calls) {
          const command = call[0] as { constructor: { name: string } };
          expect(command.constructor.name).not.toBe('DeletePublicAccessBlockCommand');
          expect(command.constructor.name).not.toMatch(/Policy|Acl|Account/);
        }
      }
    }
    expect(putCount).toBeGreaterThan(0);
  });
});
