/**
 * Tests for the bucket public access block fix.
 * The AWS client is a fake. These tests do not call AWS.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ALLOWED_FIXES } from '../../src/fixes/allow-list.js';
import { FIX_RUNNERS, registryKeysMatchAllowList } from '../../src/fixes/registry.js';
import {
  ACTION,
  IAM_ACTIONS,
  IAM_RESOURCE,
  UNDO_ACTION,
  actionMatchesAllowList,
  restoreBucketPublicAccessBlock,
  undoRestoreBucketPublicAccessBlock,
  type BucketCommand,
  type BucketPublicAccessBlockClient,
  type PublicAccessBlockFlags,
} from '../../src/fixes/restore-bucket-public-access-block.js';

const BUCKET = 'demo-logs-bucket';
const OTHER_BUCKET = 'other-demo-bucket';

const ALL_TRUE: PublicAccessBlockFlags = {
  BlockPublicAcls: true,
  IgnorePublicAcls: true,
  BlockPublicPolicy: true,
  RestrictPublicBuckets: true,
};

const MIXED: PublicAccessBlockFlags = {
  BlockPublicAcls: false,
  IgnorePublicAcls: true,
  BlockPublicPolicy: false,
  RestrictPublicBuckets: true,
};

const EVENT = {
  eventSource: 's3.amazonaws.com',
  eventName: 'DeleteBucketPublicAccessBlock',
  requestParameters: {
    bucketName: BUCKET,
  },
};

const PUT = {
  action: ACTION,
  input: {
    Bucket: BUCKET,
    PublicAccessBlockConfiguration: ALL_TRUE,
  },
};

const source = readFileSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../src/fixes/restore-bucket-public-access-block.ts'),
  'utf8',
);

function missingBlock(field: 'name' | 'code' | 'Code' = 'name'): Error {
  const error = new Error('missing-block');
  if (field === 'name') {
    error.name = 'NoSuchPublicAccessBlockConfiguration';
    return error;
  }
  return Object.assign(error, { [field]: 'NoSuchPublicAccessBlockConfiguration' });
}

function fakeClient(options?: {
  initial?: PublicAccessBlockFlags | 'absent';
  getError?: unknown;
  getResponse?: unknown;
  putError?: unknown;
}): {
  client: BucketPublicAccessBlockClient;
  send: ReturnType<typeof vi.fn>;
  current: () => PublicAccessBlockFlags | 'absent';
} {
  let current: PublicAccessBlockFlags | 'absent' = options?.initial ?? 'absent';
  const send = vi.fn(async (command: BucketCommand) => {
    if (command.action === 'GetPublicAccessBlock') {
      if (options?.getError !== undefined) {
        throw options.getError;
      }
      if (options?.getResponse !== undefined) {
        return options.getResponse;
      }
      if (current === 'absent') {
        throw missingBlock();
      }
      return { PublicAccessBlockConfiguration: { ...current } };
    }
    if (command.action === ACTION) {
      if (options?.putError !== undefined) {
        throw options.putError;
      }
      current = { ...command.input.PublicAccessBlockConfiguration };
      return {};
    }
    if (command.action === UNDO_ACTION) {
      if (current === 'absent') {
        throw missingBlock();
      }
      current = 'absent';
      return {};
    }
    throw new Error('unexpected action');
  });
  return {
    client: { send },
    send,
    current: () => current,
  };
}

function sent(send: ReturnType<typeof vi.fn>): BucketCommand[] {
  return send.mock.calls.map((call) => call[0] as BucketCommand);
}

beforeEach(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('this test must not call fetch');
  });
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'info').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.spyOn(console, 'debug').mockImplementation(() => {});
});

afterEach(() => {
  expect(console.log).not.toHaveBeenCalled();
  expect(console.info).not.toHaveBeenCalled();
  expect(console.warn).not.toHaveBeenCalled();
  expect(console.error).not.toHaveBeenCalled();
  expect(console.debug).not.toHaveBeenCalled();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('restoreBucketPublicAccessBlock', () => {
  it('uses the one allow-listed action', () => {
    expect(ACTION).toBe('PutPublicAccessBlock');
    expect(ACTION).toBe(ALLOWED_FIXES['restore-bucket-public-access-block'].action);
    expect(actionMatchesAllowList).toBe(true);
    expect(UNDO_ACTION).toBe('DeleteBucketPublicAccessBlock');
    expect(IAM_ACTIONS).toEqual(['s3:GetBucketPublicAccessBlock', 's3:PutBucketPublicAccessBlock']);
    expect(IAM_RESOURCE).toBe('arn:aws:s3:::<bucket>');
    expect(IAM_RESOURCE.includes('*')).toBe(false);
    expect(source.match(/\.send\(/g)).toEqual(['.send(']);
    expect(source.includes('s3control')).toBe(false);
    expect(source.includes('AccountPublicAccessBlock')).toBe(false);
  });

  it('keeps registry keys and allow-list keys the same', () => {
    expect(registryKeysMatchAllowList).toBe(true);
    expect(Object.keys(FIX_RUNNERS)).toEqual(Object.keys(ALLOWED_FIXES));
    expect(FIX_RUNNERS['restore-bucket-public-access-block']).toBe(restoreBucketPublicAccessBlock);
  });

  it('returns the put plan and does not call AWS by default', async () => {
    const { client, send } = fakeClient();

    const result = await restoreBucketPublicAccessBlock(EVENT, client);

    expect(result).toEqual({
      ok: true,
      applied: false,
      action: ACTION,
      bucket: BUCKET,
      command: PUT,
    });
    expect(send).not.toHaveBeenCalled();
  });

  it('does not call AWS when apply is false', async () => {
    const { client, send } = fakeClient();

    const result = await restoreBucketPublicAccessBlock(EVENT, client, { apply: false });

    expect(result.ok && result.applied).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('does not treat apply on the input object as the flag', async () => {
    const { client, send } = fakeClient();

    const result = await restoreBucketPublicAccessBlock({ ...EVENT, apply: true }, client);

    expect(result.ok && result.applied).toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('puts all four flags on the one bucket from a DeleteBucketPublicAccessBlock event', async () => {
    const { client, send } = fakeClient();
    const input = {
      ...EVENT,
      requestParameters: {
        bucketName: BUCKET,
        bucket: OTHER_BUCKET,
        Host: `${OTHER_BUCKET}.s3.amazonaws.com`,
        PublicAccessBlockConfiguration: MIXED,
      },
      resources: [{ ARN: `arn:aws:s3:::${OTHER_BUCKET}` }],
    };

    const result = await restoreBucketPublicAccessBlock(input, client, { apply: true });

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.applied).toBe(true);
    if (!result.applied) {
      return;
    }
    expect(result.recorded).toEqual({ bucket: BUCKET, present: false });
    expect(sent(send)).toEqual([
      { action: 'GetPublicAccessBlock', input: { Bucket: BUCKET } },
      PUT,
    ]);
    expect(JSON.stringify(sent(send)).includes(OTHER_BUCKET)).toBe(false);
    expect(JSON.stringify(sent(send)).includes('s3control')).toBe(false);
    expect(JSON.stringify(sent(send)).includes('AccountId')).toBe(false);
    expect(JSON.stringify(sent(send)).includes('accountId')).toBe(false);
    expect(JSON.stringify(result).includes('missing-block')).toBe(false);
  });

  it('does not call account-level APIs or another bucket', async () => {
    const { client, send } = fakeClient();

    const account = await restoreBucketPublicAccessBlock(
      {
        eventSource: 's3control.amazonaws.com',
        eventName: 'DeleteBucketPublicAccessBlock',
        requestParameters: { bucketName: BUCKET, accountId: '111122223333' },
      },
      client,
      { apply: true },
    );
    const otherName = await restoreBucketPublicAccessBlock(
      {
        ...EVENT,
        eventName: 'DeleteAccountPublicAccessBlock',
        requestParameters: { bucketName: OTHER_BUCKET },
      },
      client,
      { apply: true },
    );

    expect(account).toEqual({ ok: false, reason: 'invalid_input' });
    expect(otherName).toEqual({ ok: false, reason: 'invalid_input' });
    expect(send).not.toHaveBeenCalled();
  });

  it.each([
    ['null', null],
    ['a string', 'demo-logs-bucket'],
    ['an array', [EVENT]],
    ['a missing event name', { ...EVENT, eventName: undefined }],
    ['a bucket delete event', { ...EVENT, eventName: 'DeleteBucket' }],
    ['a missing event source', { ...EVENT, eventSource: undefined }],
    ['an account control source', { ...EVENT, eventSource: 's3control.amazonaws.com' }],
    ['a failed CloudTrail call', { ...EVENT, errorCode: 'AccessDenied' }],
    ['missing request parameters', { eventSource: EVENT.eventSource, eventName: EVENT.eventName }],
    ['request parameters null', { ...EVENT, requestParameters: null }],
    ['a missing bucket name', { ...EVENT, requestParameters: {} }],
    ['an empty bucket name', { ...EVENT, requestParameters: { bucketName: '' } }],
    ['a bucket name in Host only', { ...EVENT, requestParameters: { Host: 'demo-logs-bucket.s3.amazonaws.com' } }],
    ['a bucket field that is not bucketName', { ...EVENT, requestParameters: { bucket: BUCKET } }],
    ['an uppercase name', { ...EVENT, requestParameters: { bucketName: 'Demo-Logs-Bucket' } }],
    ['a short name', { ...EVENT, requestParameters: { bucketName: 'ab' } }],
    ['a long name', { ...EVENT, requestParameters: { bucketName: `a${'b'.repeat(62)}c` } }],
    ['a leading hyphen', { ...EVENT, requestParameters: { bucketName: '-demo-logs' } }],
    ['a trailing dot', { ...EVENT, requestParameters: { bucketName: 'demo-logs.' } }],
    ['consecutive dots', { ...EVENT, requestParameters: { bucketName: 'demo..logs' } }],
    ['an ipv4 shape', { ...EVENT, requestParameters: { bucketName: '192.168.5.4' } }],
    ['a slash', { ...EVENT, requestParameters: { bucketName: 'demo/logs' } }],
    ['a wildcard', { ...EVENT, requestParameters: { bucketName: 'demo-logs-*' } }],
    ['a space', { ...EVENT, requestParameters: { bucketName: 'demo logs' } }],
    ['an account id beside the bucket', { ...EVENT, requestParameters: { bucketName: BUCKET, accountId: '111122223333' } }],
    ['an AccountId beside the bucket', { ...EVENT, requestParameters: { bucketName: BUCKET, AccountId: '111122223333' } }],
    ['a reserved xn-- prefix', { ...EVENT, requestParameters: { bucketName: 'xn--demo-bucket' } }],
    ['a reserved sthree- prefix', { ...EVENT, requestParameters: { bucketName: 'sthree-demo-bucket' } }],
    ['a reserved demo prefix', { ...EVENT, requestParameters: { bucketName: 'amzn-s3-demo-bucket' } }],
    ['a reserved alias suffix', { ...EVENT, requestParameters: { bucketName: 'demo-bucket-s3alias' } }],
    ['a reserved object lambda suffix', { ...EVENT, requestParameters: { bucketName: 'demo-bucket--ol-s3' } }],
    ['a reserved mrap suffix', { ...EVENT, requestParameters: { bucketName: 'demo.bucket.mrap' } }],
    ['a reserved directory suffix', { ...EVENT, requestParameters: { bucketName: 'demo-bucket--x-s3' } }],
    ['a reserved table suffix', { ...EVENT, requestParameters: { bucketName: 'demo-bucket--table-s3' } }],
    ['a numeric bucket name', { ...EVENT, requestParameters: { bucketName: 12 } }],
  ])('refuses %s and does not call AWS', async (_label, input) => {
    const { client, send } = fakeClient();

    const result = await restoreBucketPublicAccessBlock(input, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'invalid_input' });
    expect(send).not.toHaveBeenCalled();
  });

  it('accepts a dotted name and the length bounds on a dry-run', async () => {
    const { client, send } = fakeClient();
    const shortName = 'a1b';
    const longName = `a${'b'.repeat(61)}c`;
    const dotted = 'demo.logs.bucket';

    const short = await restoreBucketPublicAccessBlock(
      { ...EVENT, requestParameters: { bucketName: shortName } },
      client,
    );
    const long = await restoreBucketPublicAccessBlock(
      { ...EVENT, requestParameters: { bucketName: longName } },
      client,
    );
    const dots = await restoreBucketPublicAccessBlock(
      { ...EVENT, requestParameters: { bucketName: dotted } },
      client,
    );

    expect(short.ok && !short.applied && short.bucket).toBe(shortName);
    expect(long.ok && !long.applied && long.bucket).toBe(longName);
    expect(longName).toHaveLength(63);
    expect(dots.ok && !dots.applied && dots.command.input.Bucket).toBe(dotted);
    expect(send).not.toHaveBeenCalled();
  });

  it('ignores block flags on the event', async () => {
    const { client, send } = fakeClient({ initial: MIXED });
    const input = {
      ...EVENT,
      BlockPublicAcls: false,
      requestParameters: {
        bucketName: BUCKET,
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          IgnorePublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
        },
      },
    };

    const result = await restoreBucketPublicAccessBlock(input, client, { apply: true });

    expect(result.ok && result.applied && result.command).toEqual(PUT);
    expect(sent(send)[1]).toEqual(PUT);
  });

  it('undo restores the recorded configuration', async () => {
    const { client, send, current } = fakeClient({ initial: MIXED });

    const applied = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });
    expect(applied.ok && applied.applied).toBe(true);
    if (!applied.ok || !applied.applied) {
      return;
    }
    expect(applied.recorded).toEqual({ bucket: BUCKET, present: true, configuration: MIXED });

    const planned = await undoRestoreBucketPublicAccessBlock(applied.recorded, client);
    expect(planned.ok && planned.applied).toBe(false);
    if (!planned.ok) {
      return;
    }
    expect(planned.command).toEqual({
      action: ACTION,
      input: { Bucket: BUCKET, PublicAccessBlockConfiguration: MIXED },
    });

    const undone = await undoRestoreBucketPublicAccessBlock({ ...applied.recorded, apply: true }, client, {
      apply: true,
    });

    expect(undone).toEqual({
      ok: true,
      applied: true,
      bucket: BUCKET,
      command: {
        action: ACTION,
        input: { Bucket: BUCKET, PublicAccessBlockConfiguration: MIXED },
      },
    });
    expect(current()).toEqual(MIXED);
    expect(sent(send).map((command) => command.action)).toEqual([
      'GetPublicAccessBlock',
      ACTION,
      ACTION,
    ]);
    expect(sent(send).every((command) => command.input.Bucket === BUCKET)).toBe(true);
  });

  it('undo deletes the block when none was recorded', async () => {
    const { client, send, current } = fakeClient();

    const applied = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });
    expect(applied.ok && applied.applied).toBe(true);
    if (!applied.ok || !applied.applied) {
      return;
    }

    const undone = await undoRestoreBucketPublicAccessBlock(applied.recorded, client, { apply: true });
    const again = await undoRestoreBucketPublicAccessBlock(applied.recorded, client, { apply: true });

    expect(undone).toEqual({
      ok: true,
      applied: true,
      bucket: BUCKET,
      command: { action: UNDO_ACTION, input: { Bucket: BUCKET } },
    });
    expect(again.ok && again.applied).toBe(true);
    expect(JSON.stringify(again).includes('missing-block')).toBe(false);
    expect(current()).toBe('absent');
    expect(sent(send).map((command) => command.action)).toEqual([
      'GetPublicAccessBlock',
      ACTION,
      UNDO_ACTION,
      UNDO_ACTION,
    ]);
    expect(sent(send).every((command) => command.input.Bucket === BUCKET)).toBe(true);
  });

  it('recognizes a missing block on name, code, or Code', async () => {
    for (const field of ['name', 'code', 'Code'] as const) {
      const { client, send } = fakeClient({ getError: missingBlock(field) });

      const result = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });

      expect(result.ok && result.applied && result.recorded).toEqual({ bucket: BUCKET, present: false });
      expect(sent(send).map((command) => command.action)).toEqual(['GetPublicAccessBlock', ACTION]);
    }
  });

  it('is safe to run twice', async () => {
    const { client, send, current } = fakeClient();

    const first = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });
    const second = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) {
      return;
    }
    expect(first.applied).toBe(true);
    expect(second.applied).toBe(true);
    if (!first.applied || !second.applied) {
      return;
    }
    expect(first.recorded).toEqual({ bucket: BUCKET, present: false });
    expect(second.recorded).toEqual({ bucket: BUCKET, present: true, configuration: ALL_TRUE });
    const puts = sent(send).filter((command) => command.action === ACTION);
    expect(puts).toEqual([PUT, PUT]);
    expect(sent(send).every((command) => command.input.Bucket === BUCKET)).toBe(true);
    expect(current()).toEqual(ALL_TRUE);

    const undoSecond = await undoRestoreBucketPublicAccessBlock(second.recorded, client, { apply: true });
    expect(undoSecond.ok && undoSecond.applied && undoSecond.command.action).toBe(ACTION);
    expect(current()).toEqual(ALL_TRUE);
  });

  it('does not write when the read fails for another reason', async () => {
    const { client, send } = fakeClient({
      getError: Object.assign(new Error('secret-account-detail'), { name: 'NoSuchBucket' }),
    });

    const result = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'aws_error' });
    expect(JSON.stringify(result).includes('secret-account-detail')).toBe(false);
    expect(sent(send).map((command) => command.action)).toEqual(['GetPublicAccessBlock']);
  });

  it('does not treat the error text as a missing block', async () => {
    const { client, send } = fakeClient({
      getError: new Error('NoSuchPublicAccessBlockConfiguration'),
    });

    const result = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'aws_error' });
    expect(JSON.stringify(result).includes('NoSuchPublicAccessBlockConfiguration')).toBe(false);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['a missing flag', { PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true } }],
    ['string flags', { PublicAccessBlockConfiguration: { ...ALL_TRUE, RestrictPublicBuckets: 'true' } }],
    ['a null body', null],
  ])('does not write when the read returns %s', async (_label, getResponse) => {
    const { client, send } = fakeClient({ getResponse });

    const result = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'aws_error' });
    expect(sent(send).map((command) => command.action)).toEqual(['GetPublicAccessBlock']);
  });

  it('returns aws_error when the put throws and hides the error text', async () => {
    const { client, send } = fakeClient({ putError: new Error('secret-account-detail') });

    const result = await restoreBucketPublicAccessBlock(EVENT, client, { apply: true });

    expect(result).toEqual({ ok: false, reason: 'aws_error' });
    expect(JSON.stringify(result).includes('secret-account-detail')).toBe(false);
    expect(sent(send).map((command) => command.action)).toEqual(['GetPublicAccessBlock', ACTION]);
  });

  it('refuses a bad undo snapshot and does not call AWS', async () => {
    const { client, send } = fakeClient();
    const bad = [
      null,
      { bucket: BUCKET },
      { bucket: 'ab', present: false },
      { bucket: OTHER_BUCKET, present: false, configuration: MIXED },
      { bucket: BUCKET, present: true, configuration: { ...MIXED, RestrictPublicBuckets: 'yes' } },
      { bucket: BUCKET, present: 'false' },
    ];

    for (const snapshot of bad) {
      const result = await undoRestoreBucketPublicAccessBlock(snapshot, client, { apply: true });
      expect(result).toEqual({ ok: false, reason: 'invalid_input' });
    }
    expect(send).not.toHaveBeenCalled();
  });
});
