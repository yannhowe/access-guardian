/**
 * Tests for the contain-iam-user Lambda. The IAM client is a fake.
 * These tests do not call AWS.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  GetUserCommand,
  GetUserPolicyCommand,
  ListAttachedUserPoliciesCommand,
  ListGroupsForUserCommand,
  ListUserTagsCommand,
  PutUserPolicyCommand,
} from '@aws-sdk/client-iam';
import { ALLOWED_FIXES } from '../../src/fixes/allow-list.js';
import {
  ACTION,
  CONTAINMENT_POLICY,
  POLICY_NAME,
  containmentDocument,
  handleContainIamUser,
  handler,
  type AwsClient,
} from '../../src/fixes/contain-iam-user/handler.js';
import { FIX_REGISTRY, registryKeysMatchAllowList } from '../../src/fixes/registry.js';

const EXACT_DENY = {
  Version: '2012-10-17',
  Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }],
};

const EVENT = {
  caseId: 'case-06',
  userName: 'onleave-demo',
  hrStatus: 'On leave',
};

const TAGS = [
  { Key: 'purpose', Value: 'ag-demo-synthetic' },
  { Key: 'auto-remediate', Value: 'true' },
];

type PolicyDoc = 'absent' | string;

type FakeOptions = {
  tags?: Array<{ Key: string; Value: string }>;
  attached?: Array<{ PolicyName?: string; PolicyArn?: string }>;
  groups?: Array<{ GroupName?: string; Arn?: string; Path?: string }>;
  policyDocument?: PolicyDoc;
  user?: { UserName?: string; Arn?: string; Path?: string };
  missingUser?: boolean;
  putError?: Error;
  listTagsError?: Error;
};

function fakeClient(options: FakeOptions = {}): { client: AwsClient; send: ReturnType<typeof vi.fn> } {
  const send = vi.fn(async (command: unknown) => {
    if (command instanceof ListUserTagsCommand) {
      if (options.listTagsError !== undefined) {
        throw options.listTagsError;
      }
      if (options.missingUser === true) {
        throw Object.assign(new Error('The user does not exist'), { name: 'NoSuchEntityException' });
      }
      return { Tags: options.tags ?? TAGS, IsTruncated: false };
    }
    if (command instanceof GetUserCommand) {
      const userName = command.input.UserName ?? EVENT.userName;
      return {
        User: options.user ?? {
          UserName: userName,
          Arn: `arn:aws:iam::user/${userName}`,
          Path: '/',
        },
      };
    }
    if (command instanceof ListAttachedUserPoliciesCommand) {
      return { AttachedPolicies: options.attached ?? [], IsTruncated: false };
    }
    if (command instanceof ListGroupsForUserCommand) {
      return { Groups: options.groups ?? [], IsTruncated: false };
    }
    if (command instanceof GetUserPolicyCommand) {
      if (options.policyDocument === undefined || options.policyDocument === 'absent') {
        throw Object.assign(new Error('The policy does not exist'), { name: 'NoSuchEntityException' });
      }
      return { PolicyDocument: options.policyDocument };
    }
    if (command instanceof PutUserPolicyCommand && options.putError !== undefined) {
      throw options.putError;
    }
    return {};
  });
  return { client: { send }, send };
}

function puts(send: ReturnType<typeof vi.fn>): Array<{ input: { UserName?: string; PolicyName?: string; PolicyDocument?: string } }> {
  return send.mock.calls
    .map((call) => call[0])
    .filter((command) => command instanceof PutUserPolicyCommand);
}

beforeEach(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('this test must not call fetch');
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('contain-iam-user handler', () => {
  it('names the one allow-listed action and the constant deny', () => {
    expect(ACTION).toBe('iam:PutUserPolicy');
    expect(ACTION).toBe(ALLOWED_FIXES['contain-iam-user'].action);
    expect(POLICY_NAME).toBe('ag-containment-deny');
    expect(CONTAINMENT_POLICY).toEqual(EXACT_DENY);
    expect(containmentDocument()).toBe(JSON.stringify(EXACT_DENY));
    expect(registryKeysMatchAllowList).toBe(true);
    expect(FIX_REGISTRY['contain-iam-user']).toEqual({
      findingKey: 'identity:on_leave_user_activity',
      functionName: 'ag-fix-contain-iam-user',
    });
    expect(typeof handler).toBe('function');
  });

  it('scopes the role to one user and the constant action', () => {
    const policyPath = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../../src/fixes/contain-iam-user/policy.json',
    );
    const policy = JSON.parse(readFileSync(policyPath, 'utf8')) as {
      Statement: Array<{ Action: string[]; Resource: string; Condition?: unknown }>;
    };
    const actions = policy.Statement.flatMap((statement) => statement.Action);
    expect(actions).toEqual([
      'iam:ListUserTags',
      'iam:GetUser',
      'iam:GetUserPolicy',
      'iam:ListAttachedUserPolicies',
      'iam:ListGroupsForUser',
      'iam:PutUserPolicy',
    ]);
    expect(actions.some((action) => action.includes('*'))).toBe(false);
    expect(actions.some((action) => action.startsWith('iam:Delete'))).toBe(false);
    expect(actions.some((action) => action.includes('AccessKey') || action.includes('LoginProfile'))).toBe(false);
    for (const statement of policy.Statement) {
      expect(statement.Resource).toBe('arn:aws:iam::*:user/*');
    }
    const tagCondition = {
      StringEquals: {
        'iam:ResourceTag/auto-remediate': 'true',
        'iam:ResourceTag/purpose': 'ag-demo-synthetic',
      },
    };
    const listTags = policy.Statement.find((statement) => statement.Action.includes('iam:ListUserTags'));
    expect(listTags?.Condition).toBeUndefined();
    const put = policy.Statement.find((statement) => statement.Action.includes('iam:PutUserPolicy'));
    const getUser = policy.Statement.find((statement) => statement.Action.includes('iam:GetUser'));
    expect(put?.Condition).toEqual(tagCondition);
    expect(getUser?.Condition).toEqual(tagCondition);
  });

  it('attaches the deny to an on-leave tagged user', async () => {
    const { client, send } = fakeClient();

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({
      ok: true,
      status: 'ok',
      changed: true,
      dryRun: false,
      action: ACTION,
      caseId: 'case-06',
      userName: 'onleave-demo',
      policyName: POLICY_NAME,
      policyDocument: containmentDocument(),
      reason: 'contained',
    });
    expect(puts(send)).toHaveLength(1);
    expect(puts(send)[0]?.input).toEqual({
      UserName: 'onleave-demo',
      PolicyName: 'ag-containment-deny',
      PolicyDocument: JSON.stringify(EXACT_DENY),
    });
    const names = send.mock.calls.map((call) => call[0].input.UserName);
    expect(names.every((name: string) => name === 'onleave-demo')).toBe(true);
  });

  it('sends the same document for two different users', async () => {
    const documents: string[] = [];
    for (const userName of ['onleave-demo', 'other-demo']) {
      const { client, send } = fakeClient();
      await handleContainIamUser({ ...EVENT, userName, apply: true }, client);
      documents.push(puts(send)[0]?.input.PolicyDocument ?? '');
    }
    expect(documents[0]).toBe(JSON.stringify(EXACT_DENY));
    expect(documents[1]).toBe(documents[0]);
  });

  it('returns a dry run and does not put when apply is omitted', async () => {
    const { client, send } = fakeClient();

    const result = await handleContainIamUser(EVENT, client);

    expect(result).toMatchObject({
      ok: true,
      status: 'ok',
      changed: false,
      dryRun: true,
      reason: 'dry_run',
      policyName: 'ag-containment-deny',
      policyDocument: JSON.stringify(EXACT_DENY),
    });
    expect(puts(send)).toEqual([]);
    expect(send.mock.calls.some((call) => call[0] instanceof ListUserTagsCommand)).toBe(true);
    expect(send.mock.calls.some((call) => call[0] instanceof GetUserCommand)).toBe(true);
  });

  it('does not put when apply is false', async () => {
    const { client, send } = fakeClient();

    const result = await handleContainIamUser({ ...EVENT, apply: false }, client);

    expect(result).toMatchObject({ ok: true, changed: false, dryRun: true, reason: 'dry_run' });
    expect(puts(send)).toEqual([]);
  });

  it('is idempotent when the same deny is already attached', async () => {
    let stored: string | undefined;
    const send = vi.fn(async (command: unknown) => {
      if (command instanceof ListUserTagsCommand) {
        return { Tags: TAGS, IsTruncated: false };
      }
      if (command instanceof GetUserCommand) {
        return { User: { UserName: 'onleave-demo', Arn: 'arn:aws:iam::user/onleave-demo', Path: '/' } };
      }
      if (command instanceof ListAttachedUserPoliciesCommand) {
        return { AttachedPolicies: [], IsTruncated: false };
      }
      if (command instanceof ListGroupsForUserCommand) {
        return { Groups: [], IsTruncated: false };
      }
      if (command instanceof GetUserPolicyCommand) {
        if (stored === undefined) {
          throw Object.assign(new Error('The policy does not exist'), { name: 'NoSuchEntityException' });
        }
        return { PolicyDocument: encodeURIComponent(stored) };
      }
      if (command instanceof PutUserPolicyCommand) {
        stored = command.input.PolicyDocument;
        return {};
      }
      return {};
    });

    const first = await handleContainIamUser({ ...EVENT, apply: true }, { send });
    const second = await handleContainIamUser({ ...EVENT, apply: true }, { send });

    expect(first).toMatchObject({ ok: true, changed: true, reason: 'contained' });
    expect(second).toMatchObject({ ok: true, status: 'ok', changed: false, reason: 'already_contained' });
    expect(puts(send)).toHaveLength(1);
    expect(puts(send)[0]?.input.PolicyDocument).toBe(JSON.stringify(EXACT_DENY));
  });

  it('replaces a different document with the constant deny', async () => {
    const { client, send } = fakeClient({
      policyDocument: JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
      }),
    });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, reason: 'contained' });
    expect(puts(send)[0]?.input.PolicyDocument).toBe(JSON.stringify(EXACT_DENY));
  });

  it.each([
    ['an active user', { ...EVENT, hrStatus: 'Active' }, 'hrStatus must be exactly On leave'],
    ['a lower case status', { ...EVENT, hrStatus: 'on leave' }, 'hrStatus must be exactly On leave'],
    ['a role ARN', { ...EVENT, userName: 'arn:aws:iam::role/demo-role' }, 'userName matches a role, assumed role, or SSO principal'],
    ['an assumed role', { ...EVENT, userName: 'arn:aws:sts::assumed-role/demo/session' }, 'userName matches a role, assumed role, or SSO principal'],
    ['an SSO user', { ...EVENT, userName: 'AWSReservedSSO_demo_example' }, 'userName matches a role, assumed role, or SSO principal'],
    ['an aws-reserved path', { ...EVENT, userName: 'team/aws-reserved/demo' }, 'userName matches a role, assumed role, or SSO principal'],
    ['a user ARN', { ...EVENT, userName: 'arn:aws:iam::user/onleave-demo' }, 'userName must be a plain IAM user name'],
    ['an ag- user', { ...EVENT, userName: 'ag-bot-demo' }, 'userName starts with ag-'],
  ])('refuses %s and does not call AWS', async (_label, event, reason) => {
    const { client, send } = fakeClient();

    const result = await handleContainIamUser(event, client);

    expect(result).toEqual({ ok: false, status: 'refused', changed: false, reason });
    expect(send).not.toHaveBeenCalled();
  });

  it.each([
    ['no tags', []],
    ['only the purpose tag', [{ Key: 'purpose', Value: 'ag-demo-synthetic' }]],
    ['only the auto-remediate tag', [{ Key: 'auto-remediate', Value: 'true' }]],
    ['a wrong purpose value', [{ Key: 'purpose', Value: 'other' }, { Key: 'auto-remediate', Value: 'true' }]],
    ['a wrong auto-remediate value', [{ Key: 'purpose', Value: 'ag-demo-synthetic' }, { Key: 'auto-remediate', Value: 'True' }]],
    ['a wrong key case', [{ Key: 'Purpose', Value: 'ag-demo-synthetic' }, { Key: 'auto-remediate', Value: 'true' }]],
  ])('refuses an untagged user when %s and does not put', async (_label, tags) => {
    const { client, send } = fakeClient({ tags });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      status: 'refused',
      changed: false,
      reason: 'IAM user is missing tag auto-remediate=true or purpose=ag-demo-synthetic',
    });
    expect(puts(send)).toEqual([]);
  });

  it.each([
    ['AdministratorAccess', { PolicyName: 'AdministratorAccess', PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }],
    ['IAMFullAccess by name', { PolicyName: 'IAMFullAccess', PolicyArn: 'arn:aws:iam::aws:policy/IAMFullAccess' }],
  ])('refuses an admin user with %s and does not put', async (_label, policy) => {
    const { client, send } = fakeClient({ attached: [policy] });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toEqual({ ok: false, status: 'refused', changed: false, reason: 'user is an admin' });
    expect(puts(send)).toEqual([]);
  });

  it.each([['Admin'], ['Administrators'], ['Administrator']])(
    'refuses a user in the %s group and does not put',
    async (groupName) => {
      const { client, send } = fakeClient({ groups: [{ GroupName: groupName, Path: '/' }] });

      const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

      expect(result).toEqual({ ok: false, status: 'refused', changed: false, reason: 'user is an admin' });
      expect(puts(send)).toEqual([]);
    },
  );

  it('still contains a tagged user whose only attached policy is not admin', async () => {
    const { client, send } = fakeClient({
      attached: [{ PolicyName: 'ReadOnlyAccess', PolicyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' }],
      groups: [{ GroupName: 'Developers', Path: '/' }],
    });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toMatchObject({ ok: true, changed: true, reason: 'contained' });
    expect(puts(send)).toHaveLength(1);
  });

  it('refuses a missing user', async () => {
    const { client, send } = fakeClient({ missingUser: true });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      status: 'refused',
      changed: false,
      reason: 'IAM user does not exist',
    });
    expect(puts(send)).toEqual([]);
  });

  it.each([
    ['a string apply flag', { ...EVENT, apply: 'true' }],
    ['an unknown policy field', { ...EVENT, apply: true, policyDocument: JSON.stringify(EXACT_DENY) }],
    ['a bad case id', { ...EVENT, caseId: '' }],
    ['null', null],
  ])('refuses %s and does not call AWS', async (_label, event) => {
    const { client, send } = fakeClient();

    const result = await handleContainIamUser(event, client);

    expect(result).toMatchObject({ ok: false, status: 'refused', changed: false });
    expect(send).not.toHaveBeenCalled();
  });

  it('returns the AWS error code and message when list tags fails', async () => {
    const { client, send } = fakeClient({
      listTagsError: Object.assign(new Error('User is not authorized'), { name: 'AccessDenied' }),
    });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

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
      putError: Object.assign(new Error('User is not authorized'), { name: 'AccessDeniedException' }),
    });

    const result = await handleContainIamUser({ ...EVENT, apply: true }, client);

    expect(result).toEqual({
      ok: false,
      changed: false,
      errorCode: 'AccessDeniedException',
      errorMessage: 'User is not authorized',
    });
    expect(puts(send)).toHaveLength(1);
  });
});
