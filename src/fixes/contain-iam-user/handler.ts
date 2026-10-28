/**
 * Lambda ag-fix-contain-iam-user.
 *
 * One mutating call: iam:PutUserPolicy.
 * Reads: iam:ListUserTags, iam:GetUser, iam:GetUserPolicy,
 * iam:ListAttachedUserPolicies, and iam:ListGroupsForUser.
 *
 * The policy name and the policy document are constants. Input cannot
 * change either one. The document is a single deny of every action on
 * every resource. Undo is deleting the inline policy ag-containment-deny.
 * This handler does not delete it.
 *
 * hrStatus is a structured field from AG Context. This handler trusts
 * that field as given. It does not read case text or finding text.
 *
 * apply defaults to false. Only a boolean true writes. This file does
 * not call Grok.
 *
 * What Grok decides: nothing.
 * What code decides: whether hrStatus is exactly On leave, whether
 * userName is a plain IAM user name, whether the user exists and is
 * tagged auto-remediate=true and purpose=ag-demo-synthetic, whether the
 * user is an admin, whether ag-containment-deny is already that deny
 * document, and whether the one put is sent.
 */
import {
  GetUserCommand,
  GetUserPolicyCommand,
  IAMClient,
  ListAttachedUserPoliciesCommand,
  ListGroupsForUserCommand,
  ListUserTagsCommand,
  PutUserPolicyCommand,
} from '@aws-sdk/client-iam';

export const ACTION = 'iam:PutUserPolicy' as const;
export const POLICY_NAME = 'ag-containment-deny' as const;

/** Hardcoded deny. Every put and every dry-run report uses this object. */
export const CONTAINMENT_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Deny',
      Action: '*',
      Resource: '*',
    },
  ],
} as const;

const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';
const AUTO_REMEDIATE_TAG_VALUE = 'true';
const PURPOSE_TAG_KEY = 'purpose';
const PURPOSE_TAG_VALUE = 'ag-demo-synthetic';
const ADMIN_POLICY_NAMES = new Set(['AdministratorAccess', 'IAMFullAccess']);
const ADMIN_GROUP_NAMES = new Set(['Admin', 'Administrators', 'Administrator']);
const MAX_PAGES = 5;
const CASE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const USER_NAME = /^[A-Za-z0-9+=,.@_-]{1,64}$/;
const ALLOWED_KEYS = new Set(['caseId', 'userName', 'hrStatus', 'apply']);

export function containmentDocument(): string {
  return JSON.stringify(CONTAINMENT_POLICY);
}

type Tag = { Key?: unknown; Value?: unknown };

function hasAutoRemediateTag(tags: readonly Tag[]): boolean {
  for (const tag of tags) {
    if (tag.Key === AUTO_REMEDIATE_TAG_KEY && tag.Value === AUTO_REMEDIATE_TAG_VALUE) {
      return true;
    }
  }
  return false;
}

function hasPurposeTag(tags: readonly Tag[]): boolean {
  for (const tag of tags) {
    if (tag.Key === PURPOSE_TAG_KEY && tag.Value === PURPOSE_TAG_VALUE) {
      return true;
    }
  }
  return false;
}

export type AwsClient = {
  send(command: unknown): Promise<unknown>;
};

export type ContainIamUserInput = {
  caseId: string;
  userName: string;
  hrStatus: 'On leave';
  apply: boolean;
};

export type FixResult =
  | {
      ok: true;
      status: 'ok';
      changed: boolean;
      dryRun: boolean;
      action: typeof ACTION;
      caseId: string;
      userName: string;
      policyName: typeof POLICY_NAME;
      policyDocument: string;
      reason: 'dry_run' | 'already_contained' | 'contained';
    }
  | {
      ok: false;
      status: 'refused';
      changed: false;
      reason: string;
    }
  | {
      ok: false;
      changed: false;
      errorCode: string;
      errorMessage: string;
    };

type Planned = ContainIamUserInput;

type GuardRefusal = {
  ok: false;
  status: 'refused';
  changed: false;
  reason: string;
};

type AwsFailure = {
  ok: false;
  changed: false;
  errorCode: string;
  errorMessage: string;
};

type Failure = GuardRefusal | AwsFailure;

type Page<T> = {
  items: T[];
  truncated: boolean;
  marker: string | undefined;
};

export async function handler(event: unknown): Promise<FixResult> {
  const client = new IAMClient({});
  return handleContainIamUser(event, client);
}

/**
 * Validate the event, read the user, and attach the constant deny only
 * when apply is true and that deny is not already present.
 */
export async function handleContainIamUser(event: unknown, client: AwsClient): Promise<FixResult> {
  const parsed = parseEvent(event);
  if (!parsed.ok) {
    return refused(parsed.reason);
  }

  const input = parsed.value;
  const listed = await readUserTags(client, input.userName);
  if (!listed.ok) {
    return listed.failure;
  }
  if (!hasAutoRemediateTag(listed.tags) || !hasPurposeTag(listed.tags)) {
    return refused('IAM user is missing tag auto-remediate=true or purpose=ag-demo-synthetic');
  }

  const user = await readUser(client, input.userName);
  if (!user.ok) {
    return user.failure;
  }

  const attached = await readAttachedPolicies(client, input.userName);
  if (!attached.ok) {
    return attached.failure;
  }
  const groups = await readGroups(client, input.userName);
  if (!groups.ok) {
    return groups.failure;
  }
  if (attached.admin || groups.admin) {
    return refused('user is an admin');
  }

  const current = await readContainmentPolicy(client, input.userName);
  if (!current.ok) {
    return current.failure;
  }
  if (current.matches) {
    return succeeded(input, false, 'already_contained');
  }
  if (!input.apply) {
    return succeeded(input, false, 'dry_run');
  }

  try {
    await client.send(
      new PutUserPolicyCommand({
        UserName: input.userName,
        PolicyName: POLICY_NAME,
        PolicyDocument: containmentDocument(),
      }),
    );
  } catch (err) {
    return awsFailure(err);
  }

  return succeeded(input, true, 'contained');
}

function succeeded(input: Planned, changed: boolean, reason: 'dry_run' | 'already_contained' | 'contained'): FixResult {
  return {
    ok: true,
    status: 'ok',
    changed,
    dryRun: !input.apply,
    action: ACTION,
    caseId: input.caseId,
    userName: input.userName,
    policyName: POLICY_NAME,
    policyDocument: containmentDocument(),
    reason,
  };
}

function refused(reason: string): GuardRefusal {
  return { ok: false, status: 'refused', changed: false, reason };
}

function parseEvent(event: unknown): { ok: true; value: Planned } | { ok: false; reason: string } {
  if (typeof event !== 'object' || event === null || Array.isArray(event)) {
    return { ok: false, reason: 'input must be an object' };
  }
  const record = event as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!ALLOWED_KEYS.has(key)) {
      return { ok: false, reason: 'input has an unknown field' };
    }
  }
  if (typeof record.caseId !== 'string' || !CASE_ID.test(record.caseId)) {
    return { ok: false, reason: 'caseId must be 1 to 64 letters, digits, hyphens, or underscores' };
  }

  const userName = userNameRefusal(record.userName);
  if (userName !== undefined) {
    return { ok: false, reason: userName };
  }
  if (record.hrStatus !== 'On leave') {
    return { ok: false, reason: 'hrStatus must be exactly On leave' };
  }
  if ('apply' in record && typeof record.apply !== 'boolean') {
    return { ok: false, reason: 'apply must be a boolean' };
  }

  return {
    ok: true,
    value: {
      caseId: record.caseId,
      userName: record.userName as string,
      hrStatus: 'On leave',
      apply: record.apply === true,
    },
  };
}

function userNameRefusal(name: unknown): string | undefined {
  if (typeof name !== 'string' || name.length === 0) {
    return 'userName must be a plain IAM user name';
  }
  if (name.startsWith('ag-')) {
    return 'userName starts with ag-';
  }
  if (
    name.includes('AWSReservedSSO') ||
    name.includes('/aws-reserved/') ||
    name.includes(':role/') ||
    name.includes(':assumed-role/')
  ) {
    return 'userName matches a role, assumed role, or SSO principal';
  }
  if (name.startsWith('arn:') || !USER_NAME.test(name)) {
    return 'userName must be a plain IAM user name';
  }
  return undefined;
}

function principalProblem(value: string): string | undefined {
  if (
    value.includes('AWSReservedSSO') ||
    value.includes('/aws-reserved/') ||
    value.includes(':role/') ||
    value.includes(':assumed-role/')
  ) {
    return 'IAM principal matches a role, assumed role, or SSO principal';
  }
  return undefined;
}

async function readUserTags(
  client: AwsClient,
  userName: string,
): Promise<{ ok: true; tags: Tag[] } | { ok: false; failure: Failure }> {
  const tags: Tag[] = [];
  const seen = new Set<string>();
  let marker: string | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    if (marker !== undefined && seen.has(marker)) {
      return { ok: false, failure: refused('iam:ListUserTags did not advance') };
    }
    if (marker !== undefined) {
      seen.add(marker);
    }
    let response: unknown;
    try {
      response = await client.send(
        new ListUserTagsCommand(marker === undefined ? { UserName: userName } : { UserName: userName, Marker: marker }),
      );
    } catch (err) {
      if (isMissingEntity(err)) {
        return { ok: false, failure: refused('IAM user does not exist') };
      }
      return { ok: false, failure: awsFailure(err) };
    }
    const parsed = readTagPage(response);
    if (parsed === undefined) {
      return { ok: false, failure: refused('iam:ListUserTags did not return a tag list') };
    }
    tags.push(...parsed.items);
    if (!parsed.truncated) {
      return { ok: true, tags };
    }
    if (parsed.marker === undefined) {
      return { ok: false, failure: refused('iam:ListUserTags was truncated without a marker') };
    }
    marker = parsed.marker;
  }
  return { ok: false, failure: refused('iam:ListUserTags returned too many pages') };
}

async function readUser(
  client: AwsClient,
  userName: string,
): Promise<{ ok: true } | { ok: false; failure: Failure }> {
  let response: unknown;
  try {
    response = await client.send(new GetUserCommand({ UserName: userName }));
  } catch (err) {
    if (isMissingEntity(err)) {
      return { ok: false, failure: refused('IAM user does not exist') };
    }
    return { ok: false, failure: awsFailure(err) };
  }
  const problem = userProblem(response, userName);
  if (problem !== undefined) {
    return { ok: false, failure: refused(problem) };
  }
  return { ok: true };
}

function userProblem(payload: unknown, userName: string): string | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return 'iam:GetUser did not return the user';
  }
  const user = (payload as { User?: unknown }).User;
  if (typeof user !== 'object' || user === null) {
    return 'iam:GetUser did not return the user';
  }
  const record = user as { UserName?: unknown; Arn?: unknown; Path?: unknown };
  if (record.UserName !== userName || typeof record.Arn !== 'string' || typeof record.Path !== 'string') {
    return 'iam:GetUser did not return the user';
  }
  const principal = principalProblem(record.Arn) ?? principalProblem(record.Path);
  if (principal !== undefined) {
    return principal;
  }
  if (!record.Arn.includes(':user/') || !record.Arn.endsWith(`/${userName}`)) {
    return 'iam:GetUser did not return an IAM user';
  }
  return undefined;
}

async function readAttachedPolicies(
  client: AwsClient,
  userName: string,
): Promise<{ ok: true; admin: boolean } | { ok: false; failure: Failure }> {
  const policies: Array<{ PolicyName?: unknown; PolicyArn?: unknown }> = [];
  const seen = new Set<string>();
  let marker: string | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    if (marker !== undefined && seen.has(marker)) {
      return { ok: false, failure: refused('iam:ListAttachedUserPolicies did not advance') };
    }
    if (marker !== undefined) {
      seen.add(marker);
    }
    let response: unknown;
    try {
      response = await client.send(
        new ListAttachedUserPoliciesCommand(
          marker === undefined ? { UserName: userName } : { UserName: userName, Marker: marker },
        ),
      );
    } catch (err) {
      return { ok: false, failure: awsFailure(err) };
    }
    const parsed = readRecordPage(response, 'AttachedPolicies');
    if (parsed === undefined) {
      return { ok: false, failure: refused('iam:ListAttachedUserPolicies did not return a policy list') };
    }
    policies.push(...parsed.items);
    if (!parsed.truncated) {
      let admin = false;
      for (const policy of policies) {
        const verdict = isAdminPolicy(policy);
        if (verdict === 'bad') {
          return { ok: false, failure: refused('iam:ListAttachedUserPolicies returned a policy the handler cannot read') };
        }
        if (verdict) {
          admin = true;
        }
      }
      return { ok: true, admin };
    }
    if (parsed.marker === undefined) {
      return { ok: false, failure: refused('iam:ListAttachedUserPolicies was truncated without a marker') };
    }
    marker = parsed.marker;
  }
  return { ok: false, failure: refused('iam:ListAttachedUserPolicies returned too many pages') };
}

async function readGroups(
  client: AwsClient,
  userName: string,
): Promise<{ ok: true; admin: boolean } | { ok: false; failure: Failure }> {
  const groups: Array<{ GroupName?: unknown; Arn?: unknown; Path?: unknown }> = [];
  const seen = new Set<string>();
  let marker: string | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    if (marker !== undefined && seen.has(marker)) {
      return { ok: false, failure: refused('iam:ListGroupsForUser did not advance') };
    }
    if (marker !== undefined) {
      seen.add(marker);
    }
    let response: unknown;
    try {
      response = await client.send(
        new ListGroupsForUserCommand(
          marker === undefined ? { UserName: userName } : { UserName: userName, Marker: marker },
        ),
      );
    } catch (err) {
      return { ok: false, failure: awsFailure(err) };
    }
    const parsed = readRecordPage(response, 'Groups');
    if (parsed === undefined) {
      return { ok: false, failure: refused('iam:ListGroupsForUser did not return a group list') };
    }
    groups.push(...parsed.items);
    if (!parsed.truncated) {
      for (const group of groups) {
        if (typeof group.GroupName !== 'string') {
          return { ok: false, failure: refused('iam:ListGroupsForUser returned a group the handler cannot read') };
        }
        const arn = typeof group.Arn === 'string' ? group.Arn : '';
        const path = typeof group.Path === 'string' ? group.Path : '';
        if (principalProblem(arn) !== undefined || principalProblem(path) !== undefined) {
          return { ok: false, failure: refused('IAM principal matches a role, assumed role, or SSO principal') };
        }
      }
      return { ok: true, admin: groups.some((group) => ADMIN_GROUP_NAMES.has(String(group.GroupName))) };
    }
    if (parsed.marker === undefined) {
      return { ok: false, failure: refused('iam:ListGroupsForUser was truncated without a marker') };
    }
    marker = parsed.marker;
  }
  return { ok: false, failure: refused('iam:ListGroupsForUser returned too many pages') };
}

function isAdminPolicy(policy: { PolicyName?: unknown; PolicyArn?: unknown }): boolean | 'bad' {
  const name = policy.PolicyName;
  const arn = policy.PolicyArn;
  if (name !== undefined && typeof name !== 'string') {
    return 'bad';
  }
  if (arn !== undefined && typeof arn !== 'string') {
    return 'bad';
  }
  if (typeof name !== 'string' && typeof arn !== 'string') {
    return 'bad';
  }
  if (typeof name === 'string' && ADMIN_POLICY_NAMES.has(name)) {
    return true;
  }
  if (typeof arn === 'string' && (arn.endsWith('/AdministratorAccess') || arn.endsWith('/IAMFullAccess'))) {
    return true;
  }
  return false;
}

async function readContainmentPolicy(
  client: AwsClient,
  userName: string,
): Promise<{ ok: true; matches: boolean } | { ok: false; failure: Failure }> {
  let response: unknown;
  try {
    response = await client.send(
      new GetUserPolicyCommand({
        UserName: userName,
        PolicyName: POLICY_NAME,
      }),
    );
  } catch (err) {
    if (isMissingEntity(err)) {
      return { ok: true, matches: false };
    }
    return { ok: false, failure: awsFailure(err) };
  }
  if (typeof response !== 'object' || response === null) {
    return { ok: false, failure: refused('iam:GetUserPolicy did not return a policy document') };
  }
  const raw = (response as { PolicyDocument?: unknown }).PolicyDocument;
  if (typeof raw !== 'string') {
    return { ok: false, failure: refused('iam:GetUserPolicy did not return a policy document') };
  }
  return { ok: true, matches: documentMatches(raw) };
}

/**
 * GetUserPolicy returns the document URL-encoded. Decode it only to compare
 * it with the constant. A document that does not parse is not a match.
 */
function documentMatches(raw: string): boolean {
  const parsed = parseDocument(raw);
  return parsed !== undefined && isExactDeny(parsed);
}

function parseDocument(raw: string): unknown | undefined {
  const direct = tryParse(raw);
  if (direct !== undefined) {
    return direct;
  }
  try {
    return tryParse(decodeURIComponent(raw));
  } catch {
    return undefined;
  }
}

function tryParse(raw: string): unknown | undefined {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function isExactDeny(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 2 || record.Version !== '2012-10-17' || !Array.isArray(record.Statement)) {
    return false;
  }
  if (record.Statement.length !== 1) {
    return false;
  }
  const statement = record.Statement[0];
  if (typeof statement !== 'object' || statement === null) {
    return false;
  }
  const fields = statement as Record<string, unknown>;
  return (
    Object.keys(fields).length === 3 &&
    fields.Effect === 'Deny' &&
    isStar(fields.Action) &&
    isStar(fields.Resource)
  );
}

function isStar(value: unknown): boolean {
  if (value === '*') {
    return true;
  }
  return Array.isArray(value) && value.length === 1 && value[0] === '*';
}

function readTagPage(payload: unknown): Page<Tag> | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return undefined;
  }
  const record = payload as Record<string, unknown>;
  const tags = readObjects(record.Tags);
  if (tags === undefined) {
    return undefined;
  }
  const page = readTruncation(record);
  if (page === undefined) {
    return undefined;
  }
  return { items: tags, ...page };
}

function readRecordPage(payload: unknown, field: 'AttachedPolicies' | 'Groups'): Page<Record<string, unknown>> | undefined {
  if (typeof payload !== 'object' || payload === null) {
    return undefined;
  }
  const record = payload as Record<string, unknown>;
  const items = readObjects(record[field]);
  if (items === undefined) {
    return undefined;
  }
  const page = readTruncation(record);
  if (page === undefined) {
    return undefined;
  }
  return { items, ...page };
}

function readObjects(value: unknown): Record<string, unknown>[] | undefined {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    return undefined;
  }
  const items: Record<string, unknown>[] = [];
  for (const item of value) {
    if (typeof item !== 'object' || item === null) {
      return undefined;
    }
    items.push(item as Record<string, unknown>);
  }
  return items;
}

function readTruncation(record: Record<string, unknown>): { truncated: boolean; marker: string | undefined } | undefined {
  const truncated = record.IsTruncated;
  if (truncated === undefined || truncated === false) {
    return { truncated: false, marker: undefined };
  }
  if (truncated !== true) {
    return undefined;
  }
  const marker = record.Marker;
  if (typeof marker !== 'string' || marker.length === 0) {
    return { truncated: true, marker: undefined };
  }
  return { truncated: true, marker };
}

function isMissingEntity(err: unknown): boolean {
  const { errorCode } = readAwsError(err);
  return errorCode === 'NoSuchEntity' || errorCode === 'NoSuchEntityException';
}

function awsFailure(err: unknown): AwsFailure {
  return { ok: false, changed: false, ...readAwsError(err) };
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
