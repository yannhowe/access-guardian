/**
 * The permissions boundary is bootstrap/boundary.json.
 * This test parses that file. It does not call AWS.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const USER_ACTIONS = [
  'iam:GetUser',
  'iam:ListUserTags',
  'iam:GetUserPolicy',
  'iam:ListAttachedUserPolicies',
  'iam:ListGroupsForUser',
  'iam:PutUserPolicy',
] as const;

const STILL_DENIED = [
  'iam:PassRole',
  'iam:CreateAccessKey',
  'iam:AttachUserPolicy',
  'iam:PutRolePolicy',
  'iam:DeleteUser',
  'iam:CreateUser',
  'iam:DeleteUserPolicy',
] as const;

const USER = 'arn:aws:iam::*:user/*';
const USER_ARN = 'arn:aws:iam::*:user/demo-user';
const ROLE_ARN = 'arn:aws:iam::*:role/demo-role';
const GROUP_ARN = 'arn:aws:iam::*:group/demo-group';
const POLICY_ARN = 'arn:aws:iam::*:policy/demo-policy';
const OTHER_RESOURCES = [ROLE_ARN, GROUP_ARN, POLICY_ARN, '*'] as const;

type Statement = {
  Sid?: string;
  Effect?: string;
  Action?: string | string[];
  NotAction?: string | string[];
  Resource?: string | string[];
  NotResource?: string | string[];
};

function strings(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  return typeof value === 'string' ? [value] : value;
}

function wildcardMatch(pattern: string, value: string): boolean {
  let source = '^';
  for (const char of pattern) {
    if (char === '*') {
      source += '.*';
    } else if ('\\^$+?.()|[]{}'.includes(char)) {
      source += `\\${char}`;
    } else {
      source += char;
    }
  }
  source += '$';
  return new RegExp(source).test(value);
}

function matchesAny(patterns: readonly string[], value: string): boolean {
  return patterns.some((pattern) => wildcardMatch(pattern, value));
}

function actionApplies(statement: Statement, action: string): boolean {
  const actions = strings(statement.Action);
  const notActions = strings(statement.NotAction);
  if (actions !== undefined && notActions !== undefined) {
    return false;
  }
  if (actions !== undefined) {
    return matchesAny(actions, action);
  }
  if (notActions !== undefined) {
    return !matchesAny(notActions, action);
  }
  return false;
}

function resourceApplies(statement: Statement, resource: string): boolean {
  const resources = strings(statement.Resource);
  const notResources = strings(statement.NotResource);
  if (resources !== undefined && notResources !== undefined) {
    return false;
  }
  if (resources !== undefined) {
    return matchesAny(resources, resource);
  }
  if (notResources !== undefined) {
    return !matchesAny(notResources, resource);
  }
  return false;
}

function applies(statement: Statement, action: string, resource: string): boolean {
  return actionApplies(statement, action) && resourceApplies(statement, resource);
}

function loadBoundary(): Statement[] {
  const file = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../bootstrap/boundary.json',
  );
  const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
  if (typeof parsed !== 'object' || parsed === null || !('Statement' in parsed)) {
    throw new Error('boundary is missing Statement');
  }
  const statements = (parsed as { Statement?: unknown }).Statement;
  if (!Array.isArray(statements)) {
    throw new Error('boundary Statement is not a list');
  }
  return statements as Statement[];
}

function allows(statements: readonly Statement[], action: string, resource: string): boolean {
  const denied = statements.some(
    (statement) => statement.Effect === 'Deny' && applies(statement, action, resource),
  );
  if (denied) {
    return false;
  }
  return statements.some(
    (statement) => statement.Effect === 'Allow' && applies(statement, action, resource),
  );
}

function denied(statements: readonly Statement[], action: string, resource: string): boolean {
  return statements.some(
    (statement) => statement.Effect === 'Deny' && applies(statement, action, resource),
  );
}

describe('ag-fix-boundary', () => {
  const statements = loadBoundary();
  const allowsIam = statements.filter((statement) => {
    if (statement.Effect !== 'Allow') {
      return false;
    }
    const actions = strings(statement.Action) ?? [];
    return actions.some((action) => action === '*' || action.startsWith('iam:') || action.startsWith('*:') || action.includes('iam:'));
  });

  it('allows only the six IAM user actions, and only on users', () => {
    expect(allowsIam).toHaveLength(1);
    const statement = allowsIam[0];
    expect(strings(statement?.Action)).toEqual([...USER_ACTIONS]);
    expect(strings(statement?.Resource)).toEqual([USER]);
    expect(statement?.NotAction).toBeUndefined();
    expect(statement?.NotResource).toBeUndefined();

    for (const action of USER_ACTIONS) {
      expect(allows(statements, action, USER_ARN)).toBe(true);
      for (const resource of OTHER_RESOURCES) {
        expect(allows(statements, action, resource)).toBe(false);
      }
    }
  });

  it('has no wildcard IAM allow', () => {
    for (const statement of statements) {
      if (statement.Effect !== 'Allow') {
        continue;
      }
      expect(statement.NotAction).toBeUndefined();
      for (const action of strings(statement.Action) ?? []) {
        expect(action).not.toContain('*');
        expect(action).not.toBe('iam:*');
        if (action.startsWith('iam:')) {
          expect(USER_ACTIONS).toContain(action);
        }
      }
    }
  });

  it('keeps every other IAM action denied, including on roles, groups, and policies', () => {
    const userDeny = statements.find((statement) => statement.Sid === 'DenyIamOnUsersExceptContainment');
    expect(strings(userDeny?.NotAction)).toEqual([...USER_ACTIONS]);
    expect(strings(userDeny?.Resource)).toEqual([USER]);
    expect(userDeny?.Effect).toBe('Deny');
    expect(userDeny?.Action).toBeUndefined();

    const offUser = statements.find((statement) => statement.Sid === 'DenyIamOffUsers');
    expect(offUser?.Effect).toBe('Deny');
    expect(strings(offUser?.Action)).toEqual(['iam:*']);
    expect(strings(offUser?.NotResource)).toEqual([USER]);
    expect(offUser?.NotAction).toBeUndefined();

    const resources = [USER_ARN, ...OTHER_RESOURCES];
    for (const action of STILL_DENIED) {
      for (const resource of resources) {
        expect(denied(statements, action, resource)).toBe(true);
        expect(allows(statements, action, resource)).toBe(false);
      }
    }

    for (const action of USER_ACTIONS) {
      expect(denied(statements, action, USER_ARN)).toBe(false);
      for (const resource of OTHER_RESOURCES) {
        expect(denied(statements, action, resource)).toBe(true);
      }
    }
  });

  it('does not widen the other allows, and still denies s3:PutBucketPolicy', () => {
    expect(allows(statements, 'ec2:DescribeSecurityGroups', '*')).toBe(true);
    expect(allows(statements, 'ec2:DescribeSecurityGroupRules', '*')).toBe(true);
    expect(allows(statements, 'ec2:RevokeSecurityGroupIngress', 'arn:aws:ec2:*:*:security-group/sg-demo0001')).toBe(true);
    expect(allows(statements, 'ec2:RevokeSecurityGroupIngress', '*')).toBe(false);
    expect(allows(statements, 'ec2:AuthorizeSecurityGroupIngress', 'arn:aws:ec2:*:*:security-group/sg-demo0001')).toBe(false);

    const bucket = 'arn:aws:s3:::ag-demo-public-10281729';
    expect(allows(statements, 's3:GetBucketTagging', bucket)).toBe(true);
    expect(allows(statements, 's3:GetBucketPublicAccessBlock', bucket)).toBe(true);
    expect(allows(statements, 's3:PutBucketPublicAccessBlock', bucket)).toBe(true);
    expect(allows(statements, 's3:PutBucketPublicAccessBlock', 'arn:aws:s3:::other-bucket')).toBe(false);
    expect(denied(statements, 's3:PutBucketPublicAccessBlock', bucket)).toBe(false);
    expect(allows(statements, 's3:DeleteBucketPublicAccessBlock', bucket)).toBe(false);

    const stream = 'arn:aws:logs:*:*:log-group:/aws/lambda/ag-fix-contain-iam-user:stream';
    expect(allows(statements, 'logs:CreateLogStream', stream)).toBe(true);
    expect(allows(statements, 'logs:PutLogEvents', stream)).toBe(true);
    expect(allows(statements, 'logs:PutLogEvents', 'arn:aws:logs:*:*:log-group:/aws/lambda/other:stream')).toBe(false);

    const putPolicy = statements.find((statement) => statement.Sid === 'DenyNonIamPutPolicy');
    expect(putPolicy?.Effect).toBe('Deny');
    expect(strings(putPolicy?.Action)).toContain('s3:PutBucketPolicy');
    expect(strings(putPolicy?.Action)).not.toContain('iam:PutUserPolicy');
    expect(strings(putPolicy?.Action)).not.toContain('s3:PutBucketPublicAccessBlock');
    expect(denied(statements, 's3:PutBucketPolicy', bucket)).toBe(true);
    expect(denied(statements, 's3:PutBucketPolicy', '*')).toBe(true);
    expect(allows(statements, 's3:PutBucketPolicy', bucket)).toBe(false);
  });
});
