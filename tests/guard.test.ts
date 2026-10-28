/**
 * The guard fails closed.
 * The real tree must pass. In-memory cases show what a bad change looks like.
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ALLOWED_FIXES } from '../src/fixes/allow-list.js';
import { FIX_REGISTRY } from '../src/fixes/registry.js';
import { audit, type AuditInput, type FixFolder, type SourceFile } from '../src/guard/audit.js';
import { CLOSE_ONLY_ACTIONS } from '../src/guard/mutating-apis.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function markers(): string[] {
  const host = 'api.' + 'x.ai';
  return ['https://' + host, host, 'chat' + '/completions', 'XAI_' + 'API_KEY', 'XAI_' + 'MODEL'];
}

function walk(dir: string): SourceFile[] {
  const out: SourceFile[] = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...walk(full));
      continue;
    }
    if (name.endsWith('.ts')) {
      out.push({
        path: path.relative(root, full).split(path.sep).join('/'),
        text: readFileSync(full, 'utf8'),
      });
    }
  }
  return out;
}

function readOptional(file: string): string | null {
  return existsSync(file) ? readFileSync(file, 'utf8') : null;
}

function loadFixes(): FixFolder[] {
  const dir = path.join(root, 'src/fixes');
  const fixes: FixFolder[] = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (!statSync(full).isDirectory()) {
      continue;
    }
    fixes.push({
      name,
      handlerText: readOptional(path.join(full, 'handler.ts')),
      policyText: readOptional(path.join(full, 'policy.json')),
      metadataText: readOptional(path.join(full, 'fix.json')),
      hasTest: existsSync(path.join(root, 'tests/fixes', `${name}.test.ts`)),
    });
  }
  return fixes;
}

function repoInput(over: Partial<AuditInput> = {}): AuditInput {
  return {
    files: [...walk(path.join(root, 'src')), ...walk(path.join(root, 'tests'))],
    fixes: loadFixes(),
    allowList: ALLOWED_FIXES,
    registry: FIX_REGISTRY,
    closeOnlyActions: CLOSE_ONLY_ACTIONS,
    xaiMarkers: markers(),
    grokClientPath: 'src/grok/client.ts',
    xaiAllowedPaths: ['src/grok/client.ts', 'tests/grok/client.test.ts'],
    terraform: {
      mainText: readFileSync(path.join(root, 'infra/main.tf'), 'utf8'),
      moduleText: readFileSync(path.join(root, 'infra/modules/fix/main.tf'), 'utf8'),
    },
    ...over,
  };
}

const HANDLER = [
  "const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';",
  "const AUTO_REMEDIATE_TAG_VALUE = 'true';",
  'function hasAutoRemediateTag(tags: { Key?: string; Value?: string }[]) {',
  '  return tags.some((tag) => tag.Key === AUTO_REMEDIATE_TAG_KEY && tag.Value === AUTO_REMEDIATE_TAG_VALUE);',
  '}',
  'new DescribeSecurityGroupRulesCommand({})',
  'if (!hasAutoRemediateTag(tags)) {',
  '  return { ok: false };',
  '}',
  'new RevokeSecurityGroupIngressCommand({})',
].join('\n');

function policy(statements: Array<{ action: string; resource: string }>): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: statements.map((statement) => ({
      Effect: 'Allow',
      Action: [statement.action],
      Resource: statement.resource,
    })),
  });
}

const GOOD_POLICY = policy([
  { action: 'ec2:DescribeSecurityGroupRules', resource: '*' },
  { action: 'ec2:RevokeSecurityGroupIngress', resource: 'arn:aws:ec2:*:*:security-group/*' },
]);

function metadata(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    name: 'close-open-port',
    findingKey: 'cloud:open_port',
    action: 'ec2:RevokeSecurityGroupIngress',
    description: 'Revoke one ingress rule on one security group',
    callsGrok: false,
    ...over,
  });
}

function folder(over: Partial<FixFolder> = {}): FixFolder {
  return {
    name: 'close-open-port',
    handlerText: HANDLER,
    policyText: GOOD_POLICY,
    metadataText: metadata(),
    hasTest: true,
    ...over,
  };
}

describe('guard', () => {
  it('lists the fixes we are willing to automate', () => {
    expect(ALLOWED_FIXES['close-open-port']).toEqual({
      findingKey: 'cloud:open_port',
      action: 'ec2:RevokeSecurityGroupIngress',
      summary: 'Revoke one ingress rule on one security group',
      undo: 'Authorize that same ingress rule again',
    });
    for (const entry of Object.values(ALLOWED_FIXES)) {
      expect(entry.findingKey).toMatch(/^[a-z0-9_]+:[a-z0-9_]+$/);
      expect(entry.action).toMatch(/^[a-z0-9]+:[A-Za-z0-9]+$/);
      expect(entry.summary.length).toBeGreaterThan(0);
      expect(entry.undo.length).toBeGreaterThan(0);
    }
    expect(CLOSE_ONLY_ACTIONS).toContain('ec2:RevokeSecurityGroupIngress');
    expect(CLOSE_ONLY_ACTIONS).toContain('s3:PutBucketPublicAccessBlock');
  });

  it('passes on this repo', () => {
    expect(audit(repoInput())).toEqual([]);
  });

  it('fails when a fix folder is not on the allow-list', () => {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [
        folder({
          name: 'delete-bucket',
          metadataText: metadata({ name: 'delete-bucket', findingKey: 'cloud:delete_bucket' }),
        }),
      ],
    });

    expect(failures.map((failure) => failure.message)).toContain('fix delete-bucket is not on the allow-list');
  });

  it('fails when handler, policy, metadata, or tests are missing', () => {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [folder({ handlerText: null, policyText: null, metadataText: null, hasTest: false })],
    });
    const messages = failures.map((failure) => failure.message);

    expect(messages).toContain('fix close-open-port is missing handler.ts');
    expect(messages).toContain('fix close-open-port is missing policy.json');
    expect(messages).toContain('fix close-open-port is missing fix.json');
    expect(messages).toContain('fix close-open-port is missing tests');
  });

  it.each([
    ['ec2:AuthorizeSecurityGroupIngress'],
    ['iam:PassRole'],
    ['s3:PutBucketPolicy'],
    ['s3:DeleteBucketPublicAccessBlock'],
  ])('blocks %s even if someone adds it to the close-only list', (action) => {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      closeOnlyActions: [...CLOSE_ONLY_ACTIONS, action],
      fixes: [
        folder({
          policyText: policy([
            { action: 'ec2:DescribeSecurityGroupRules', resource: '*' },
            { action, resource: 'arn:aws:ec2:*:*:security-group/*' },
          ]),
          handlerText: HANDLER,
        }),
      ],
    });

    expect(failures.some((failure) => failure.message === `blocked action ${action}`)).toBe(true);
  });

  it('blocks a wildcard action', () => {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [
        folder({
          policyText: policy([
            { action: 'ec2:DescribeSecurityGroupRules', resource: '*' },
            { action: 'ec2:*', resource: '*' },
          ]),
        }),
      ],
    });

    expect(failures.some((failure) => failure.message.includes('wildcard action'))).toBe(true);
  });

  it('rejects Resource * on a mutating action unless metadata justifies it', () => {
    const open = policy([
      { action: 'ec2:DescribeSecurityGroupRules', resource: '*' },
      { action: 'ec2:RevokeSecurityGroupIngress', resource: '*' },
    ]);
    const denied = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [folder({ policyText: open })],
    });
    expect(denied.some((failure) => failure.message.includes('Resource * without justification'))).toBe(true);

    const allowed = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [
        folder({
          policyText: open,
          metadataText: metadata({
            wildcardResourceJustification: 'IAM cannot scope this action to one resource.',
          }),
        }),
      ],
    });
    expect(allowed.some((failure) => failure.message.includes('Resource *'))).toBe(false);
  });

  it('fails when the handler calls an operation the policy does not list', () => {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [
        folder({
          handlerText: `${HANDLER}\nnew DeleteSecurityGroupCommand({})`,
        }),
      ],
    });
    const messages = failures.map((failure) => failure.message);

    expect(messages.some((message) => message.includes('DeleteSecurityGroup'))).toBe(true);
    expect(messages.some((message) => message.includes('close calls'))).toBe(true);
  });

  it('fails when a fix folder has no Terraform entry', () => {
    const failures = audit({
      ...repoInput(),
      terraform: {
        mainText: 'locals { fix_names = toset([]) }',
        moduleText: 'permissions_boundary = var.permissions_boundary_arn',
      },
    });

    expect(failures.map((failure) => failure.message)).toContain(
      'fix close-open-port has no Terraform entry',
    );
  });

  it('fails when the module omits the permissions boundary', () => {
    const mainText = readFileSync(path.join(root, 'infra/main.tf'), 'utf8');
    const failures = audit({
      ...repoInput(),
      terraform: { mainText, moduleText: 'resource "aws_iam_role" "fix" {}' },
    });

    expect(failures.map((failure) => failure.message)).toContain(
      'fix module does not set permissions_boundary',
    );
  });

  it('passes when an allow-listed handler checks the auto-remediate tag before the close', () => {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [folder()],
    });

    expect(failures.filter((failure) => failure.message.includes('hasAutoRemediateTag'))).toEqual([]);
    expect(failures.filter((failure) => failure.message.includes('AUTO_REMEDIATE_TAG'))).toEqual([]);
    expect(failures.filter((failure) => failure.message.includes('intended-public'))).toEqual([]);
  });

  it('fails when an allow-listed handler does not call hasAutoRemediateTag', () => {
    const handlerText = [
      "const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';",
      "const AUTO_REMEDIATE_TAG_VALUE = 'true';",
      'function hasAutoRemediateTag(tags: { Key?: string; Value?: string }[]) {',
      '  return false;',
      '}',
      'new DescribeSecurityGroupRulesCommand({})',
      'new RevokeSecurityGroupIngressCommand({})',
    ].join('\n');
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [folder({ handlerText })],
    });

    expect(failures.map((failure) => failure.message)).toContain(
      'fix close-open-port does not call hasAutoRemediateTag( before its mutating send',
    );
  });

  it('fails when an allow-listed handler checks the auto-remediate tag after the close', () => {
    const handlerText = [
      "const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';",
      "const AUTO_REMEDIATE_TAG_VALUE = 'true';",
      'function hasAutoRemediateTag(tags: { Key?: string; Value?: string }[]) {',
      '  return false;',
      '}',
      'new DescribeSecurityGroupRulesCommand({})',
      'new RevokeSecurityGroupIngressCommand({})',
      'hasAutoRemediateTag(tags)',
    ].join('\n');
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [folder({ handlerText })],
    });
    const messages = failures.map((failure) => failure.message);

    expect(messages).toContain('fix close-open-port calls hasAutoRemediateTag( after its mutating send');
    expect(messages).not.toContain(
      'fix close-open-port does not call hasAutoRemediateTag( before its mutating send',
    );
  });

  function publicAccessHandler(body: string): string {
    return [
      "const AUTO_REMEDIATE_TAG_KEY = 'auto-remediate';",
      "const AUTO_REMEDIATE_TAG_VALUE = 'true';",
      "const INTENDED_PUBLIC_TAG_KEY = 'intended-public';",
      "const INTENDED_PUBLIC_TAG_VALUE = 'true';",
      'function hasAutoRemediateTag(tags: { Key?: string; Value?: string }[]) {',
      '  return false;',
      '}',
      'function hasIntendedPublicTag(tags: { Key?: string; Value?: string }[]) {',
      '  return false;',
      '}',
      'new GetBucketTaggingCommand({})',
      'if (!hasAutoRemediateTag(tags)) {',
      '  return { ok: false };',
      '}',
      body,
      'new PutBucketPublicAccessBlockCommand({})',
    ].join('\n');
  }

  function intendedPublicMessages(handlerText: string, name: string): string[] {
    const failures = audit({
      ...repoInput(),
      terraform: undefined,
      fixes: [folder({ name, handlerText })],
    });
    return failures.map((failure) => failure.message).filter((message) => message.includes('intended-public'));
  }

  it('passes when remove-bucket-public-access-block requires intended-public before the send', () => {
    const handlerText = publicAccessHandler(
      ['if (!hasIntendedPublicTag(tags)) {', '  return { ok: false };', '}'].join('\n'),
    );

    expect(intendedPublicMessages(handlerText, 'remove-bucket-public-access-block')).toEqual([]);
  });

  it('passes when restore-bucket-public-access-block requires intended-public to be absent before the send', () => {
    const handlerText = publicAccessHandler(
      ['if (hasIntendedPublicTag(tags)) {', '  return { ok: false };', '}'].join('\n'),
    );

    expect(intendedPublicMessages(handlerText, 'restore-bucket-public-access-block')).toEqual([]);
  });

  it('fails when remove-bucket-public-access-block does not require intended-public to be present', () => {
    const missing = publicAccessHandler('const ready = true;');
    const wrongWay = publicAccessHandler(
      ['if (hasIntendedPublicTag(tags)) {', '  return { ok: false };', '}'].join('\n'),
    );

    expect(intendedPublicMessages(missing, 'remove-bucket-public-access-block')).toContain(
      'fix remove-bucket-public-access-block does not require intended-public to be present before its mutating send',
    );
    expect(intendedPublicMessages(wrongWay, 'remove-bucket-public-access-block')).toContain(
      'fix remove-bucket-public-access-block does not require intended-public to be present before its mutating send',
    );
  });

  it('fails when remove-bucket-public-access-block checks intended-public after the send', () => {
    const handlerText = [
      publicAccessHandler('const ready = true;'),
      'if (!hasIntendedPublicTag(tags)) {',
      '  return { ok: false };',
      '}',
    ].join('\n');

    const messages = intendedPublicMessages(handlerText, 'remove-bucket-public-access-block');
    expect(messages).toContain(
      'fix remove-bucket-public-access-block checks intended-public after its mutating send',
    );
    expect(messages).not.toContain(
      'fix remove-bucket-public-access-block does not require intended-public to be present before its mutating send',
    );
  });

  it('fails when restore-bucket-public-access-block does not require intended-public to be absent', () => {
    const missing = publicAccessHandler('const ready = true;');
    const wrongWay = publicAccessHandler(
      ['if (!hasIntendedPublicTag(tags)) {', '  return { ok: false };', '}'].join('\n'),
    );

    expect(intendedPublicMessages(missing, 'restore-bucket-public-access-block')).toContain(
      'fix restore-bucket-public-access-block does not require intended-public to be absent before its mutating send',
    );
    expect(intendedPublicMessages(wrongWay, 'restore-bucket-public-access-block')).toContain(
      'fix restore-bucket-public-access-block does not require intended-public to be absent before its mutating send',
    );
  });

  it('fails when restore-bucket-public-access-block checks intended-public after the send', () => {
    const handlerText = [
      publicAccessHandler('const ready = true;'),
      'if (hasIntendedPublicTag(tags)) {',
      '  return { ok: false };',
      '}',
    ].join('\n');

    const messages = intendedPublicMessages(handlerText, 'restore-bucket-public-access-block');
    expect(messages).toContain(
      'fix restore-bucket-public-access-block checks intended-public after its mutating send',
    );
    expect(messages).not.toContain(
      'fix restore-bucket-public-access-block does not require intended-public to be absent before its mutating send',
    );
  });

  it('fails when a bucket public access block fix declares the wrong intended-public key', () => {
    const handlerText = publicAccessHandler(
      ['if (!hasIntendedPublicTag(tags)) {', '  return { ok: false };', '}'].join('\n'),
    ).replace("const INTENDED_PUBLIC_TAG_KEY = 'intended-public';", "const INTENDED_PUBLIC_TAG_KEY = 'Intended-Public';");

    expect(intendedPublicMessages(handlerText, 'remove-bucket-public-access-block')).toContain(
      "fix remove-bucket-public-access-block does not declare const INTENDED_PUBLIC_TAG_KEY = 'intended-public'",
    );
  });

  it('fails when an xAI call sits outside the Grok client', () => {
    const endpoint = markers()[0] ?? '';
    const failures = audit({
      ...repoInput(),
      files: [{ path: 'src/extractors/advisory/read.ts', text: `const url = '${endpoint}';\n` }],
    });

    expect(failures.some((failure) => failure.path === 'src/extractors/advisory/read.ts')).toBe(true);
  });

  it('rejects an em dash in docs and code', () => {
    const banned = [String.fromCodePoint(0x2014), String.fromCodePoint(0x2013)];
    const hits: string[] = [];

    function scan(dir: string): void {
      for (const name of readdirSync(dir)) {
        if (name === 'node_modules' || name === '.git' || name === 'dist' || name === '.terraform') {
          continue;
        }
        const full = path.join(dir, name);
        if (statSync(full).isDirectory()) {
          scan(full);
          continue;
        }
        const text = readFileSync(full, 'utf8');
        for (const mark of banned) {
          if (text.includes(mark)) {
            hits.push(path.relative(root, full));
          }
        }
      }
    }

    scan(root);
    expect(hits).toEqual([]);
  });

  it('ships project rules and always applies the core rule', () => {
    const dir = path.join(root, '.cursor/rules');
    const names = ['core.mdc', 'fixes.mdc', 'grok.mdc', 'protected.mdc'];
    for (const name of names) {
      const text = readFileSync(path.join(dir, name), 'utf8');
      expect(text.startsWith('---\n')).toBe(true);
      expect(text).toContain('\n---\n');
    }
    const core = readFileSync(path.join(dir, 'core.mdc'), 'utf8');
    const front = core.split('\n---\n')[0] ?? '';
    expect(front).toMatch(/alwaysApply:\s*true/);
    for (const name of names.slice(1)) {
      const text = readFileSync(path.join(dir, name), 'utf8');
      expect(text.split('\n---\n')[0] ?? '').toMatch(/alwaysApply:\s*false/);
    }
  });
});
