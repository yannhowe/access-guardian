/**
 * The guard fails closed.
 * The real tree must pass. The in-memory cases show what a bad change looks like.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ALLOWED_FIXES } from '../src/fixes/allow-list.js';
import { audit, type AuditRules, type SourceFile } from '../src/guard/audit.js';
import { MUTATING_APIS } from '../src/guard/mutating-apis.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function markers(): string[] {
  const host = 'api.' + 'x.ai';
  return ['https://' + host, host, 'chat' + '/completions', 'XAI_' + 'API_KEY', 'XAI_' + 'MODEL'];
}

function rules(over: Partial<AuditRules> = {}): AuditRules {
  return {
    allowList: ALLOWED_FIXES,
    mutatingApis: MUTATING_APIS,
    xaiMarkers: markers(),
    grokClientPath: 'src/grok/client.ts',
    xaiAllowedPaths: ['src/grok/client.ts', 'tests/grok/client.test.ts'],
    catalogPath: 'src/guard/mutating-apis.ts',
    ...over,
  };
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

function repoFiles(): SourceFile[] {
  return [...walk(path.join(root, 'src')), ...walk(path.join(root, 'tests'))];
}

describe('guard', () => {
  it('lists the fixes we are willing to automate', () => {
    expect(ALLOWED_FIXES).toEqual({
      'close-open-port': {
        action: 'RevokeSecurityGroupIngress',
        summary: 'Revoke one ingress rule on one security group',
        undo: 'Authorize that same ingress rule again',
      },
    });
  });

  it('passes on this repo', () => {
    expect(audit(repoFiles(), rules())).toEqual([]);
  });

  it('fails when a fix is not on the allow-list', () => {
    const files: SourceFile[] = [
      {
        path: 'src/fixes/delete-bucket.ts',
        text: "export const ACTION = 'DeleteBucket' as const;\nawait client.send(command);\n",
      },
    ];

    const failures = audit(files, rules());

    expect(failures.map((failure) => failure.message)).toContain('fix delete-bucket is not on the allow-list');
  });

  it('fails when a fix declares two actions', () => {
    const files: SourceFile[] = [
      {
        path: 'src/fixes/close-open-port.ts',
        text: [
          "export const ACTION = 'RevokeSecurityGroupIngress' as const;",
          "export const ACTION = 'AuthorizeSecurityGroupIngress' as const;",
          'await client.send(command);',
        ].join('\n'),
      },
    ];

    const messages = audit(files, rules()).map((failure) => failure.message);

    expect(messages).toContain('fix close-open-port declares 2 actions');
    expect(messages.some((message) => message.includes('more than one action'))).toBe(true);
  });

  it('fails when an xAI call sits outside the Grok client', () => {
    const endpoint = markers()[0] ?? '';
    const chat = 'chat' + '/completions';
    const files: SourceFile[] = [
      {
        path: 'src/extractors/advisory/read.ts',
        text: `await fetch('${endpoint}/v1/${chat}');\n`,
      },
    ];

    const failures = audit(files, rules());

    expect(failures.length).toBeGreaterThan(0);
    expect(failures.every((failure) => failure.path === 'src/extractors/advisory/read.ts')).toBe(true);
  });

  it('allows the Grok client to name the endpoint', () => {
    const chat = 'chat' + '/completions';
    const keyName = 'XAI_' + 'API_KEY';
    const modelName = 'XAI_' + 'MODEL';
    const files: SourceFile[] = [
      {
        path: 'src/grok/client.ts',
        text: `const url = '${markers()[0]}/v1/${chat}';\nprocess.env.${keyName};\nprocess.env.${modelName};\n`,
      },
    ];

    expect(audit(files, rules())).toEqual([]);
  });

  it('fails when a mutating command is not on the allow-list', () => {
    const files: SourceFile[] = [
      {
        path: 'src/fixes/close-open-port.ts',
        text: [
          "export const ACTION = 'RevokeSecurityGroupIngress' as const;",
          'RevokeSecurityGroupIngress',
          'await client.send(command);',
          'new ' + 'DeleteSecurityGroupCommand({})',
        ].join('\n'),
      },
    ];

    const messages = audit(files, rules()).map((failure) => failure.message);

    expect(messages.some((message) => message.includes('DeleteSecurityGroupCommand'))).toBe(true);
  });

  it('allows a Describe command', () => {
    const files: SourceFile[] = [
      {
        path: 'src/fixes/close-open-port.ts',
        text: [
          "export const ACTION = 'RevokeSecurityGroupIngress' as const;",
          'RevokeSecurityGroupIngress',
          'await client.send(command);',
          'new ' + 'DescribeSecurityGroupsCommand({})',
        ].join('\n'),
      },
    ];

    expect(audit(files, rules())).toEqual([]);
  });

  it('fails when a Grok call does not say what it decides', () => {
    const files: SourceFile[] = [
      {
        path: 'src/extractors/advisory/read.ts',
        text: 'const result = await extract(opts);\n',
      },
    ];

    const messages = audit(files, rules()).map((failure) => failure.message);

    expect(messages).toContain('Grok call is missing a "What Grok decides:" note');
    expect(messages).toContain('Grok call is missing a "What code decides:" note');
  });

  it('rejects an em dash in docs and code', () => {
    const banned = [String.fromCodePoint(0x2014), String.fromCodePoint(0x2013)];
    const hits: string[] = [];

    function scan(dir: string): void {
      for (const name of readdirSync(dir)) {
        if (name === 'node_modules' || name === '.git') {
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
});
