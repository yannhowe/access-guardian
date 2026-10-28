/**
 * The protected-path check is a pure function. These tests do not call GitHub.
 */
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { evaluate, isProtectedPath } from '../scripts/check-protected-paths.mjs';

const script = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../scripts/check-protected-paths.mjs',
);

describe('protected paths', () => {
  it('allows a new fix folder and its Terraform name', () => {
    const files = [
      'src/fixes/close-public-bucket/handler.ts',
      'src/fixes/close-public-bucket/policy.json',
      'src/fixes/close-public-bucket/fix.json',
      'tests/fixes/close-public-bucket.test.ts',
      'infra/main.tf',
    ];
    expect(evaluate(files, false)).toEqual({ ok: true, hits: [] });
  });

  it.each([
    'src/guard/audit.ts',
    'src/guard/mutating-apis.ts',
    'tests/guard.test.ts',
    'tests/guard/extra.test.ts',
    'infra/modules/fix/main.tf',
    '.github/workflows/terraform-plan.yml',
    '.github/CODEOWNERS',
    'src/fixes/allow-list.ts',
    '.cursor/skills/writing-remediators/SKILL.md',
  ])('blocks %s until the guard-change label is set', (file) => {
    expect(isProtectedPath(file)).toBe(true);
    expect(evaluate([file, 'src/fixes/close-public-bucket/handler.ts'], false).ok).toBe(false);
    expect(evaluate([file], true)).toEqual({ ok: true, hits: [file] });
  });

  it('does not treat a nearby path as protected', () => {
    expect(isProtectedPath('tests/workflows.test.ts')).toBe(false);
    expect(isProtectedPath('infra/main.tf')).toBe(false);
    expect(isProtectedPath('src/fixes/registry.ts')).toBe(false);
    expect(isProtectedPath('src/fixes/close-open-port/handler.ts')).toBe(false);
  });

  it('exits 0 or 1 from the script without calling git', () => {
    const pass = execFileSync(process.execPath, [script], {
      env: { ...process.env, CHANGED_FILES: 'infra/main.tf\n', HAS_GUARD_LABEL: 'false' },
      encoding: 'utf8',
    });
    expect(pass).toContain('No protected paths changed.');

    expect(() =>
      execFileSync(process.execPath, [script], {
        env: {
          ...process.env,
          CHANGED_FILES: 'src/guard/audit.ts\n',
          HAS_GUARD_LABEL: 'false',
        },
        encoding: 'utf8',
        stdio: 'pipe',
      }),
    ).toThrow();
  });
});
