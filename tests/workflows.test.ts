/**
 * The Terraform workflows stay pointed at repo variables, not hardcoded accounts.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function read(relative: string): string {
  return readFileSync(path.join(root, relative), 'utf8');
}

describe('terraform workflows', () => {
  const plan = read('.github/workflows/terraform-plan.yml');
  const apply = read('.github/workflows/terraform-apply.yml');

  it('plans on pull requests with the read-only role and posts the plan', () => {
    expect(plan).toContain('pull_request:');
    expect(plan).toContain('aws-actions/configure-aws-credentials@v4');
    expect(plan).toContain('vars.AG_TF_PLAN_ROLE_ARN');
    expect(plan).toContain('ap-southeast-1');
    expect(plan).toContain('npm test');
    expect(plan).toContain('npx tsc --noEmit');
    expect(plan).toContain('terraform -chdir=infra fmt -check -recursive');
    expect(plan).toContain('terraform -chdir=infra validate');
    expect(plan).toContain('terraform -chdir=infra plan');
    expect(plan).toContain('issues.createComment');
    expect(plan).toContain('scripts/check-protected-paths.mjs');
    expect(plan).toContain('guard-change');
    expect(plan).not.toContain('terraform -chdir=infra apply');
  });

  it('applies on main with the apply role', () => {
    expect(apply).toContain('branches:');
    expect(apply).toContain('- main');
    expect(apply).toContain('vars.AG_TF_APPLY_ROLE_ARN');
    expect(apply).toContain('ap-southeast-1');
    expect(apply).toContain('bash scripts/build-fixes.sh');
    expect(apply).toContain('terraform -chdir=infra apply -input=false -auto-approve');
  });

  it('loads the state backend from repo variables', () => {
    for (const text of [plan, apply]) {
      expect(text).toContain('vars.AG_TF_STATE_BUCKET');
      expect(text).toContain('vars.AG_TF_STATE_KEY');
      expect(text).toContain('vars.AG_TF_STATE_REGION');
      expect(text).toContain('vars.AG_TF_LOCK_TABLE');
      expect(text).toContain('vars.AG_FIX_BOUNDARY_ARN');
      expect(text).not.toMatch(/\b\d{12}\b/);
    }
  });
});
