/**
 * The advisory reader is intentionally not implemented.
 * Replace this file with tests of the reader when it is built.
 */
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const folder = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../src/extractors/advisory');

describe('advisory reader slot', () => {
  it('documents the contract and has no TypeScript yet', () => {
    const readme = readFileSync(path.join(folder, 'README.md'), 'utf8');
    expect(readme).toContain('vulnerableFunctions');
    expect(readme).toContain('affectedRange');
    expect(readme).toContain('fixedVersion');
    expect(readme).toContain('writing-extractors');
    expect(readme).toContain('What Grok decides:');
    expect(readme).toContain('What code decides:');

    const typescript = readdirSync(folder).filter((name) => name.endsWith('.ts'));
    expect(typescript).toEqual([]);
  });
});
